"""DAST scanner - Deterministic Dynamic Application Security Testing.

Performs safe, passive HTTP-based security analysis of web applications and APIs.
No exploitation, no destructive requests, no brute force, no modification of remote systems.

Detection methods:
  - Header inspection (missing/insecure headers)
  - Response analysis (status codes, body content reflection)
  - Parameter mutation (passive reflection detection)
  - Timing differentials (within safe thresholds)
  - TLS/certificate inspection
  - Endpoint discovery (common paths)

All findings are inference-based and deterministic — identical inputs always produce
identical outputs.

OWASP Top 10 coverage:
  A01: Broken Access Control
  A02: Cryptographic Failures
  A03: Injection
  A04: Insecure Design
  A05: Security Misconfiguration
  A06: Vulnerable and Outdated Components
  A07: Identification and Authentication Failures
  A08: Software and Data Integrity Failures
  A09: Security Logging and Monitoring Failures
  A10: Server-Side Request Forgery
"""

from __future__ import annotations

import re
import ssl
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import base64
import json

from ..models import Finding, ScanResult, Severity


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 15
DEFAULT_USER_AGENT = (
    "SentinelDAST/1.0 (Security Scanner; https://github.com/sentinel-security/sentinel)"
)
MAX_REDIRECTS = 5
MAX_RESPONSE_SIZE = 512 * 1024  # 512KB max response body

# Safe injection payloads (passive/observational only — no exploitation)
# Each type has multiple payloads for cross-validation accuracy
INJECTION_PAYLOADS: Dict[str, List[str]] = {
    "sql": [
        "'", "\"", "';", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' UNION SELECT NULL--", "1; SELECT 1",
    ],
    "nosql": [
        "'", "\"", "';'", "{$ne: null}", '{"$ne": null}',
    ],
    "command": [
        "; echo", "| echo", "`echo`", "$(echo)", "& echo",
    ],
    "ldap": [
        "*", "*)(uid=*)", "|(uid=*)",
    ],
    "xpath": [
        "'", "\"", "' and '1'='1", "\" and \"1\"=\"1",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{7*'7'}}",
        "#{7*7}", "*{7*7}",
    ],
}

# XSS test payloads (passive reflection check — no execution)
# Each payload is designed to detect reflection in different HTML contexts
XSS_PAYLOADS: List[Dict] = [
    {"payload": "<xss>", "context": "tag", "description": "Raw HTML tag injection"},
    {"payload": "<script>alert(1)</script>", "context": "tag", "description": "Script tag injection"},
    {"payload": '" onfocus="alert(1)', "context": "attribute", "description": "Event handler injection"},
    {"payload": "'-alert(1)-'", "context": "js_string_single", "description": "JavaScript string break (single quote)"},
    {"payload": '\"-alert(1)-\"', "context": "js_string_double", "description": "JavaScript string break (double quote)"},
    {"payload": "javascript:alert(1)", "context": "uri", "description": "javascript: URI injection"},
    {"payload": "<svg/onload=alert(1)>", "context": "svg", "description": "SVG onload event handler"},
    {"payload": "<img src=x onerror=alert(1)>", "context": "tag", "description": "Image onerror event handler"},
    {"payload": "<body onload=alert(1)>", "context": "body", "description": "Body onload event handler"},
    {"payload": "<details/open/ontoggle=alert(1)>", "context": "details", "description": "Details ontoggle event handler"},
    {"payload": "<marquee/onstart=alert(1)>", "context": "marquee", "description": "Marquee onstart event handler"},
    {"payload": "%3Cscript%3Ealert(1)%3C/script%3E", "context": "url_encoded", "description": "URL-encoded script tag"},
    {"payload": "<iframe src=javascript:alert(1)>", "context": "iframe", "description": "Iframe javascript: URI"},
    {"payload": "<a href=javascript:alert(1)>click</a>", "context": "anchor", "description": "Anchor javascript: URI"},
    {"payload": "<math><mi/xlink:href=\"data:x,<script>alert(1)</script>\">", "context": "mathml", "description": "MathML xlink:href injection"},
]

# Minimum number of payloads that must reflect for a HIGH-confidence finding
MIN_PAYLOADS_FOR_HIGH_CONFIDENCE = 2

# Common security headers to check
SECURITY_HEADERS: Dict[str, Tuple[str, str, Severity]] = {
    "Strict-Transport-Security": (
        "Missing HTTP Strict-Transport-Security (HSTS) header. "
        "HSTS enforces HTTPS connections and prevents SSL stripping attacks.",
        "CWE-319", Severity.HIGH,
    ),
    "Content-Security-Policy": (
        "Missing Content-Security-Policy (CSP) header. "
        "CSP mitigates XSS and data injection attacks by controlling allowed resources.",
        "CWE-1021", Severity.MEDIUM,
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options header. "
        "This header prevents MIME-type sniffing attacks.",
        "CWE-693", Severity.MEDIUM,
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options header. "
        "This header prevents clickjacking attacks by controlling iframe embedding.",
        "CWE-1021", Severity.MEDIUM,
    ),
    "X-XSS-Protection": (
        "Missing X-XSS-Protection header. "
        "This header enables the browser's cross-site scripting filter.",
        "CWE-79", Severity.LOW,
    ),
    "Referrer-Policy": (
        "Missing Referrer-Policy header. "
        "Without this header, referrer information may leak in cross-origin requests.",
        "CWE-200", Severity.LOW,
    ),
    "Permissions-Policy": (
        "Missing Permissions-Policy header. "
        "This header controls which browser features and APIs can be used.",
        "CWE-693", Severity.LOW,
    ),
    "Cache-Control": (
        "Missing Cache-Control header for sensitive content. "
        "Without proper caching directives, sensitive data may be stored in browser cache.",
        "CWE-525", Severity.LOW,
    ),
}

# Common admin/debug/sensitive endpoints
SENSITIVE_ENDPOINTS: List[str] = [
    "/admin", "/administrator", "/wp-admin", "/login", "/signin",
    "/debug", "/console", "/actuator", "/swagger", "/api/docs",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/.env", "/.git/config", "/config", "/backup",
    "/api/health", "/health", "/healthcheck", "/status",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/graphql", "/api/graphql",
    "/.vscode/settings.json", "/.DS_Store", "/docker-compose.yml",
    "/package.json", "/tsconfig.json", "/.aws/credentials",
    "/.kube/config", "/Dockerfile", "/docker-compose.yaml",
    "/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml",
    "/Procfile", "/.npmrc", "/.pypirc", "/wp-config.php",
    "/web.config", "/appsettings.json", "/appsettings.Development.json",
]

# Common IDOR patterns to test
IDOR_ENDPOINTS: List[str] = [
    "/api/users/1", "/api/profile/1", "/api/account/1",
    "/user/1", "/profile/1", "/account/1",
]

# TLS version constants
TLS_VERSIONS: Dict[int, Tuple[str, int]] = {
    ssl.TLSVersion.TLSv1_3: ("TLS 1.3", 1),
    ssl.TLSVersion.TLSv1_2: ("TLS 1.2", 2),
    ssl.TLSVersion.TLSv1_1: ("TLS 1.1", 3),
    ssl.TLSVersion.TLSv1: ("TLS 1.0", 4),
}

# Cloud provider metadata endpoints (checking for exposure, not exploiting)
CLOUD_METADATA_PATTERNS: List[Tuple[str, str, str, Severity]] = [
    ("aws", "imds", "http://169.254.169.254/latest/meta-data/",
     "AWS IMDS metadata endpoint exposure check.", Severity.CRITICAL),
    ("gcp", "metadata", "http://metadata.google.internal/computeMetadata/v1/",
     "GCP metadata endpoint exposure check.", Severity.CRITICAL),
    ("azure", "metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "Azure IMDS metadata endpoint exposure check.", Severity.CRITICAL),
]


# ═══════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════

def build_url(base: str, path: str) -> str:
    """Safely combine a base URL with a path."""
    base = base.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


def extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or url


def extract_scheme(url: str) -> str:
    """Extract the scheme from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme or "http"


def get_origin_url(url: str) -> str:
    """Get the origin (scheme + host) from a URL."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_https(url: str) -> bool:
    """Check if a URL uses HTTPS."""
    return extract_scheme(url).lower() == "https"


# ═══════════════════════════════════════════════════════════════════════
# Safe HTTP Client
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SafeResponse:
    """Represents a safe HTTP response with all data we need for analysis."""
    status_code: int
    headers: Dict[str, str]
    body: str
    url: str
    elapsed_ms: float
    content_type: str = ""


def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = MAX_REDIRECTS,
) -> SafeResponse:
    """Make a safe HTTP request using urllib.

    This is the core HTTP client for DAST scanning. It is fully deterministic,
    makes no exploitative requests, and handles errors gracefully.

    Args:
        url: The URL to request.
        method: HTTP method (GET, POST, etc.).
        headers: Additional headers to send.
        body: Request body for POST/PUT requests.
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow redirects.
        max_redirects: Maximum number of redirects to follow.

    Returns:
        A SafeResponse with the response data.
    """
    req_headers: Dict[str, str] = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/json,application/xml,*/*",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        req_headers.update(headers)

    if body:
        if "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    start_time = time.time()

    try:
        data = body.encode("utf-8") if body else None

        req = urllib.request.Request(
            url,
            data=data,
            headers=req_headers,
            method=method,
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        redirect_count = 0
        current_url = url

        while redirect_count <= max_redirects:
            try:
                resp = urllib.request.urlopen(
                    req, context=ctx, timeout=timeout
                )
                elapsed_ms = (time.time() - start_time) * 1000
                resp_headers = dict(resp.headers)
                resp_body = resp.read(MAX_RESPONSE_SIZE).decode("utf-8", errors="replace")
                content_type = resp_headers.get("Content-Type", "")

                return SafeResponse(
                    status_code=resp.status,
                    headers=resp_headers,
                    body=resp_body,
                    url=current_url,
                    elapsed_ms=elapsed_ms,
                    content_type=content_type,
                )
            except urllib.error.HTTPError as e:
                elapsed_ms = (time.time() - start_time) * 1000
                resp_headers = dict(e.headers)
                resp_body = ""
                try:
                    resp_body = e.read(MAX_RESPONSE_SIZE).decode("utf-8", errors="replace")
                except Exception:
                    pass

                # If we got a redirect and follow_redirects is enabled
                if follow_redirects and e.code in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        break
                    location = resp_headers.get("Location", "")
                    if location:
                        current_url = urllib.parse.urljoin(current_url, location)
                        req = urllib.request.Request(
                            current_url,
                            data=data,
                            headers=req_headers,
                            method=method,
                        )
                        continue

                content_type = resp_headers.get("Content-Type", "")
                return SafeResponse(
                    status_code=e.code,
                    headers=resp_headers,
                    body=resp_body,
                    url=current_url,
                    elapsed_ms=elapsed_ms,
                    content_type=content_type,
                )

    except urllib.error.URLError as e:
        elapsed_ms = (time.time() - start_time) * 1000
        return SafeResponse(
            status_code=0,
            headers={},
            body=f"Connection error: {e.reason}",
            url=url,
            elapsed_ms=elapsed_ms,
        )
    except (socket.timeout, OSError, ValueError) as e:
        elapsed_ms = (time.time() - start_time) * 1000
        return SafeResponse(
            status_code=0,
            headers={},
            body=f"Request error: {e}",
            url=url,
            elapsed_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = (time.time() - start_time) * 1000
        return SafeResponse(
            status_code=0,
            headers={},
            body=f"Unexpected error: {e}",
            url=url,
            elapsed_ms=elapsed_ms,
        )


def check_tls_version(hostname: str, port: int = 443) -> Tuple[Optional[str], int, str]:
    """Check the TLS version supported by a server.

    Args:
        hostname: The server hostname.
        port: The port to connect to.

    Returns:
        (version_name, version_rank, version_info) tuple.
        Returns (None, 999, error_msg) on failure.
    """
    for ver_constant, (ver_name, ver_rank) in sorted(
        TLS_VERSIONS.items(), key=lambda x: x[1][1]
    ):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ver_constant
            ctx.maximum_version = ver_constant
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else "unknown"
                    return (ver_name, ver_rank, f"TLS {ver_name} negotiated with {cipher_name}")
        except (ssl.SSLError, OSError, socket.timeout):
            continue

    # Fall back to checking minimum supported version
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else "unknown"
                if ver:
                    for v_constant, (v_name, v_rank) in TLS_VERSIONS.items():
                        if v_name == ver:
                            return (v_name, v_rank, f"Connected with {ver} using {cipher_name}")
                    return (ver, 3, f"Connected with {ver} using {cipher_name}")
    except Exception:
        pass

    return (None, 999, "Could not establish TLS connection")


# ═══════════════════════════════════════════════════════════════════════
# DAST Scanner
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DASTConfig:
    """Configuration for the DAST scanner."""
    timeout: int = DEFAULT_TIMEOUT
    follow_redirects: bool = True
    max_endpoints: int = 30
    check_injection: bool = True
    check_xss: bool = True
    check_headers: bool = True
    check_tls: bool = True
    check_cors: bool = True
    check_auth: bool = True
    check_access_control: bool = True
    check_misconfiguration: bool = True
    check_cookies: bool = True
    check_directory_listing: bool = True
    check_error_handling: bool = True
    check_admin_endpoints: bool = True
    check_metadata: bool = True
    check_rate_limiting: bool = True
    check_open_redirect: bool = True
    check_graphql: bool = True
    check_csp: bool = True
    check_http_methods: bool = True
    check_framework: bool = True
    check_cookie_prefix: bool = True
    check_sri: bool = True
    check_websocket: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)


class DASTScanner:
    """Deterministic DAST scanner for web applications and APIs.

    Performs passive, observational security analysis using only:
      - HTTP response analysis
      - Header inspection
      - Reflection detection
      - TLS configuration checks
      - Endpoint discovery

    No exploitation, no destructive payloads, no brute force.
    """

    def __init__(
        self,
        target_url: str,
        config: Optional[DASTConfig] = None,
    ) -> None:
        """Initialize the DAST scanner.

        Args:
            target_url: The target URL to scan.
            config: Scanner configuration options.
        """
        self.target_url = target_url.rstrip("/")
        self.config = config or DASTConfig()
        self.origin = get_origin_url(target_url)
        self.domain = extract_domain(target_url)
        self.findings: List[Finding] = []
        self.scanned_endpoints: List[str] = []

    def _add_finding(
        self,
        rule_id: str,
        issue_type: str,
        severity: Severity,
        message: str,
        endpoint: str = "",
        evidence: str = "",
        confidence: float = 0.8,
        remediation_hint: str = "",
        cwe_id: str = "",
        owasp_category: str = "",
        snippet: str = "",
    ) -> None:
        """Add a finding to the results."""
        endpoint = endpoint or self.target_url
        finding = Finding(
            file_path=endpoint,
            line_number=0,
            issue_type=issue_type,
            severity=severity,
            message=message,
            rule_id=rule_id,
            confidence=confidence,
            snippet=snippet or evidence[:120],
            detection_method="dast",
            remediation_hint=remediation_hint,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            endpoint=endpoint,
            evidence=evidence[:500],
        )
        self.findings.append(finding)

    def _make_request(self, path: str = "", **kwargs) -> SafeResponse:
        """Make a request to the target URL with optional path."""
        url = build_url(self.origin, path.lstrip("/")) if path else self.target_url
        headers = self.config.custom_headers

        if "headers" in kwargs:
            headers = {**(kwargs.pop("headers")), **self.config.custom_headers}

        return make_request(url, headers=headers, **kwargs)

    def scan(self) -> ScanResult:
        """Run the full DAST scan against the target URL.

        Returns:
            A ScanResult containing all findings and metadata.
        """
        start_time = time.time()

        # ─── Phase 1: Initial Reconnaissance ────────────────────────
        initial_resp = self._make_request(timeout=self.config.timeout)
        self.scanned_endpoints.append(self.target_url)

        if initial_resp.status_code == 0:
            self._add_finding(
                rule_id="DAST-CONNECTION-ERROR",
                issue_type="dast_connectivity",
                severity=Severity.LOW,
                message=f"Could not connect to {self.target_url}. "
                        f"Response: {initial_resp.body[:200]}",
                evidence=initial_resp.body[:200],
                confidence=1.0,
                cwe_id="CWE-300",
                owasp_category="A05:2021",
            )
            return self._build_result(start_time)

        # ─── Phase 2: Security Headers ──────────────────────────────
        if self.config.check_headers:
            self._check_security_headers(initial_resp)

        # ─── Phase 3: Cookie Security ───────────────────────────────
        if self.config.check_cookies:
            self._check_cookie_security(initial_resp)

        # ─── Phase 4: CORS Configuration ────────────────────────────
        if self.config.check_cors:
            self._check_cors()

        # ─── Phase 5: TLS/HTTPS Assessment ──────────────────────────
        if self.config.check_tls and is_https(self.target_url):
            self._check_tls()
        elif not is_https(self.target_url):
            self._add_finding(
                rule_id="DAST-NO-HTTPS",
                issue_type="dast_cryptography",
                severity=Severity.HIGH,
                message=f"Target does not use HTTPS: {self.target_url}. "
                        "Data transmitted over HTTP is unencrypted.",
                cwe_id="CWE-319",
                owasp_category="A02:2021",
                remediation_hint="Enable HTTPS with a valid TLS certificate. "
                                 "Redirect all HTTP traffic to HTTPS.",
                confidence=1.0,
            )

        # ─── Phase 6: Server Information Disclosure ─────────────────
        self._check_server_info(initial_resp)

        # ─── Phase 7: Injection Reflection Checks ───────────────────
        if self.config.check_injection:
            self._check_injection_reflections()

        # ─── Phase 8: XSS Reflection Checks ─────────────────────────
        if self.config.check_xss:
            self._check_xss_reflections()

        # ─── Phase 9: SSTI Detection ────────────────────────────────
        if self.config.check_injection:
            self._check_ssti()

        # ─── Phase 10: Directory & Endpoint Enumeration ─────────────
        if self.config.check_admin_endpoints:
            self._check_sensitive_endpoints()

        # ─── Phase 11: Error Handling & Verbose Errors ──────────────
        if self.config.check_error_handling:
            self._check_verbose_errors()

        # ─── Phase 12: Directory Listing ────────────────────────────
        if self.config.check_directory_listing:
            self._check_directory_listing()

        # ─── Phase 13: Authentication Checks ────────────────────────
        if self.config.check_auth:
            self._check_authentication()

        # ─── Phase 14: Access Control Checks ────────────────────────
        if self.config.check_access_control:
            self._check_access_control()

        # ─── Phase 15: Open Redirect ────────────────────────────────
        if self.config.check_open_redirect:
            self._check_open_redirect()

        # ─── Phase 16: ReDoS Pattern Detection ──────────────────────
        if self.config.check_injection:
            self._check_redos()

        # ─── Phase 17: XXE & Insecure Deserialization Indicators ─────
        if self.config.check_misconfiguration:
            self._check_xxe_and_deserialization(initial_resp)

        # ─── Phase 18: JWT Misconfiguration ───────────────────────────
        if self.config.check_auth:
            self._check_jwt_misconfiguration(initial_resp)

        # ─── Phase 19: Rate Limiting ──────────────────────────────────
        if self.config.check_rate_limiting:
            self._check_rate_limiting()

        # ─── Phase 20: Cloud Metadata ───────────────────────────────
        if self.config.check_metadata:
            self._check_cloud_metadata_exposure()

        # ─── Phase 21: SSRF Indicators ──────────────────────────────
        self._check_ssrf_indicators(initial_resp)

        # ─── Phase 22: GraphQL Introspection ────────────────────────
        if self.config.check_graphql:
            self._check_graphql_introspection()

        # ─── Phase 23: CSP Analysis ─────────────────────────────────
        if self.config.check_csp:
            self._check_csp_analysis(initial_resp)

        # ─── Phase 24: HTTP Method Enumeration ──────────────────────
        if self.config.check_http_methods:
            self._check_http_methods()

        # ─── Phase 25: Framework Fingerprinting ──────────────────────
        if self.config.check_framework:
            self._check_framework_fingerprinting(initial_resp)

        # ─── Phase 26: Cookie Prefix Analysis ────────────────────────
        if self.config.check_cookie_prefix:
            self._check_cookie_prefix(initial_resp)

        # ─── Phase 27: Subresource Integrity ─────────────────────────
        if self.config.check_sri:
            self._check_subresource_integrity(initial_resp)

        # ─── Phase 28: WebSocket Security ────────────────────────────
        if self.config.check_websocket:
            self._check_websocket_security(initial_resp)

        # ─── Phase 29: Content-Type Sniffing ─────────────────────────
        if self.config.check_misconfiguration:
            self._check_content_type_sniffing(initial_resp)

        # Build result
        return self._build_result(start_time)

    def _build_result(self, start_time: float) -> ScanResult:
        """Build a ScanResult from collected findings."""
        result = ScanResult(
            findings=self.findings,
            scanned_endpoints=len(self.scanned_endpoints),
            scan_time_ms=(time.time() - start_time) * 1000,
            target_url=self.target_url,
        )
        result.deduplicate()
        return result

    # ═══════════════════════════════════════════════════════════════════
    # Check implementations
    # ═══════════════════════════════════════════════════════════════════

    def _check_security_headers(self, resp: SafeResponse) -> None:
        """Check for missing or insecure security headers."""
        present_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, (message, cwe_id, severity) in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower not in present_headers:
                self._add_finding(
                    rule_id=f"DAST-{header_name.upper().replace('-', '_')}",
                    issue_type="dast_security_misconfiguration",
                    severity=severity,
                    message=message,
                    cwe_id=cwe_id,
                    owasp_category="A05:2021",
                    confidence=0.95,
                    evidence=f"Header '{header_name}' not present in response.",
                    remediation_hint=f"Add the '{header_name}' header to all responses. "
                                     f"See: https://securityheaders.com",
                )

        # Check for HSTS preload
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            if "max-age=" not in hsts.lower():
                self._add_finding(
                    rule_id="DAST-HSTS-NO-MAX-AGE",
                    issue_type="dast_security_misconfiguration",
                    severity=Severity.MEDIUM,
                    message="HSTS header present but missing 'max-age' directive.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021",
                    evidence=hsts,
                    remediation_hint="Add max-age directive: Strict-Transport-Security: "
                                     "max-age=31536000; includeSubDomains; preload",
                )
            else:
                # Check max-age value
                max_age_match = re.search(r"max-age=(\d+)", hsts, re.I)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 10886400:
                        self._add_finding(
                            rule_id="DAST-HSTS-LOW-MAX-AGE",
                            issue_type="dast_security_misconfiguration",
                            severity=Severity.LOW,
                            message=f"HSTS max-age ({max_age}s) is less than recommended "
                                    "minimum of 10886400s (126 days).",
                            cwe_id="CWE-319",
                            owasp_category="A02:2021",
                            evidence=hsts,
                            remediation_hint="Increase max-age to at least 10886400 "
                                             "(126 days) or preferably 31536000 (1 year).",
                        )

    def _check_cookie_security(self, resp: SafeResponse) -> None:
        """Check cookies for security attributes."""
        set_cookie = resp.headers.get("Set-Cookie", "")
        if not set_cookie:
            return

        # Split multiple Set-Cookie headers
        cookies: List[str] = [set_cookie]
        # Some servers send multiple Set-Cookie headers, join them
        all_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
        if all_cookies:
            cookies = all_cookies

        for cookie_header in cookies:
            cookie_name = cookie_header.split("=", 1)[0] if "=" in cookie_header else "unknown"

            if "secure" not in cookie_header.lower():
                self._add_finding(
                    rule_id="DAST-COOKIE-NO-SECURE",
                    issue_type="dast_cryptography",
                    severity=Severity.HIGH,
                    message=f"Cookie '{cookie_name}' missing 'Secure' flag.",
                    cwe_id="CWE-614",
                    owasp_category="A02:2021",
                    evidence=cookie_header[:200],
                    remediation_hint="Add the 'Secure' flag to cookies to ensure they "
                                     "are only transmitted over HTTPS.",
                )

            if "httponly" not in cookie_header.lower():
                self._add_finding(
                    rule_id="DAST-COOKIE-NO-HTTPONLY",
                    issue_type="dast_security_misconfiguration",
                    severity=Severity.MEDIUM,
                    message=f"Cookie '{cookie_name}' missing 'HttpOnly' flag.",
                    cwe_id="CWE-1004",
                    owasp_category="A05:2021",
                    evidence=cookie_header[:200],
                    remediation_hint="Add the 'HttpOnly' flag to cookies that don't "
                                     "need JavaScript access.",
                )

            if "samesite" not in cookie_header.lower():
                self._add_finding(
                    rule_id="DAST-COOKIE-NO-SAMESITE",
                    issue_type="dast_security_misconfiguration",
                    severity=Severity.MEDIUM,
                    message=f"Cookie '{cookie_name}' missing 'SameSite' attribute.",
                    cwe_id="CWE-1275",
                    owasp_category="A05:2021",
                    evidence=cookie_header[:200],
                    remediation_hint="Add 'SameSite=Lax' or 'SameSite=Strict' to "
                                     "cookies to prevent CSRF attacks.",
                )

    def _check_cors(self) -> None:
        """Check for CORS misconfiguration."""
        resp = self._make_request(
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            }
        )
        cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        cors_credentials = resp.headers.get("Access-Control-Allow-Credentials", "")

        if cors_origin == "*":
            self._add_finding(
                rule_id="DAST-CORS-WILDCARD",
                issue_type="dast_access_control",
                severity=Severity.HIGH,
                message="CORS policy allows all origins (*). This exposes the "
                        "application to cross-origin data access.",
                cwe_id="CWE-942",
                owasp_category="A01:2021",
                evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                confidence=0.9,
                remediation_hint="Restrict Access-Control-Allow-Origin to specific "
                                 "trusted origins. Use '*' only for public APIs.",
            )

        if cors_origin.startswith("http://"):
            self._add_finding(
                rule_id="DAST-CORS-HTTP-ORIGIN",
                issue_type="dast_access_control",
                severity=Severity.MEDIUM,
                message=f"CORS allows HTTP origin: {cors_origin}. "
                        "This weakens security by allowing insecure origins.",
                cwe_id="CWE-942",
                owasp_category="A01:2021",
                evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                confidence=0.8,
                remediation_hint="Only allow HTTPS origins in CORS configuration.",
            )

        if cors_origin and cors_origin != "*" and cors_credentials.lower() == "true":
            self._add_finding(
                rule_id="DAST-CORS-WITH-CREDENTIALS",
                issue_type="dast_access_control",
                severity=Severity.MEDIUM,
                message="CORS allows credentials with a specific origin. "
                        "This can lead to credential leakage in cross-origin requests.",
                cwe_id="CWE-942",
                owasp_category="A01:2021",
                evidence=f"Access-Control-Allow-Origin: {cors_origin}; "
                         f"Access-Control-Allow-Credentials: true",
                confidence=0.7,
                remediation_hint="Ensure the CORS origin allowlist is strictly maintained "
                                 "and does not include untrusted origins.",
            )

    def _check_tls(self) -> None:
        """Check TLS configuration."""
        hostname = self.domain
        port = 443

        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.port:
            port = parsed.port

        ver_name, ver_rank, ver_info = check_tls_version(hostname, port)

        if ver_name is None:
            self._add_finding(
                rule_id="DAST-TLS-CONNECTION-FAILED",
                issue_type="dast_cryptography",
                severity=Severity.HIGH,
                message=f"Could not establish TLS connection to {hostname}:{port}.",
                evidence=ver_info,
                cwe_id="CWE-295",
                owasp_category="A02:2021",
                remediation_hint="Ensure the server has a valid TLS certificate "
                                 "configured and is accessible.",
                confidence=1.0,
            )
            return

        if ver_rank >= 3:
            severity = Severity.HIGH if ver_rank >= 4 else Severity.MEDIUM
            self._add_finding(
                rule_id="DAST-WEAK-TLS",
                issue_type="dast_cryptography",
                severity=severity,
                message=f"Server supports {ver_name}, which is deprecated. "
                        "TLS 1.2 or higher is recommended.",
                cwe_id="CWE-326",
                owasp_category="A02:2021",
                evidence=ver_info,
                remediation_hint="Disable TLS 1.0/1.1 and SSL 2.0/3.0 on the server. "
                                 "Enable only TLS 1.2 and TLS 1.3.",
            )

    def _check_server_info(self, resp: SafeResponse) -> None:
        """Check for server information disclosure."""
        server_header = resp.headers.get("Server", "")
        if server_header:
            self._add_finding(
                rule_id="DAST-SERVER-INFO-DISCLOSURE",
                issue_type="dast_information_disclosure",
                severity=Severity.LOW,
                message=f"Server information disclosed: '{server_header}'. "
                        "This information can help attackers target specific vulnerabilities.",
                cwe_id="CWE-200",
                owasp_category="A05:2021",
                evidence=f"Server: {server_header}",
                confidence=0.9,
                remediation_hint="Configure the server to omit or obfuscate the Server header "
                                 "to prevent version fingerprinting.",
            )

        # Check for X-Powered-By
        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            self._add_finding(
                rule_id="DAST-X-POWERED-BY",
                issue_type="dast_information_disclosure",
                severity=Severity.LOW,
                message=f"Technology stack disclosed via X-Powered-By: '{powered_by}'.",
                cwe_id="CWE-200",
                owasp_category="A05:2021",
                evidence=f"X-Powered-By: {powered_by}",
                confidence=0.9,
                remediation_hint="Remove or obfuscate X-Powered-By headers to prevent "
                                 "technology fingerprinting.",
            )

        # Check for debug mode indicators in response
        debug_indicators = [
            r"DEBUG\s*=\s*True",
            r"debug\s*=\s*true",
            r"APP_DEBUG\s*=\s*true",
            r"WP_DEBUG",
            r"laravel\.debug\s*=\s*true",
            r"Django\s+Debug\s+Toolbar",
            r"<div[^>]*class=\"[^\"]*debug[^\"]*\"",
        ]
        for pattern in debug_indicators:
            if re.search(pattern, resp.body, re.I):
                self._add_finding(
                    rule_id="DAST-DEBUG-MODE",
                    issue_type="dast_security_misconfiguration",
                    severity=Severity.HIGH,
                    message="Debug mode is enabled. Debug mode in production can "
                            "expose sensitive information, stack traces, and configuration.",
                    cwe_id="CWE-489",
                    owasp_category="A05:2021",
                    evidence=f"Pattern '{pattern}' matched in response body.",
                    confidence=0.8,
                    remediation_hint="Disable debug mode in production. Set DEBUG=False, "
                                     "APP_DEBUG=false, or equivalent.",
                )
                break

    def _check_injection_reflections(self) -> None:
        """Check for injection vulnerabilities via passive multi-payload reflection detection.

        Uses multiple payloads per injection type and requires cross-validation
        to minimize false positives. Confidence is boosted when:
        - Multiple payloads reflect in the response
        - Reflection occurs in an executable HTML context
        - Payload appears outside of error messages
        """
        for inj_type, payloads in INJECTION_PAYLOADS.items():
            reflected_payloads: List[str] = []
            reflection_contexts: List[str] = []

            for payload in payloads:
                test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
                resp = self._make_request(test_url, timeout=self.config.timeout)

                if resp.status_code == 0:
                    continue

                # Check if payload is reflected in the response
                if payload in resp.body:
                    reflected_payloads.append(payload)
                    context = self._get_reflection_context(resp.body, payload)
                    reflection_contexts.append(context)

            if not reflected_payloads:
                continue

            # Calculate confidence based on multiple signals
            num_reflected = len(reflected_payloads)
            base_confidence = 0.4

            # Boost: multiple payloads reflect (cross-validation)
            if num_reflected >= MIN_PAYLOADS_FOR_HIGH_CONFIDENCE:
                base_confidence += 0.25

            # Boost: reflection in multiple distinct contexts
            unique_contexts = len(set(reflection_contexts))
            if unique_contexts >= 2:
                base_confidence += 0.1

            # Check if ALL reflections are within error messages (likely FP)
            all_in_errors = all(
                self._is_in_error_message(ctx) for ctx in reflection_contexts
            )
            if all_in_errors and num_reflected < 3:
                base_confidence -= 0.2

            # Boost: check if payload appears in executable HTML context
            in_exec_context = any(
                self._is_in_executable_context(ctx, p)
                for ctx, p in zip(reflection_contexts, reflected_payloads)
            )
            if in_exec_context:
                base_confidence += 0.15

            # Boost: payload appears multiple times in body
            total_occurrences = sum(resp.body.count(p) for p in reflected_payloads)
            if total_occurrences > num_reflected * 2:
                base_confidence += 0.1

            # Cap confidence
            confidence = min(base_confidence, 0.95)

            severity_map = {
                "sql": Severity.CRITICAL,
                "command": Severity.CRITICAL,
                "ldap": Severity.HIGH,
                "xpath": Severity.HIGH,
                "nosql": Severity.HIGH,
                "ssti": Severity.CRITICAL,
            }
            cwe_map = {
                "sql": "CWE-89",
                "command": "CWE-78",
                "ldap": "CWE-90",
                "xpath": "CWE-643",
                "nosql": "CWE-943",
                "ssti": "CWE-94",
            }
            owasp_map = {
                "sql": "A03:2021",
                "command": "A03:2021",
                "ldap": "A03:2021",
                "xpath": "A03:2021",
                "nosql": "A03:2021",
                "ssti": "A03:2021",
            }

            severity = severity_map.get(inj_type, Severity.HIGH)
            cwe_id = cwe_map.get(inj_type, "CWE-74")
            owasp = owasp_map.get(inj_type, "A03:2021")

            # Use the best context for evidence
            best_context = max(reflection_contexts, key=len) if reflection_contexts else ""
            reflected_summary = ", ".join(reflected_payloads[:3])
            if len(reflected_payloads) > 3:
                reflected_summary += f" (+{len(reflected_payloads) - 3} more)"

            self._add_finding(
                rule_id=f"DAST-INJECTION-{inj_type.upper()}",
                issue_type="dast_injection",
                severity=severity,
                message=f"Potential {inj_type.upper()} injection detected. "
                        f"{num_reflected} payload(s) reflected in response "
                        f"({reflected_summary}).",
                cwe_id=cwe_id,
                owasp_category=owasp,
                evidence=f"Reflected {num_reflected}/{len(payloads)} payloads. "
                         f"Context: '{best_context}'",
                confidence=confidence,
                remediation_hint=self._injection_remediation(inj_type),
            )

    def _get_reflection_context(self, body: str, payload: str, window: int = 50) -> str:
        """Extract context around a reflected payload in the response body."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(body), idx + len(payload) + window)
        context = body[start:end]
        # Clean up whitespace
        context = re.sub(r"\s+", " ", context).strip()
        return context[:120]

    def _is_in_error_message(self, context: str) -> bool:
        """Check if the reflection context is within an error message (likely false positive)."""
        error_indicators = [
            "Traceback", "Error:", "Warning:", "Notice:", "Fatal error",
            "exception", "SyntaxError", "TypeError", "ValueError", "NameError",
            "Warning:", "Parse error", "Stack trace", "Stacktrace",
            "not found", "does not exist", "Invalid input", "Bad request",
            "404 Not Found", "500 Internal",
        ]
        return any(indicator.lower() in context.lower() for indicator in error_indicators)

    def _is_in_executable_context(self, context: str, payload: str) -> bool:
        """Check if reflected payload appears in an executable HTML context.
        
        Executable contexts include:
        - Inside <script> tags
        - In HTML event handlers (onclick, onfocus, etc.)
        - In href/src attributes (potential XSS/ injection)
        - Inside <style> tags
        """
        # Create context with placeholder for the reflected payload
        context_lower = context.lower()
        
        # Check script context
        if "<script" in context_lower:
            return True
        
        # Check event handler context (onclick, onfocus, onerror, etc.)
        if re.search(r"on\w+\s*=", context_lower):
            return True
        
        # Check attribute context (inside HTML tags)
        if re.search(r"<[a-zA-Z][^>]*" + re.escape(payload[:20]), context):
            return True
        if re.search(re.escape(payload[:20]) + r"[^>]*>", context):
            return True
        
        # Check href/src/action attributes
        for attr in ["href", "src", "action", "data", "formaction"]:
            if f"{attr}=" in context_lower:
                # Check if payload is near the attribute
                attr_pos = context_lower.find(f"{attr}=")
                if attr_pos >= 0:
                    attr_value_start = context_lower.find("\"", attr_pos)
                    if attr_value_start >= 0:
                        attr_value_end = context_lower.find("\"", attr_value_start + 1)
                        if attr_value_end >= 0:
                            attr_value = context[attr_value_start:attr_value_end + 1]
                            if payload[:20] in attr_value:
                                return True
        
        return False

    def _injection_remediation(self, inj_type: str) -> str:
        """Get remediation guidance for an injection type."""
        remediations = {
            "sql": "Use parameterized queries with prepared statements. "
                   "Validate and sanitize all user inputs. Consider using an ORM.",
            "command": "Avoid shell commands with user input. Use language-native APIs. "
                       "If required, use subprocess with shell=False and a whitelist.",
            "ldap": "Use LDAP escape functions for all user-supplied values. "
                    "Validate input against a whitelist pattern.",
            "xpath": "Use parameterized XPath queries. Avoid string concatenation "
                     "in XPath expressions.",
            "nosql": "Validate and sanitize all user input. Use a query builder or ORM "
                     "that escapes special operators.",
            "ssti": "Use a sandboxed template engine. Avoid passing user input to "
                    "template rendering functions like render_template_string().",
        }
        return remediations.get(inj_type, "Validate and sanitize all user inputs. "
                                          "Use parameterized queries and prepared statements.")

    def _check_xss_reflections(self) -> None:
        """Check for reflected XSS vulnerabilities using multi-payload validation.

        Uses structured payloads with context metadata to accurately assess:
        - Whether reflection occurs in an executable HTML context (script, event handler, etc.)
        - How many payloads reflect (cross-validation)
        - The specific HTML context type for severity scoring
        """
        reflected_payloads: List[Dict] = []

        for payload_entry in XSS_PAYLOADS:
            payload = payload_entry["payload"]
            context_type = payload_entry["context"]

            test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
            resp = self._make_request(test_url, timeout=self.config.timeout)

            if resp.status_code == 0:
                continue

            # Check if payload is reflected unsanitized
            if payload in resp.body:
                context = self._get_reflection_context(resp.body, payload)
                # Determine if reflection is in an executable HTML context
                exec_context = self._is_in_executable_context(context, payload)
                reflected_payloads.append({
                    "payload": payload,
                    "context_type": context_type,
                    "context": context,
                    "exec_context": exec_context,
                    "resp": resp,
                })

        if not reflected_payloads:
            return

        # Calculate confidence
        num_reflected = len(reflected_payloads)
        base_confidence = 0.4

        # Boost: multiple different payload types reflect
        if num_reflected >= 2:
            base_confidence += 0.2
        if num_reflected >= 3:
            base_confidence += 0.1

        # Boost: reflection in executable context (event handlers, script tags)
        exec_context_count = sum(1 for rp in reflected_payloads if rp["exec_context"])
        if exec_context_count > 0:
            base_confidence += 0.2

        # Boost: multiple distinct context types
        context_types = set(rp["context_type"] for rp in reflected_payloads)
        if len(context_types) >= 2:
            base_confidence += 0.1

        # Check if payloads appear in HTML body vs error page
        html_body_indicators = ["<html", "<body", "<div", "<p>", "<h1", "<table"]
        in_html_body = any(
            any(tag in rp["resp"].body.lower() for tag in html_body_indicators)
            for rp in reflected_payloads
        )
        if in_html_body:
            base_confidence += 0.1

        # Penalty: all reflections only in error messages
        all_in_errors = all(
            self._is_in_error_message(rp["context"]) for rp in reflected_payloads
        )
        if all_in_errors:
            base_confidence -= 0.2

        confidence = min(base_confidence, 0.95)

        payload_summary = ", ".join(rp["payload"] for rp in reflected_payloads[:3])
        if len(reflected_payloads) > 3:
            payload_summary += f" (+{len(reflected_payloads) - 3} more)"

        best_context = max(rp["context"] for rp in reflected_payloads)
        context_types_str = ", ".join(sorted(context_types))

        self._add_finding(
            rule_id="DAST-XSS-REFLECTED",
            issue_type="dast_xss",
            severity=Severity.HIGH,
            message=f"Potential reflected XSS detected. {num_reflected} payload(s) "
                    f"({payload_summary}) reflected in response. "
                    f"Context types: {context_types_str}.",
            cwe_id="CWE-79",
            owasp_category="A03:2021",
            evidence=f"Reflected {num_reflected}/{len(XSS_PAYLOADS)} payloads. "
                     f"Executable context: {exec_context_count > 0}. "
                     f"Best context: '{best_context}'",
            confidence=confidence,
            remediation_hint="Sanitize all user input using context-appropriate "
                             "encoding (HTML entity encoding, URL encoding, etc.). "
                             "Use a Content-Security-Policy header as defense-in-depth.",
        )

    def _check_ssti(self) -> None:
        """Check for Server-Side Template Injection."""
        # Use a simple math expression: {{7*7}}
        test_url = f"{self.target_url}?name={urllib.parse.quote('{{7*7}}')}"
        resp = self._make_request(test_url, timeout=self.config.timeout)

        if resp.status_code == 0:
            return

        # Check for SSTI indicators in the response
        ssti_indicators = [
            (r"49\b", "Jinja2/Twig/Handlebars", Severity.CRITICAL, "{{7*7}} evaluated to 49"),
            (r"\{#", "Jinja2 comment syntax exposed", Severity.MEDIUM, "Jinja2 comment syntax visible"),
        ]

        for pattern, engine, severity, evidence in ssti_indicators:
            if re.search(pattern, resp.body):
                self._add_finding(
                    rule_id="DAST-SSTI",
                    issue_type="dast_injection",
                    severity=severity,
                    message=f"Potential Server-Side Template Injection ({engine}) detected.",
                    cwe_id="CWE-94",
                    owasp_category="A03:2021",
                    evidence=evidence,
                    confidence=0.6,
                    remediation_hint="Avoid passing user input to template rendering "
                                     "functions. Use a sandboxed template environment. "
                                     "Validate and sanitize all template variables.",
                )
                break

    def _check_sensitive_endpoints(self) -> None:
        """Check for exposed sensitive endpoints."""
        for endpoint in SENSITIVE_ENDPOINTS:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break

            url = build_url(self.origin, endpoint.lstrip("/"))
            resp = self._make_request(url, timeout=self.config.timeout)
            self.scanned_endpoints.append(url)

            if resp.status_code == 0:
                continue

            severity = Severity.HIGH
            confidence = 0.7

            # Classify endpoints by risk
            high_risk = ["/admin", "/administrator", "/wp-admin", "/console",
                         "/actuator", "/phpinfo.php", "/.env", "/.git/config",
                         "/backup"]
            medium_risk = ["/debug", "/swagger", "/api/docs", "/info.php",
                           "/server-status", "/server-info"]
            login_endpoints = ["/login", "/signin"]

            if any(endpoint.startswith(p) or endpoint == p for p in high_risk):
                severity = Severity.HIGH
            elif any(endpoint.startswith(p) or endpoint == p for p in medium_risk):
                severity = Severity.MEDIUM
            elif any(endpoint.startswith(p) or endpoint == p for p in login_endpoints):
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Check for specific conditions
            if endpoint in ("/.git/config", "/.env", "/backup"):
                if resp.status_code < 400:
                    severity = Severity.CRITICAL
                    confidence = 0.9
                    if endpoint == "/.git/config" and "[core]" in resp.body:
                        confidence = 1.0
                    elif endpoint == "/.env" and re.search(r"(?i)(API_KEY|SECRET|PASSWORD)", resp.body):
                        confidence = 1.0
            elif endpoint == "/phpinfo.php" and "PHP License" in resp.body:
                confidence = 1.0
            elif endpoint == "/actuator" and "_links" in resp.body:
                severity = Severity.CRITICAL
                confidence = 0.95

            if resp.status_code < 400:
                status_hint = f" (HTTP {resp.status_code})"
                body_hint = ""
                if len(resp.body) > 10:
                    body_hint = f" - Response body starts with: {resp.body[:100].strip()[:80]}"

                self._add_finding(
                    rule_id=f"DAST-EXPOSED-{endpoint.upper().replace('/', '_').replace('.', '_').strip('_')}",
                    issue_type="dast_exposed_endpoint",
                    severity=severity,
                    message=f"Exposed endpoint detected: '{endpoint}'{status_hint}. "
                            "This endpoint should not be publicly accessible.",
                    endpoint=url,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    evidence=f"HTTP {resp.status_code} - {endpoint}{body_hint}",
                    confidence=confidence,
                    remediation_hint=f"Restrict access to '{endpoint}' using "
                                     "authentication and network-level controls. "
                                     "Remove the endpoint in production if unused.",
                )

    def _check_verbose_errors(self) -> None:
        """Check for verbose error messages that leak information."""
        test_endpoints = [
            ("/test%0d%0a", "CRLF injection"),
            ("/..%2f", "Path traversal"),
            ("/../../../etc/passwd", "Path traversal"),
            ("/%00", "Null byte injection"),
        ]

        for endpoint, test_type in test_endpoints:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break

            url = build_url(self.origin, endpoint.lstrip("/"))
            resp = self._make_request(url, timeout=self.config.timeout)
            self.scanned_endpoints.append(url)

            if resp.status_code == 0:
                continue

            # Check for information leakage in error responses
            error_indicators = [
                (r"Traceback|Stack trace|Stacktrace", "Stack trace exposed"),
                (r"SQL syntax.*MySQL|Warning:.*mysql_", "Database error message"),
                (r"Fatal error", "Fatal PHP error"),
                (r"RuntimeError|TypeError|ValueError|NameError", "Python exception"),
                (r"java\.lang\.|Exception in thread", "Java exception"),
                (r"in <module>", "Python traceback"),
                (r"File \".*\", line \d+", "File path disclosure"),
                (r"Warning:.*(?:include|require|open|file_get_contents)", "Include path disclosure"),
                (r"Class '.*' not found", "Class autoloading error"),
                (r"Undefined variable", "Undefined variable warning"),
            ]

            for pattern, indicator_name in error_indicators:
                if re.search(pattern, resp.body, re.I):
                    context = self._get_reflection_context(resp.body, resp.body[:50] if len(resp.body) > 50 else resp.body)
                    self._add_finding(
                        rule_id=f"DAST-VERBOSE-ERROR-{test_type.upper().replace(' ', '_')}",
                        issue_type="dast_information_disclosure",
                        severity=Severity.MEDIUM if resp.status_code < 500 else Severity.HIGH,
                        message=f"Verbose error message detected: {indicator_name}. "
                                "Error messages can leak sensitive implementation details.",
                        endpoint=url,
                        cwe_id="CWE-209",
                        owasp_category="A05:2021",
                        evidence=f"Pattern detected in response to {url}: {context[:150]}",
                        confidence=0.85,
                        remediation_hint="Configure the application to return generic error "
                                         "messages in production. Log detailed errors server-side only.",
                    )
                    break  # One finding per endpoint

    def _check_directory_listing(self) -> None:
        """Check for directory listing vulnerability."""
        test_dirs = ["/", "/images", "/css", "/js", "/static", "/assets", "/uploads", "/files"]

        for directory in test_dirs:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break

            url = build_url(self.origin, directory.lstrip("/"))
            resp = self._make_request(url, timeout=self.config.timeout)

            if resp.status_code == 0:
                continue

            if resp.status_code == 200:
                # Check for directory listing patterns
                listing_indicators = [
                    r"<title>Index of /",
                    r"<h1>Index of /",
                    r"Parent Directory</a>",
                    r"\[DIR\]",
                    r"Directory listing for",
                    r"<a href=\"\?C=N;O=D\">",
                    r"<a href=\"\\?C=N;O=A\">",
                    r"Apache.*Server at.*Port",
                    r"nginx.*directory index",
                ]

                for indicator in listing_indicators:
                    if re.search(indicator, resp.body, re.I):
                        self._add_finding(
                            rule_id="DAST-DIRECTORY-LISTING",
                            issue_type="dast_security_misconfiguration",
                            severity=Severity.MEDIUM,
                            message=f"Directory listing enabled for '{directory}'. "
                                    "This exposes the directory structure and file contents.",
                            endpoint=url,
                            cwe_id="CWE-548",
                            owasp_category="A05:2021",
                            evidence=f"Directory listing pattern detected in response to {url}",
                            confidence=0.95,
                            remediation_hint="Disable directory listing in the web server "
                                             "configuration (Options -Indexes for Apache, "
                                             "autoindex off for nginx).",
                        )
                        break

    def _check_authentication(self) -> None:
        """Check authentication-related issues."""
        # Check login endpoint
        login_url = build_url(self.origin, "login")
        resp = self._make_request(login_url, timeout=self.config.timeout)

        if resp.status_code == 0 or resp.status_code >= 400:
            return

        # Check for default/weak login pages
        weak_login_indicators = [
            r"<input[^>]*type=[\"']?password[\"']?[^>]*>",
            r"<form[^>]*action=[\"']?login[\"']?",
            r"name=[\"']?(?:username|email|user|login)[\"']?",
        ]

        has_form = any(re.search(p, resp.body, re.I) for p in weak_login_indicators)

        if has_form:
            # Check if login form is served over HTTPS
            if not is_https(self.target_url):
                self._add_finding(
                    rule_id="DAST-LOGIN-OVER-HTTP",
                    issue_type="dast_authentication",
                    severity=Severity.CRITICAL,
                    message="Login form served over unencrypted HTTP. "
                            "Credentials can be intercepted via man-in-the-middle attacks.",
                    endpoint=login_url,
                    cwe_id="CWE-319",
                    owasp_category="A02:2021",
                    evidence=f"Login form detected at {login_url} over HTTP",
                    confidence=0.95,
                    remediation_hint="Enforce HTTPS for all authentication pages. "
                                     "Use HSTS to ensure browsers always use HTTPS.",
                )

            # Test for user enumeration via response differentiation
            self._check_user_enumeration(login_url)

    def _check_user_enumeration(self, login_url: str) -> None:
        """Check for user enumeration via response differentiation."""
        # Test with common usernames
        test_users = ["admin", "root", "test", "user", "administrator"]

        responses: List[Tuple[str, int, int]] = []  # (username, status_code, body_length)

        for username in test_users[:3]:  # Limit to prevent rate limiting
            data = urllib.parse.urlencode({
                "username": username,
                "password": "InvalidPassword123!@#",
            })

            resp = self._make_request(
                login_url,
                method="POST",
                body=data,
                timeout=self.config.timeout,
            )

            if resp.status_code == 0:
                continue

            responses.append((username, resp.status_code, len(resp.body)))

        # Check for response differentiation
        if len(responses) >= 2:
            statuses = set(r[1] for r in responses)
            lengths = set(r[2] for r in responses)

            if len(lengths) > 1 or len(statuses) > 1:
                self._add_finding(
                    rule_id="DAST-USER-ENUMERATION",
                    issue_type="dast_authentication",
                    severity=Severity.MEDIUM,
                    message="Possible user enumeration vulnerability detected. "
                            "Response differs for valid vs invalid usernames.",
                    endpoint=login_url,
                    cwe_id="CWE-204",
                    owasp_category="A07:2021",
                    evidence=f"Response sizes vary: {dict((u, s, l) for u, s, l in responses)}",
                    confidence=0.5,
                    remediation_hint="Return consistent responses for both valid and invalid "
                                     "usernames. Use generic error messages like "
                                     "'Invalid username or password'.",
                )

    def _check_access_control(self) -> None:
        """Check for access control vulnerabilities (IDOR, privilege escalation)."""
        for endpoint in IDOR_ENDPOINTS:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break

            url = build_url(self.origin, endpoint.lstrip("/"))
            resp = self._make_request(url, timeout=self.config.timeout)
            self.scanned_endpoints.append(url)

            if resp.status_code == 0:
                continue

            if resp.status_code == 200:
                # Check if response contains sensitive user data
                sensitive_patterns = [
                    r"\"(?:email|phone|address|ssn|credit_card)\"",
                    r"\"role\":\s*\"admin\"",
                    r"\"is_admin\":\s*true",
                    r"\"(?:user_id|id)\":\s*\d+",
                    r"password|credit_card|social_security",
                ]

                has_sensitive_data = any(re.search(p, resp.body, re.I) for p in sensitive_patterns)

                if has_sensitive_data:
                    self._add_finding(
                        rule_id="DAST-IDOR-POTENTIAL",
                        issue_type="dast_access_control",
                        severity=Severity.HIGH,
                        message=f"Potential Insecure Direct Object Reference (IDOR) at "
                                "'{endpoint}'. Endpoint returned data without authentication.",
                        endpoint=url,
                        cwe_id="CWE-639",
                        owasp_category="A01:2021",
                        evidence=f"HTTP 200 - endpoint '{endpoint}' returned data with "
                                "sensitive patterns",
                        confidence=0.5,
                        remediation_hint="Implement proper access control checks. Use "
                                         "authorization middleware to verify the user has "
                                         "permission to access the requested resource.",
                    )

    def _check_open_redirect(self) -> None:
        """Check for open redirect vulnerabilities."""
        redirect_test_url = f"{self.target_url}?next=https://evil.com"
        resp = self._make_request(
            redirect_test_url,
            follow_redirects=False,
            timeout=self.config.timeout,
        )

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if location and ("evil.com" in location or "//evil.com" in location):
                self._add_finding(
                    rule_id="DAST-OPEN-REDIRECT",
                    issue_type="dast_injection",
                    severity=Severity.MEDIUM,
                    message="Potential open redirect vulnerability. "
                            "The application redirects to a URL provided in a parameter.",
                    cwe_id="CWE-601",
                    owasp_category="A03:2021",
                    evidence=f"Redirect to '{location}' from parameter 'next'",
                    confidence=0.7,
                    remediation_hint="Do not use user-supplied input in redirect URLs. "
                                     "Use a whitelist of allowed redirect targets or "
                                     "use indirect references.",
                )

    def _check_redos(self) -> None:
        """Check for ReDoS (Regular Expression Denial of Service) vulnerability indicators.

        Detects if the application exposes endpoints that accept user-supplied
        regex patterns, which could be vulnerable to ReDoS attacks.
        """
        test_url = f"{self.target_url}?regex=(a+)+b&input=aaaaaaac"
        resp = self._make_request(test_url, timeout=self.config.timeout)

        if resp.status_code == 0:
            return

        # Check for patterns suggesting regex processing in the response
        redos_indicators = [
            r"(?i)(?:regex|regexp|regular.?express).*(?:error|exception|timeout|fail)",
            r"(?i)(?:backtrack|catastrophic|stack overflow|too many ).*",
            r"re\.(?:compile|search|match|findall|fullmatch)",
            r"preg_(?:match|replace|filter|split)",
            r"Pattern\.(?:compile|matches|split)",
        ]

        for indicator in redos_indicators:
            if re.search(indicator, resp.body, re.I):
                self._add_finding(
                    rule_id="DAST-REDOS",
                    issue_type="dast_insecure_design",
                    severity=Severity.MEDIUM,
                    message="Potential ReDoS (Regular Expression Denial of Service) vulnerability. "
                            "The application may be accepting user-supplied regex patterns "
                            "without proper safeguards.",
                    cwe_id="CWE-1333",
                    owasp_category="A04:2021",
                    evidence=f"ReDoS indicator '{indicator}' matched in response to regex probe",
                    confidence=0.4,
                    remediation_hint="Avoid accepting regex patterns from users. "
                                     "If necessary, implement regex timeout limits, "
                                     "input validation, and use safe regex engines. "
                                     "Monitor for excessive regex execution times.",
                )
                break

        # Check for abnormally long response times (> 5s) which could indicate
        # catastrophic backtracking
        if resp.elapsed_ms > 5000:
            self._add_finding(
                rule_id="DAST-REDOS-TIMING",
                issue_type="dast_insecure_design",
                severity=Severity.HIGH,
                message="Abnormally long response time detected for regex input. "
                        "This suggests possible catastrophic backtracking (ReDoS).",
                cwe_id="CWE-1333",
                owasp_category="A04:2021",
                evidence=f"Response took {resp.elapsed_ms:.0f}ms for regex probe payload",
                confidence=0.5,
                remediation_hint="Implement input validation for regex patterns. "
                                 "Use a timeout with regex operations. Consider using "
                                 "a dedicated regex safety library.",
            )

    def _check_xxe_and_deserialization(self, resp: SafeResponse) -> None:
        """Check for XXE (XML External Entity) and insecure deserialization indicators.

        Analyzes response headers and body for clues that the application
        processes XML or deserializes user data in an unsafe manner.
        """
        # Check Content-Type for XML processing
        content_type = resp.headers.get("Content-Type", "").lower()
        if "xml" in content_type:
            self._add_finding(
                rule_id="DAST-XXE-POTENTIAL",
                issue_type="dast_injection",
                severity=Severity.MEDIUM,
                message="Application processes XML data (Content-Type: XML). "
                        "This could be vulnerable to XXE (XML External Entity) attacks "
                        "if the XML parser is not securely configured.",
                cwe_id="CWE-611",
                owasp_category="A05:2021",
                evidence=f"XML Content-Type detected: {content_type}",
                confidence=0.3,  # Low confidence - just XML processing, not confirmed XXE
                remediation_hint="Disable external entity resolution in XML parsers. "
                                 "Use 'defusedxml' in Python or equivalent safe XML "
                                 "parsing libraries. Disable DTD processing entirely.",
            )

        # Check for endpoints that accept XML (SOAP, REST XML, etc.)
        xml_accepted_endpoints = [
            "/api", "/soap", "/ws", "/xmlrpc", "/xml",
            "/api/xml", "/rpc", "/soap/", "/service",
        ]

        for endpoint in xml_accepted_endpoints:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break

            test_url = build_url(self.origin, endpoint.lstrip("/"))
            xml_resp = self._make_request(
                test_url,
                method="POST",
                headers={"Content-Type": "application/xml"},
                body='<?xml version="1.0" encoding="UTF-8"?><root><test/></root>',
                timeout=self.config.timeout,
            )
            self.scanned_endpoints.append(test_url)

            if xml_resp.status_code < 500 and xml_resp.status_code > 0:
                self._add_finding(
                    rule_id="DAST-XXE-ENDPOINT",
                    issue_type="dast_injection",
                    severity=Severity.HIGH,
                    message=f"XML-accepting endpoint detected: '{endpoint}'. "
                            "XML processing endpoints may be vulnerable to XXE attacks.",
                    endpoint=test_url,
                    cwe_id="CWE-611",
                    owasp_category="A05:2021",
                    evidence=f"HTTP {xml_resp.status_code} - endpoint '{endpoint}' accepted XML POST",
                    confidence=0.5,
                    remediation_hint="Configure XML parsers to disable external entity "
                                     "processing and DTD loading. Use secure alternatives "
                                     "like JSON where possible.",
                )
                break

        # Check for insecure deserialization indicators in response body
        deserialization_body_patterns = [
            (r"(?i)pickle\s*\.\s*(?:loads|load)", "Python pickle deserialization"),
            (r"(?i)yaml\.(?:load|loads)", "YAML deserialization (unsafe with default loader)"),
            (r"(?i)marshal\.(?:load|loads)", "Python marshal deserialization"),
            (r"(?i)java\.io\.(?:ObjectInputStream|Serializable)", "Java deserialization"),
            (r"(?i)Unmarshal|Deserialize|Deserialization", "Generic deserialization"),
            (r"(?i)PHP\s*(?:serialize|unserialize)", "PHP deserialization"),
        ]

        for pattern, indicator_name in deserialization_body_patterns:
            if re.search(pattern, resp.body, re.I):
                self._add_finding(
                    rule_id="DAST-INSECURE-DESERIALIZATION",
                    issue_type="dast_injection",
                    severity=Severity.MEDIUM,
                    message=f"Insecure deserialization indicator detected: {indicator_name}. "
                            "Insecure deserialization can lead to remote code execution.",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021",
                    evidence=f"Pattern '{pattern}' matched in response body",
                    confidence=0.35,
                    remediation_hint="Avoid using native deserialization formats. "
                                     "Use safe alternatives like JSON with a schema validator. "
                                     "Implement integrity checks (e.g., HMAC) on serialized data.",
                )
                break

        # Check for serialized content types in response headers
        content_type = resp.headers.get("Content-Type", "").lower()
        serialized_content_types = {
            "application/x-java-serialized-object": "Java serialized object",
            "application/php-serialized": "PHP serialized object",
            "application/x-www-form-urlencoded": None,  # Too generic, skip
        }
        for ct, label in serialized_content_types.items():
            if label and ct in content_type:
                self._add_finding(
                    rule_id="DAST-INSECURE-DESERIALIZATION",
                    issue_type="dast_injection",
                    severity=Severity.MEDIUM,
                    message=f"Insecure deserialization indicator detected: {label}. "
                            "Insecure deserialization can lead to remote code execution.",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021",
                    evidence=f"Content-Type header: {content_type}",
                    confidence=0.35,
                    remediation_hint="Avoid using native deserialization formats. "
                                     "Use safe alternatives like JSON with a schema validator. "
                                     "Implement integrity checks (e.g., HMAC) on serialized data.",
                )

    def _check_jwt_misconfiguration(self, resp: SafeResponse) -> None:
        """Check for JWT (JSON Web Token) misconfigurations.

        Analyzes response headers, cookies, and body for JWT tokens
        and checks for common security misconfigurations.
        """
        # Search for JWT tokens in response headers (Authorization Bearer)
        auth_header = resp.headers.get("Authorization", "")
        jwt_tokens: List[str] = []

        # Check Authorization header
        if "bearer" in auth_header.lower():
            token = auth_header.split(None, 1)[-1] if len(auth_header.split(None, 1)) > 1 else ""
            if token:
                jwt_tokens.append(token)

        # Check cookies for JWT patterns
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            # Common JWT cookie names
            for cookie_name in ["token", "jwt", "access_token", "id_token", "session"]:
                if cookie_name in set_cookie.lower():
                    match = re.search(rf"{cookie_name}=([^;]+)", set_cookie, re.I)
                    if match:
                        jwt_tokens.append(match.group(1))

        # Check response body for JWT tokens
        jwt_body_pattern = re.compile(
            r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
        )
        body_tokens = jwt_body_pattern.findall(resp.body)
        jwt_tokens.extend(body_tokens)

        # Analyze found JWT tokens
        for token in jwt_tokens[:5]:  # Limit analysis to first 5 tokens
            self._analyze_jwt_token(token)

    def _analyze_jwt_token(self, token: str) -> None:
        """Analyze a JWT token for security misconfigurations."""
        parts = token.split(".")
        if len(parts) < 2:
            return

        # Decode and check header
        import base64

        def decode_jwt_part(part: str) -> Dict:
            """Safely decode a JWT part (base64url)."""
            try:
                # Fix padding
                padded = part + "=" * (4 - len(part) % 4) if len(part) % 4 else part
                decoded = base64.urlsafe_b64decode(padded)
                return json.loads(decoded)
            except Exception:
                return {}

        header = decode_jwt_part(parts[0])

        # Check for "alg": "none" (unsigned JWT)
        alg = header.get("alg", "")
        if alg == "none" or alg == "None" or alg == "NONE":
            self._add_finding(
                rule_id="DAST-JWT-ALG-NONE",
                issue_type="dast_authentication",
                severity=Severity.CRITICAL,
                message="JWT token uses 'alg: none' which means the token is unsigned "
                        "and can be forged by anyone.",
                cwe_id="CWE-347",
                owasp_category="A07:2021",
                evidence=f"JWT header: alg=none in token starting with {parts[0][:30]}...",
                confidence=1.0,
                remediation_hint="Reject tokens with 'alg: none'. Configure the JWT library "
                                 "to require a valid signature algorithm. Never use "
                                 "'alg: none' in production.",
            )

        # Check for weak algorithms
        if alg in ("HS256", "HS384", "HS512"):
            # Symmetric algorithms with public verification can be forged
            self._add_finding(
                rule_id="DAST-JWT-SYMMETRIC-ALG",
                issue_type="dast_authentication",
                severity=Severity.MEDIUM,
                message="JWT token uses symmetric algorithm (HS256/HS384/HS512). "
                        "If the public key is known, tokens can be forged.",
                cwe_id="CWE-347",
                owasp_category="A07:2021",
                evidence=f"JWT algorithm: {alg}",
                confidence=0.6,
                remediation_hint="Use asymmetric algorithms (RS256, ES256) instead of "
                                 "symmetric ones. Never use the same key for signing "
                                 "and verification.",
            )

        # Check for algorithm confusion risk
        if alg and alg.startswith("RS"):
            self._add_finding(
                rule_id="DAST-JWT-ALG-CONFUSION",
                issue_type="dast_authentication",
                severity=Severity.LOW,
                message="JWT token uses RSA algorithm (RS256/RS384/RS512). "
                        "Ensure the server properly validates the algorithm to prevent "
                        "algorithm confusion attacks.",
                cwe_id="CWE-347",
                owasp_category="A07:2021",
                evidence=f"JWT algorithm: {alg}",
                confidence=0.3,
                remediation_hint="Always validate the JWT algorithm against a whitelist. "
                                 "Use the 'aud' claim to bind the token to a specific "
                                 "intended audience.",
            )

        # Check payload for common issues
        if len(parts) > 1:
            payload = decode_jwt_part(parts[1])

            # Check for missing expiration
            if "exp" not in payload:
                self._add_finding(
                    rule_id="DAST-JWT-NO-EXPIRY",
                    issue_type="dast_authentication",
                    severity=Severity.HIGH,
                    message="JWT token does not have an 'exp' (expiration) claim. "
                            "Tokens without expiration never expire.",
                    cwe_id="CWE-613",
                    owasp_category="A07:2021",
                    evidence="JWT payload missing 'exp' claim",
                    confidence=0.9,
                    remediation_hint="Always include an 'exp' claim in JWT tokens with "
                                     "a reasonable expiration time (e.g., 15-60 minutes "
                                     "for access tokens).",
                )

            # Check for long-lived tokens
            if "exp" in payload and isinstance(payload["exp"], (int, float)):
                import datetime
                exp_time = datetime.datetime.fromtimestamp(payload["exp"], tz=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                token_lifetime = (exp_time - now).total_seconds()

                if token_lifetime > 86400:  # More than 24 hours
                    self._add_finding(
                        rule_id="DAST-JWT-LONG-LIVED",
                        issue_type="dast_authentication",
                        severity=Severity.MEDIUM,
                        message=f"JWT token has an excessively long lifetime "
                                f"({token_lifetime / 3600:.1f} hours). Long-lived tokens "
                                "increase the risk of token theft.",
                        cwe_id="CWE-613",
                        owasp_category="A07:2021",
                        evidence=f"Token expires at: {exp_time.isoformat()}",
                        confidence=0.7,
                        remediation_hint="Use short-lived access tokens (15-60 minutes). "
                                         "Use refresh tokens for longer sessions.",
                    )

            # Check for "jti" (JWT ID), "iss" (issuer), and "aud" (audience)
            missing_claims = []
            if "iss" not in payload:
                missing_claims.append("iss (issuer)")
            if "aud" not in payload:
                missing_claims.append("aud (audience)")

            if missing_claims:
                self._add_finding(
                    rule_id="DAST-JWT-MISSING-CLAIMS",
                    issue_type="dast_authentication",
                    severity=Severity.LOW,
                    message=f"JWT token missing recommended claims: {', '.join(missing_claims)}. "
                            "These claims help prevent token reuse and misdirection.",
                    cwe_id="CWE-347",
                    owasp_category="A07:2021",
                    evidence=f"Missing claims: {', '.join(missing_claims)}",
                    confidence=0.5,
                    remediation_hint="Include 'iss' (issuer) and 'aud' (audience) claims "
                                     "in all JWT tokens. Validate these claims on the server side.",
                )

    def _check_rate_limiting(self) -> None:
        """Check for missing rate limiting by making rapid sequential requests."""
        test_endpoint = build_url(self.origin, "login")
        test_endpoint = build_url(self.origin, "login")

        # Make several rapid requests to the same endpoint
        response_times: List[float] = []
        response_codes: List[int] = []

        for i in range(5):
            resp = self._make_request(
                test_endpoint,
                timeout=self.config.timeout,
            )
            response_times.append(resp.elapsed_ms)
            response_codes.append(resp.status_code)

        # All requests succeeded with 200 — possible missing rate limiting
        if all(code == 200 for code in response_codes):
            avg_time = sum(response_times) / len(response_times)

            self._add_finding(
                rule_id="DAST-NO-RATE-LIMITING",
                issue_type="dast_insecure_design",
                severity=Severity.LOW,
                message="No rate limiting detected. "
                        "The endpoint accepted 5 rapid requests without throttling.",
                cwe_id="CWE-770",
                owasp_category="A04:2021",
                evidence=f"All 5 requests returned HTTP 200 (avg response: {avg_time:.0f}ms). "
                         "No 429 status code observed.",
                confidence=0.4,
                remediation_hint="Implement rate limiting for authentication and "
                                 "sensitive endpoints. Use 429 Too Many Requests "
                                 "responses with Retry-After headers.",
            )

    def _check_cloud_metadata_exposure(self) -> None:
        """Check for cloud metadata endpoint exposure (SSRF indicator)."""
        for provider, metadata_type, metadata_url, message, severity in CLOUD_METADATA_PATTERNS:
            try:
                resp = make_request(
                    metadata_url,
                    headers={"Metadata": "true"} if provider == "gcp" else {},
                    timeout=3,  # Short timeout for metadata checks
                )
                if resp.status_code > 0 and resp.status_code < 500:
                    self._add_finding(
                        rule_id=f"DAST-{provider.upper()}-METADATA-ACCESSIBLE",
                        issue_type="dast_ssrf",
                        severity=severity,
                        message=f"{provider.upper()} {metadata_type} endpoint is accessible: "
                                f"{message}",
                        cwe_id="CWE-918",
                        owasp_category="A10:2021",
                        evidence=f"HTTP {resp.status_code} - metadata endpoint responded "
                                 f"with {len(resp.body)} bytes",
                        confidence=0.9,
                        remediation_hint="Block access to cloud metadata endpoints using "
                                         "network policies and IAM roles. Disable IMDSv1 "
                                         "and use IMDSv2 with hop limits.",
                    )
            except Exception:
                pass

    def _check_ssrf_indicators(self, resp: SafeResponse) -> None:
        """Check for SSRF indicators in the application."""
        # Check if the application exposes features that make HTTP requests
        ssrf_features = [
            (r"(?i)(?:fetch|request|curl|wget|url|proxy)\s*[=:]\s*['\"][^'\"]+['\"]",
             "Application reads external URLs from parameters"),
            (r"(?i)(?:webhook|callback|notify|pingback)\s*[=:]\s*['\"][^'\"]+['\"]",
             "Application has webhook/callback features that fetch external URLs"),
        ]

        body_lower = resp.body.lower()
        for pattern, indicator in ssrf_features:
            if re.search(pattern, body_lower, re.I):
                match = re.search(pattern, body_lower, re.I)
                self._add_finding(
                    rule_id="DAST-SSRF-INDICATOR",
                    issue_type="dast_ssrf",
                    severity=Severity.MEDIUM,
                    message=f"SSRF indicator detected: {indicator}. "
                            "Features that fetch external URLs may be vulnerable to SSRF.",
                    cwe_id="CWE-918",
                    owasp_category="A10:2021",
                    evidence=f"{match.group()[:200] if match else indicator}" if match else indicator,
                    confidence=0.3,
                    remediation_hint="Implement a URL allowlist for all external requests. "
                                     "Disable or restrict features that fetch user-supplied URLs. "
                                     "Use network segmentation to limit outbound traffic.",
                )
                break

        # Check for SSRF via URL parameter testing
        ssrf_test_url = f"{self.target_url}?url=http://169.254.169.254/latest/meta-data/"
        ssrf_resp = self._make_request(ssrf_test_url, timeout=self.config.timeout)

        if ssrf_resp.status_code > 0 and ssrf_resp.status_code < 500:
            if "ami-id" in ssrf_resp.body or "instance-id" in ssrf_resp.body or "security-credentials" in ssrf_resp.body:
                self._add_finding(
                    rule_id="DAST-SSRF-CLOUD-METADATA",
                    issue_type="dast_ssrf",
                    severity=Severity.CRITICAL,
                    message="SSRF vulnerability confirmed. Application fetches URLs "
                            "from user input and returned cloud metadata.",
                    cwe_id="CWE-918",
                    owasp_category="A10:2021",
                    evidence=f"Metadata endpoint responded to SSRF probe at {ssrf_test_url}",
                    confidence=0.95,
                    remediation_hint="Block access to cloud metadata endpoints. "
                                     "Implement a URL allowlist. Use IMDSv2 with hop limits.",
                )


    # ═══════════════════════════════════════════════════════════════════
    # NEW Phase 22-29: Modern web security checks
    # ═══════════════════════════════════════════════════════════════════

    def _check_graphql_introspection(self) -> None:
        """Check for exposed GraphQL introspection endpoint."""
        for endpoint in ["/graphql", "/api/graphql", "/gql", "/api/gql"]:
            if len(self.scanned_endpoints) >= self.config.max_endpoints:
                break
            url = build_url(self.origin, endpoint)
            resp = self._make_request(
                url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"query":"{__schema{types{name}}}"}',
                timeout=self.config.timeout,
            )
            self.scanned_endpoints.append(url)
            if resp.status_code == 200 and "__schema" in resp.body:
                self._add_finding(
                    rule_id="DAST-GRAPHQL-INTROSPECTION",
                    issue_type="dast_information_disclosure",
                    severity=Severity.MEDIUM,
                    message=f"GraphQL introspection is enabled at '{endpoint}'. This exposes the entire API schema to attackers.",
                    endpoint=url,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    evidence=f"Introspection query returned schema data ({len(resp.body)} bytes)",
                    confidence=0.95,
                    remediation_hint="Disable GraphQL introspection in production. Use Apollo Server's introspection: false or equivalent for your framework.",
                )
                break

    def _check_csp_analysis(self, resp: SafeResponse) -> None:
        """Analyze Content-Security-Policy header for dangerous directives."""
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return
        findings_list = []
        if "'unsafe-inline'" in csp:
            findings_list.append("'unsafe-inline' (allows inline scripts/styles → XSS risk)")
        if "'unsafe-eval'" in csp:
            findings_list.append("'unsafe-eval' (allows eval() → code injection risk)")
        if re.search(r"(?:script-src|default-src)\s+[^;]*\*", csp):
            findings_list.append("wildcard source in script-src or default-src (allows scripts from any domain)")
        if "data:" in csp:
            findings_list.append("data: URI allowed (can be used for XSS payloads)")
        if findings_list:
            self._add_finding(
                rule_id="DAST-CSP-INSECURE",
                issue_type="dast_security_misconfiguration",
                severity=Severity.MEDIUM,
                message=f"Content-Security-Policy contains insecure directives: {'; '.join(findings_list)}",
                cwe_id="CWE-1021",
                owasp_category="A05:2021",
                evidence=csp[:300],
                confidence=0.9,
                remediation_hint="Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes for inline scripts. Use strict-dynamic for script loading.",
            )

    def _check_http_methods(self) -> None:
        """Check for dangerous HTTP methods enabled on the server."""
        url = build_url(self.origin, "")
        resp = self._make_request(url, method="OPTIONS", timeout=self.config.timeout)
        if resp.status_code == 0:
            return
        allow_header = resp.headers.get("Allow", resp.headers.get("Access-Control-Allow-Methods", ""))
        if not allow_header:
            return
        dangerous_methods = ["TRACE", "PUT", "DELETE", "PATCH"]
        found_dangerous = [m for m in dangerous_methods if m.upper() in allow_header.upper()]
        if found_dangerous:
            self._add_finding(
                rule_id="DAST-HTTP-METHODS",
                issue_type="dast_security_misconfiguration",
                severity=Severity.MEDIUM,
                message=f"Potentially dangerous HTTP methods enabled: {', '.join(found_dangerous)}. "
                        "TRACE can enable XST attacks. PUT/DELETE may allow unauthorized modifications.",
                cwe_id="CWE-749",
                owasp_category="A05:2021",
                evidence=f"Allow header: {allow_header}",
                confidence=0.8,
                remediation_hint="Disable TRACE method. Restrict PUT, DELETE, PATCH to authenticated users only. Use proper HTTP method allowlisting.",
            )

    def _check_framework_fingerprinting(self, resp: SafeResponse) -> None:
        """Detect framework/technology stack from response headers and body patterns."""
        frameworks: List[Tuple[str, str, str]] = []
        # Check headers
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "").lower()
        set_cookie = resp.headers.get("Set-Cookie", "")
        # Django
        if "csrftoken" in set_cookie.lower() or "django" in powered:
            frameworks.append(("Django", "Python", "Cookie: csrftoken"))
        # Rails
        if "_session_id" in set_cookie.lower() or "rails" in server.lower():
            frameworks.append(("Ruby on Rails", "Ruby", "Server/Rails signature"))
        # Express
        if "express" in powered or "connect.sid" in set_cookie.lower():
            frameworks.append(("Express.js", "Node.js", "Cookie: connect.sid / X-Powered-By"))
        # Laravel
        if "laravel_session" in set_cookie.lower() or "laravel" in powered:
            frameworks.append(("Laravel", "PHP", "Cookie: laravel_session"))
        # Spring
        if "JSESSIONID" in set_cookie or "spring" in powered:
            frameworks.append(("Spring Boot", "Java", "Cookie: JSESSIONID"))
        # ASP.NET
        if "ASPSESSIONID" in set_cookie or "ASP.NET" in powered:
            frameworks.append(("ASP.NET", "C#", "Cookie: ASPSESSIONID"))
        # Flask
        if "session" in set_cookie.lower() and "python" in server.lower():
            frameworks.append(("Flask", "Python", "Server/Python signature"))
        if frameworks:
            fw_desc = "; ".join(f"{fw[0]} ({fw[1]}, indicator: {fw[2]})" for fw in frameworks)
            self._add_finding(
                rule_id="DAST-FRAMEWORK-FINGERPRINT",
                issue_type="dast_information_disclosure",
                severity=Severity.LOW,
                message=f"Framework/technology stack detected: {fw_desc}",
                cwe_id="CWE-200",
                owasp_category="A05:2021",
                evidence=f"Detected: {', '.join(fw[0] for fw in frameworks)}",
                confidence=0.7,
                remediation_hint="Remove or obfuscate framework-specific headers and cookie names. Use generic Server header. Strip X-Powered-By.",
            )

    def _check_cookie_prefix(self, resp: SafeResponse) -> None:
        """Check for __Host- and __Secure- cookie prefixes on session cookies."""
        set_cookie = resp.headers.get("Set-Cookie", "")
        if not set_cookie:
            return
        session_cookie_names = {"session", "sessionid", "sid", "connect.sid", "JSESSIONID",
                                 "laravel_session", "PHPSESSID", "_session_id", "csrftoken",
                                 "token", "jwt", "access_token"}
        cookies: List[str] = [set_cookie]
        all_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
        if all_cookies:
            cookies = all_cookies
        for cookie_header in cookies:
            cookie_name = cookie_header.split("=", 1)[0] if "=" in cookie_header else ""
            name_lower = cookie_name.lower()
            if any(s in name_lower for s in session_cookie_names):
                if not cookie_name.startswith("__Host-") and not cookie_name.startswith("__Secure-"):
                    self._add_finding(
                        rule_id="DAST-COOKIE-PREFIX",
                        issue_type="dast_security_misconfiguration",
                        severity=Severity.LOW,
                        message=f"Session cookie '{cookie_name}' does not use __Host- or __Secure- prefix. "
                                "Without these prefixes, cookies may be set by subdomains or over HTTP.",
                        cwe_id="CWE-1275",
                        owasp_category="A05:2021",
                        evidence=f"Cookie: {cookie_header[:150]}",
                        confidence=0.6,
                        remediation_hint="Rename session cookies to use __Host- prefix (most secure) or __Secure- prefix. "
                                         "__Host- cookies require Secure, Path=/, and no Domain attribute.",
                    )

    def _check_subresource_integrity(self, resp: SafeResponse) -> None:
        """Check for 3rd-party <script> tags without Subresource Integrity (SRI) hashes."""
        # Find external script tags without integrity attribute
        script_pattern = re.compile(
            r'<script[^>]*src=["\'](https?:)?//([^"\']+)["\'][^>]*>',
            re.IGNORECASE,
        )
        scripts_without_integrity = []
        for match in script_pattern.finditer(resp.body):
            tag = match.group(0)
            if "integrity=" not in tag.lower():
                domain = match.group(2)
                scripts_without_integrity.append(domain[:60])
        if scripts_without_integrity:
            unique_sources = list(set(scripts_without_integrity))[:5]
            self._add_finding(
                rule_id="DAST-SRI-MISSING",
                issue_type="dast_security_misconfiguration",
                severity=Severity.LOW,
                message=f"{len(scripts_without_integrity)} external script(s) loaded without Subresource Integrity (SRI) hashes. "
                        f"Sources: {', '.join(unique_sources)}",
                cwe_id="CWE-829",
                owasp_category="A08:2021",
                evidence=f"Scripts from: {', '.join(unique_sources)}",
                confidence=0.85,
                remediation_hint="Add integrity=\"sha384-...\" attributes to all external script tags. Use https://www.srihash.org to generate hashes.",
            )

    def _check_websocket_security(self, resp: SafeResponse) -> None:
        """Check for WebSocket security indicators in response."""
        body_lower = resp.body.lower()
        ws_indicators = [
            (r"(?:ws|wss)://", "WebSocket URL found in response"),
            (r"new\s+WebSocket\s*\(", "JavaScript WebSocket constructor found"),
        ]
        for pattern, indicator in ws_indicators:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                ws_urls = list(set(matches))[:3]
                self._add_finding(
                    rule_id="DAST-WEBSOCKET",
                    issue_type="dast_security_misconfiguration",
                    severity=Severity.LOW,
                    message=f"WebSocket usage detected: {indicator}. Ensure WebSocket connections use wss://, validate Origin headers, and implement authentication.",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021",
                    evidence=f"Patterns found: {', '.join(str(u) for u in ws_urls)}",
                    confidence=0.7,
                    remediation_hint="Use wss:// (WebSocket Secure) only. Validate the Origin header on the server. Implement token-based WebSocket authentication.",
                )
                break

    def _check_content_type_sniffing(self, resp: SafeResponse) -> None:
        """Check for X-Content-Type-Options: nosniff header."""
        cto = resp.headers.get("X-Content-Type-Options", "")
        if cto.lower() != "nosniff":
            self._add_finding(
                rule_id="DAST-NO-NOSNIFF",
                issue_type="dast_security_misconfiguration",
                severity=Severity.LOW,
                message="Missing X-Content-Type-Options: nosniff header. Browsers may MIME-sniff content, enabling XSS via uploaded files.",
                cwe_id="CWE-693",
                owasp_category="A05:2021",
                evidence=f"X-Content-Type-Options: {cto or '(not set)'}",
                confidence=0.9,
                remediation_hint="Add 'X-Content-Type-Options: nosniff' header to all responses to prevent MIME type sniffing.",
            )


# ═══════════════════════════════════════════════════════════════════════
# Main scan function (pipeline interface)
# ═══════════════════════════════════════════════════════════════════════

def scan_url(
    target_url: str,
    severity_threshold: Severity = Severity.HIGH,
    config: Optional[DASTConfig] = None,
) -> ScanResult:
    """Run a full DAST scan against a target URL.

    This is the main entry point called from the pipeline.

    Args:
        target_url: The URL to scan.
        severity_threshold: Minimum severity to trigger BLOCK.
        config: Optional DAST scanner configuration.

    Returns:
        A ScanResult containing all findings and metadata.
    """
    scanner = DASTScanner(target_url, config=config or DASTConfig())
    result = scanner.scan()
    result.severity_threshold = severity_threshold
    return result
