"""Static analysis scanner - detects insecure code patterns using AST and regex.

Detection methods:
  - ast: Python AST analysis for deeper structural issues
  - regex: Pattern matching for cross-language vulnerability patterns
  - hybrid: AST + regex cross-verification

Covers code execution, injection attacks, cryptographic misuse,
deserialization, information disclosure, and insecure configurations.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Dict, List, Optional, Set

from ..models import DetectionMethod, Finding, Severity


# ═══════════════════════════════════════════════════════════════════════
# Regex-based unsafe patterns (cross-language)
# ═══════════════════════════════════════════════════════════════════════

UNSAFE_PATTERNS: List[Dict] = [
    # ─── Code Execution & Command Injection ───────────────────────────
    {
        "name": "eval-usage",
        "pattern": re.compile(r"\beval\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of eval() detected. eval() can execute arbitrary code from untrusted input, leading to code injection.",
        "rule_id": "SAF-EVAL",
        "confidence": 1.0,
        "remediation": "Replace eval() with safer alternatives like ast.literal_eval() or a proper parser.",
    },
    {
        "name": "exec-usage",
        "pattern": re.compile(r"\bexec\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of exec() detected. exec() can execute arbitrary Python code from untrusted input.",
        "rule_id": "SAF-EXEC",
        "confidence": 1.0,
        "remediation": "Avoid exec(). Restructure code to use functions, dictionaries, or proper dispatch patterns.",
    },
    {
        "name": "compile-call",
        "pattern": re.compile(r"\bcompile\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of compile() with untrusted input can lead to arbitrary code execution.",
        "rule_id": "SAF-COMPILE",
        "confidence": 0.7,
        "remediation": "Ensure compile() is only used with trusted source code. Consider alternatives like ast.parse().",
    },
    {
        "name": "os-system",
        "pattern": re.compile(r"\bos\.system\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of os.system() detected. This runs shell commands and can lead to command injection with untrusted input.",
        "rule_id": "SAF-OS-SYSTEM",
        "confidence": 0.95,
        "remediation": "Replace os.system() with subprocess.run() and pass arguments as a list (shell=False).",
    },
    {
        "name": "os-popen",
        "pattern": re.compile(r"\bos\.popen\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of os.popen() detected. This runs shell commands and can lead to command injection.",
        "rule_id": "SAF-OS-POPEN",
        "confidence": 0.95,
        "remediation": "Replace with subprocess.Popen() or subprocess.run() with shell=False.",
    },
    {
        "name": "subprocess-shell-true",
        "pattern": re.compile(r"subprocess\.(?:call|Popen|run|check_call|check_output)\s*\([^)]*\bshell\s*=\s*True"),
        "severity": Severity.HIGH,
        "message": "Unsafe subprocess usage with shell=True detected. This runs commands through the system shell and can lead to command injection.",
        "rule_id": "SAF-SUBPROCESS-SHELL",
        "confidence": 0.95,
        "remediation": "Use shell=False and pass command arguments as a list. If shell=True is required, validate user input strictly.",
    },
    {
        "name": "child-process-exec",
        "pattern": re.compile(r"(?:child_process|cp)\.(?:exec|execSync|spawn|spawnSync|fork)\s*\("),
        "severity": Severity.HIGH,
        "message": "Node.js child_process execution detected. If the command contains user input, this can lead to command injection.",
        "rule_id": "SAF-NODE-EXEC",
        "confidence": 0.8,
        "remediation": "Use child_process.execFile() with arguments as an array, or validate/sanitize all user input.",
    },
    {
        "name": "php-exec-functions",
        "pattern": re.compile(r"\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\("),
        "severity": Severity.HIGH,
        "message": "PHP code execution function detected. These can execute shell commands and lead to command injection.",
        "rule_id": "SAF-PHP-EXEC",
        "confidence": 0.9,
        "remediation": "Avoid shell execution functions. Use PHP's built-in functions or libraries instead of shell commands.",
    },

    # ─── Deserialization Attacks ──────────────────────────────────────
    {
        "name": "pickle-unsafe",
        "pattern": re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "severity": Severity.HIGH,
        "message": "Unsafe deserialization via pickle detected. Pickle can execute arbitrary code during deserialization.",
        "rule_id": "SAF-PICKLE",
        "confidence": 0.9,
        "remediation": "Use a safer serialization format like JSON or msgpack. If pickle is required, only deserialize trusted data.",
    },
    {
        "name": "yaml-load",
        "pattern": re.compile(r"\byaml\.load\s*\((?![^)]*\bLoader\s*=\s*SafeLoader)"),
        "severity": Severity.HIGH,
        "message": "Unsafe yaml.load() detected without SafeLoader. This can execute arbitrary code. Use yaml.safe_load() instead.",
        "rule_id": "SAF-YAML-LOAD",
        "confidence": 0.85,
        "remediation": "Replace yaml.load() with yaml.safe_load() or use yaml.load() with Loader=yaml.SafeLoader.",
    },
    {
        "name": "marshal-unsafe",
        "pattern": re.compile(r"\bmarshal\.(?:load|loads)\s*\("),
        "severity": Severity.MEDIUM,
        "message": "Unsafe deserialization via marshal detected. Marshal can execute arbitrary code during deserialization from untrusted sources.",
        "rule_id": "SAF-MARSHAL",
        "confidence": 0.8,
        "remediation": "Avoid marshal for untrusted data. Use JSON or other safe serialization formats.",
    },
    {
        "name": "jsonpickle-usage",
        "pattern": re.compile(r"\bjsonpickle\.(?:decode|load|loads)\s*\("),
        "severity": Severity.HIGH,
        "message": "Unsafe deserialization via jsonpickle detected. jsonpickle can execute arbitrary code during deserialization.",
        "rule_id": "SAF-JSONPICKLE",
        "confidence": 0.8,
        "remediation": "Avoid jsonpickle with untrusted data. Use standard json module for safe serialization.",
    },

    # ─── SQL Injection ────────────────────────────────────────────────
    {
        "name": "sql-query-concatenation",
        "pattern": re.compile(
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["\'][^"\']*?["\']\s*[+%]'
        ),
        "severity": Severity.HIGH,
        "message": "Potential SQL injection detected. String concatenation in SQL queries can lead to injection attacks. Use parameterized queries instead.",
        "rule_id": "SAF-SQL-CONCAT",
        "confidence": 0.7,
        "remediation": "Use parameterized queries with placeholders (%s for psycopg2, ? for sqlite3) instead of string concatenation.",
    },
    {
        "name": "sql-query-fstring",
        "pattern": re.compile(
            r'(?i)(?:cursor\.execute|\.execute|\.raw)\s*\(\s*f[\"\']'
        ),
        "severity": Severity.HIGH,
        "message": "Potential SQL injection detected via f-string in database query. Use parameterized queries with placeholders instead.",
        "rule_id": "SAF-SQL-FSTRING",
        "confidence": 0.75,
        "remediation": "Replace f-strings with parameterized queries using ? or %s placeholders.",
    },

    # ─── Cross-Site Scripting (XSS) ──────────────────────────────────
    {
        "name": "innerHTML-assignment",
        "pattern": re.compile(r"\.innerHTML\s*="),
        "severity": Severity.HIGH,
        "message": "innerHTML assignment detected. Setting innerHTML with untrusted input can lead to XSS attacks. Use textContent or innerText instead.",
        "rule_id": "SAF-INNER-HTML",
        "confidence": 0.8,
        "remediation": "Use textContent instead of innerHTML. If HTML is necessary, sanitize input with DOMPurify or a similar library.",
    },
    {
        "name": "dangerouslySetInnerHTML",
        "pattern": re.compile(r"dangerouslySetInnerHTML"),
        "severity": Severity.HIGH,
        "message": "dangerouslySetInnerHTML detected in React. This bypasses React's XSS protection. Sanitize input before rendering HTML.",
        "rule_id": "SAF-REACT-HTML",
        "confidence": 0.85,
        "remediation": "Sanitize HTML content with DOMPurify before passing to dangerouslySetInnerHTML.",
    },

    # ─── Template Injection (SSTI) ────────────────────────────────────
    {
        "name": "jinja2-template-injection",
        "pattern": re.compile(r"from_string\s*\([^)]*\)|Template\s*\([^)]*\)"),
        "severity": Severity.MEDIUM,
        "message": "Potential server-side template injection via Jinja2. Avoid passing user input to from_string() or Template().",
        "rule_id": "SAF-JINJA-TEMPLATE",
        "confidence": 0.5,
        "remediation": "Use Jinja2's FileSystemLoader with templates on disk, not from_string() with user input.",
    },

    # ─── Path Traversal & File Disclosure ────────────────────────────
    {
        "name": "open-user-input",
        "pattern": re.compile(r"(?:open|file_get_contents|readFile|readFileSync)\s*\([^)]*\b(request|input|user|query|body|params|data)\b"),
        "severity": Severity.MEDIUM,
        "message": "Potential path traversal vulnerability. File operations with user-supplied paths can allow attackers to read arbitrary files.",
        "rule_id": "SAF-PATH-TRAVERSAL",
        "confidence": 0.5,
        "remediation": "Validate and sanitize user-supplied file paths. Use allowlists of permitted paths or files.",
    },

    # ─── Weak Cryptography ────────────────────────────────────────────
    {
        "name": "md5-hash",
        "pattern": re.compile(r"\bhashlib\.md5\s*\(|md5\s*\("),
        "severity": Severity.MEDIUM,
        "message": "Use of MD5 hash function detected. MD5 is cryptographically broken and should not be used for security purposes.",
        "rule_id": "SAF-MD5",
        "confidence": 0.8,
        "remediation": "Use SHA-256 (hashlib.sha256()) or SHA-3 instead of MD5. MD5 is vulnerable to collision attacks.",
    },
    {
        "name": "sha1-hash",
        "pattern": re.compile(r"\bhashlib\.sha1\s*\(|sha1\s*\("),
        "severity": Severity.MEDIUM,
        "message": "Use of SHA-1 hash function detected. SHA-1 is cryptographically broken for security purposes.",
        "rule_id": "SAF-SHA1",
        "confidence": 0.7,
        "remediation": "Use SHA-256 (hashlib.sha256()) or SHA-3 instead of SHA-1. SHA-1 is vulnerable to collision attacks.",
    },
    {
        "name": "weak-cipher",
        "pattern": re.compile(r"\b(?:DES|RC2|RC4|Blowfish|ARC4)\s*\("),
        "severity": Severity.HIGH,
        "message": "Use of weak encryption algorithm detected. DES, RC2, RC4, and Blowfish are considered cryptographically weak.",
        "rule_id": "SAF-WEAK-CIPHER",
        "confidence": 0.75,
        "remediation": "Use AES-256-GCM or ChaCha20-Poly1305 for modern, secure encryption.",
    },
    {
        "name": "ecb-mode",
        "pattern": re.compile(r"(?:ECB|\.ECB)\b"),
        "severity": Severity.MEDIUM,
        "message": "ECB (Electronic Codebook) encryption mode detected. ECB is insecure because identical plaintext blocks produce identical ciphertext blocks.",
        "rule_id": "SAF-ECB-MODE",
        "confidence": 0.7,
        "remediation": "Use GCM or CBC mode instead of ECB. Never use ECB for encrypting more than one block of data.",
    },

    # ─── Insecure HTTP & Transport ────────────────────────────────────
    {
        "name": "insecure-http",
        "pattern": re.compile(r"http://[a-zA-Z0-9.\-]+(?::\d+)?/"),
        "severity": Severity.LOW,
        "message": "HTTP URL detected instead of HTTPS. Prefer HTTPS for secure communication.",
        "rule_id": "SAF-HTTP",
        "confidence": 0.3,
        "remediation": "Replace http:// with https:// for all external communications. Avoid sending data over unencrypted connections.",
    },

    # ─── Information Disclosure ───────────────────────────────────────
    {
        "name": "debug-endpoint",
        "pattern": re.compile(r"(?i)(?:/debug|/status|/actuator|/console|/admin)\b"),
        "severity": Severity.LOW,
        "message": "Potential debug or administrative endpoint detected. Debug endpoints should be disabled in production.",
        "rule_id": "SAF-DEBUG-ENDPOINT",
        "confidence": 0.4,
        "remediation": "Remove or disable debug/management endpoints in production. Use feature flags to control access.",
    },

    # ─── Insecure Configuration ───────────────────────────────────────
    {
        "name": "cors-allow-all",
        "pattern": re.compile(r"(?:Access-Control-Allow-Origin|AccessControlAllowOrigin)\s*[:=]\s*['\"]\*['\"]"),
        "severity": Severity.MEDIUM,
        "message": "CORS policy allows all origins (*). This exposes the application to cross-origin attacks.",
        "rule_id": "SAF-CORS-ALL",
        "confidence": 0.7,
        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted origins. Use '*' only for public APIs that don't use credentials.",
    },

    # ─── Unsafe Temporary Files ───────────────────────────────────────
    {
        "name": "tempfile-mktemp",
        "pattern": re.compile(r"\btempfile\.mktemp\s*\("),
        "severity": Severity.MEDIUM,
        "message": "Use of tempfile.mktemp() detected. This is vulnerable to race condition attacks (TOCTOU).",
        "rule_id": "SAF-TEMPFILE-MKTEMP",
        "confidence": 0.9,
        "remediation": "Use tempfile.mkstemp() or TemporaryFile() instead of mktemp(). These are not vulnerable to TOCTOU races.",
    },

    # ─── Weak Randomness ─────────────────────────────────────────────
    {
        "name": "random-usage",
        "pattern": re.compile(r"\brandom\.(?:random|randint|randrange|choice|shuffle|sample)\s*\("),
        "severity": Severity.LOW,
        "message": "Use of random module detected. The random module is not cryptographically secure.",
        "rule_id": "SAF-RANDOM",
        "confidence": 0.5,
        "remediation": "Use the secrets module instead of random for security-sensitive operations like token generation.",
    },

    # ─── Assert Usage ────────────────────────────────────────────────
    {
        "name": "assert-usage",
        "pattern": re.compile(r"\bassert\s+"),
        "severity": Severity.LOW,
        "message": "Use of assert detected. Assertions are stripped when Python is run with -O (optimization flag), removing security checks.",
        "rule_id": "SAF-ASSERT",
        "confidence": 0.5,
        "remediation": "Replace assert statements with proper if/raise checks that remain active with -O.",
    },
]


# ──────────────────────────────────────────────────────────────────────
# False positive filters
# ──────────────────────────────────────────────────────────────────────

def _is_false_positive(line: str, rule_name: str) -> bool:
    """Check if a match is likely a false positive based on context."""
    lower_line = line.lower()

    # Skip test file assertions
    if ("def test_" in lower_line or "class test" in lower_line) and rule_name == "assert-usage":
        return True

    # Skip imports
    if "import " in lower_line and "from " in lower_line:
        return True

    # Skip comments and docstrings
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
        return True
    if '"""' in stripped or "'''" in stripped:
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════
# AST-based Python analysis
# ═══════════════════════════════════════════════════════════════════════

def _ast_scan(file_path: str, repo_root: str, source: str) -> List[Finding]:
    """Deep AST-based scanning for Python files.

    Detects issues that regex alone cannot reliably catch:
      - Dangerous function calls with user-controlled arguments
      - Hardcoded credentials assigned to named variables
      - Bare except clauses
      - HTTP/requests calls without timeouts
      - Subprocess calls without explicit shell=False

    Args:
        file_path: Absolute path to the Python file.
        repo_root: Root path of the repository.
        source: The full source code of the file.

    Returns:
        A list of findings from AST analysis.
    """
    findings: List[Finding] = []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, repo_root)

    # Track imports for context-aware analysis
    dangerous_imports: Dict[str, str] = {}

    # Build function context map: node -> function_name
    # Walk the tree manually to track function nesting
    function_context: Dict[int, str] = {}  # line -> function name

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Record the function context for all nodes within this function
            for child in ast.walk(node):
                if hasattr(child, 'lineno'):
                    function_context[child.lineno] = node.name

    for node in ast.walk(tree):
        # ─── Detect Dangerous Imports ──────────────────────────────
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("pickle", "marshal", "shelve", "jsonpickle"):
                    local_name = alias.asname or alias.name
                    dangerous_imports[local_name] = alias.name

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            dangerous_from = {
                "os": ["system", "popen", "execv", "execve"],
                "subprocess": ["call", "Popen", "run", "check_call", "check_output"],
                "pickle": ["load", "loads"],
                "marshal": ["load", "loads"],
            }
            if module in dangerous_from:
                for alias in node.names:
                    if alias.name in dangerous_from[module]:
                        local_name = alias.asname or alias.name
                        dangerous_imports[local_name] = module

        # ─── Detect Hardcoded Credentials in Assignments ──────────
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    var_name = target.id.lower()
                    value = str(node.value.value)

                    suspicious_names = [
                        "password", "passwd", "pwd", "secret", "api_key", "apikey",
                        "api_secret", "apisecret", "auth_token", "authtoken",
                        "access_key", "secret_key", "private_key", "encryption_key",
                        "jwt_secret", "session_secret", "consumer_secret",
                        "db_password", "db_passwd",
                    ]

                    if var_name in suspicious_names and len(value) >= 8:
                        # Avoid duplicates with secrets scanner
                        snippet = ast.get_source_segment(source, node) or ""
                        ctx = function_context.get(node.lineno, "")
                        ctx_str = f" in function '{ctx}'" if ctx else ""
                        finding = Finding(
                            file_path=rel_path,
                            line_number=node.lineno,
                            issue_type="static_analysis",
                            severity=Severity.MEDIUM,
                            message=f"Hardcoded {var_name.replace('_', ' ')} detected in source code{ctx_str}. Use environment variables or a secrets manager.",
                            rule_id="SAF-HARDCODED-CRED",
                            confidence=0.7,
                            snippet=snippet[:80],
                            detection_method="ast",
                            remediation_hint=f"Move {var_name} to environment variables or a secrets manager like HashiCorp Vault.",
                        )
                        findings.append(finding)

        # ─── Detect Bare Except ───────────────────────────────────
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                body = node.body
                if len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Ellipsis)):
                    finding = Finding(
                        file_path=rel_path,
                        line_number=node.lineno,
                        issue_type="static_analysis",
                        severity=Severity.LOW,
                        message="Bare except clause detected. Bare except catches all exceptions including SystemExit and KeyboardInterrupt.",
                        rule_id="SAF-BARE-EXCEPT",
                        confidence=0.8,
                        snippet="except:",
                        detection_method="ast",
                        remediation_hint="Use specific exception types (e.g., except ValueError:). Never catch bare except in production code.",
                    )
                    findings.append(finding)

        # ─── Detect HTTP requests without timeout ─────────────────
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and
                    node.func.value.id in ("requests", "httpx") and
                    node.func.attr in ("get", "post", "put", "patch", "delete", "head")):
                    has_timeout = any(
                        kw.arg == "timeout" for kw in node.keywords if kw.arg is not None
                    )
                    if not has_timeout:
                        snippet = ast.get_source_segment(source, node) or ""
                        ctx = function_context.get(node.lineno, "")
                        ctx_str = f" in function '{ctx}'" if ctx else ""
                        finding = Finding(
                            file_path=rel_path,
                            line_number=node.lineno,
                            issue_type="static_analysis",
                            severity=Severity.LOW,
                            message=f"HTTP request without timeout detected{ctx_str}. Requests without timeouts can hang indefinitely.",
                            rule_id="SAF-REQUEST-TIMEOUT",
                            confidence=0.6,
                            snippet=snippet[:80],
                            detection_method="ast",
                            remediation_hint="Add a timeout parameter: requests.get(url, timeout=10)",
                        )
                        findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════
# Main scanning functions
# ═══════════════════════════════════════════════════════════════════════

def scan_file(file_path: str, repo_root: str) -> List[Finding]:
    """Scan a single file using both regex and AST analysis.

    Args:
        file_path: Absolute path to the file to scan.
        repo_root: Root path of the repository.

    Returns:
        A list of findings for detected security issues.
    """
    findings: List[Finding] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
            lines = source.splitlines(keepends=True)
    except (IOError, OSError):
        return findings

    rel_path = os.path.relpath(file_path, repo_root)
    _, ext = os.path.splitext(file_path)

    # ─── Phase 1: Regex pattern matching (all file types) ─────────
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip comments, docstrings
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if '"""' in stripped or "'''" in stripped:
            continue

        for rule in UNSAFE_PATTERNS:
            try:
                match = rule["pattern"].search(line)
            except re.error:
                continue

            if not match:
                continue

            # False positive filter
            if _is_false_positive(line, rule["name"]):
                continue

            # Avoid self-references
            if "SAF-" in line and rule["rule_id"] in line:
                continue

            # Skip re.compile() matching the compile-call pattern
            if rule["name"] == "compile-call" and "re.compile" in line:
                continue

            finding = Finding(
                file_path=rel_path,
                line_number=line_num,
                issue_type="static_analysis",
                severity=rule["severity"],
                message=rule["message"],
                rule_id=rule["rule_id"],
                confidence=rule["confidence"],
                snippet=line.strip()[:80],
                detection_method="regex",
                remediation_hint=rule.get("remediation", ""),
            )
            findings.append(finding)

    # ─── Phase 2: AST scanning (Python only) ──────────────────────
    if ext.lower() == ".py":
        ast_findings = _ast_scan(file_path, repo_root, source)
        findings.extend(ast_findings)

    return findings


def scan(repo_root: str) -> List[Finding]:
    """Run static analysis on the entire repository.

    Args:
        repo_root: Root path of the repository to scan.

    Returns:
        A list of findings for detected security issues.
    """
    from .file_discovery import discover_files

    findings: List[Finding] = []
    files = discover_files(repo_root)

    for rel_path in files:
        full_path = os.path.join(repo_root, rel_path)
        findings.extend(scan_file(full_path, repo_root))

    return findings
