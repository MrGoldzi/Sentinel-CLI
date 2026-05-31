#!/usr/bin/env python3
"""
Vulnerable Test HTTP Server for Sentinel DAST Scanner

This server intentionally includes security vulnerabilities and misconfigurations
designed to trigger findings across all 21 phases of Sentinel's DAST scanner.

WARNING: This server is intentionally vulnerable. DO NOT expose it to untrusted
networks or the public internet. It is intended for local testing only.

Usage:
    python test_servers/vulnerable_server.py [--port PORT]
    
Then scan with:
    python cli.py dast http://localhost:8080
"""

from __future__ import annotations

import argparse
import base64
import datetime
import http.server
import json
import os
import re
import socketserver
import sys
import urllib.parse
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════

# Server version string exposed via Server header
SERVER_SOFTWARE = "TestVulnerableServer/1.0 (Debian; Python)"

# JWT token with no expiry and symmetric alg (for JWT misconfiguration testing)
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
# No "exp" claim intentionally
TOKEN_NO_EXPIRY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# JWT token with alg: none (unsigned)
TOKEN_ALG_NONE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
)

# JWT token with expiry 30 days out (long-lived)
exp_future = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).timestamp())
TOKEN_LONG_LIVED_PAYLOAD = base64.urlsafe_b64encode(
    json.dumps({"sub": "user123", "name": "Test User", "exp": exp_future}).encode()
).rstrip(b"=").decode()
TOKEN_LONG_LIVED_HEADER = base64.urlsafe_b64encode(
    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
).rstrip(b"=").decode()
TOKEN_LONG_LIVED = f"{TOKEN_LONG_LIVED_HEADER}.{TOKEN_LONG_LIVED_PAYLOAD}.signature"

# Fake user data for IDOR testing
FAKE_USERS = {
    1: {"email": "admin@example.com", "role": "admin", "phone": "555-0100"},
    2: {"email": "user@example.com", "role": "user", "phone": "555-0101"},
}

# Flag to track authentication requests for user enumeration
login_attempts: List[str] = []


class VulnerableRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that serves intentionally vulnerable responses."""

    # Disable logging of DNS lookups for speed
    def address_string(self) -> str:
        return self.client_address[0]

    # ─── Helper Methods ─────────────────────────────────────────────

    def _send_json(self, data: dict, status: int = 200) -> None:
        """Send a JSON response."""
        body = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(body.encode())

    def _send_html(self, html: str, status: int = 200) -> None:
        """Send an HTML response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_text(self, text: str, status: int = 200) -> None:
        """Send a plain text response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(text.encode())

    def _send_xml(self, xml: str, status: int = 200) -> None:
        """Send an XML response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(xml.encode())

    def _send_vulnerable_headers(self) -> None:
        """Intentionally vulnerable headers — minimal security headers."""
        # NOTE: Most security headers are MISSING to trigger findings.
        # We only send the ones that should be present for specific tests.

        # Server info disclosure (Phase 6)
        self.send_header("Server", SERVER_SOFTWARE)
        self.send_header("X-Powered-By", "Express")  # Fake tech stack disclosure

        # Set-Cookie without Secure/HttpOnly/SameSite (Phase 3)
        self.send_header("Set-Cookie", "session_id=abc123; Path=/")

    def _get_query_params(self) -> Dict[str, str]:
        """Parse query parameters from the request path."""
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    # ─── Route Handler ──────────────────────────────────────────────

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = self._get_query_params()

        # Route table — maps paths to handlers
        routes: Dict[str, object] = {
            # Phase 9: SSTI detection
            "/": self._handle_root,
            # Phase 5: HTTPS check + Phase 2: headers (handled by default)
            "/health": self._handle_health,
            # Phase 3: Cookie security
            "/set-cookie": self._handle_cookie_test,
            # Phase 4: CORS misconfiguration (Phase 4)
            "/cors": self._handle_cors,
            # Phase 6: Debug mode indicator
            "/debug": self._handle_debug,
            # Phase 7/8: Injection & XSS reflection (via q parameter)
            # The base `/` handler echoes back q= for reflection
            # Additional reflection endpoint
            "/search": self._handle_reflection,
            # Phase 9: SSTI
            "/ssti": self._handle_ssti,
            # Phase 10: Sensitive endpoints
            "/admin": self._handle_admin,
            "/login": self._handle_login_get,
            "/signin": self._handle_login_get,
            "/config": self._handle_config,
            "/.env": self._handle_env,
            "/.git/config": self._handle_git_config,
            "/backup": self._handle_backup,
            "/robots.txt": self._handle_robots,
            "/sitemap.xml": self._handle_sitemap,
            "/phpinfo.php": self._handle_phpinfo,
            "/actuator": self._handle_actuator,
            "/swagger": self._handle_swagger,
            "/api/docs": self._handle_swagger,
            "/api/health": self._handle_health,
            "/healthcheck": self._handle_health,
            # Phase 11: Verbose errors
            "/error-test": self._handle_verbose_error,
            "/%00": self._handle_null_byte,
            # Phase 12: Directory listing
            "/uploads": self._handle_directory_listing,
            "/assets": self._handle_directory_listing,
            "/files": self._handle_directory_listing,
            # Phase 14: IDOR / Access control
            "/api/users/1": self._handle_idor,
            "/api/users/2": self._handle_idor,
            "/api/profile/1": self._handle_idor,
            "/api/account/1": self._handle_idor,
            "/user/1": self._handle_idor,
            "/profile/1": self._handle_idor,
            "/account/1": self._handle_idor,
            # Phase 15: Open redirect
            "/redirect": self._handle_open_redirect,
            # Phase 16: ReDoS
            "/regex-test": self._handle_redos_probe,
            # Phase 17: XXE (XML endpoint)
            "/api": self._handle_xml_endpoint,
            "/soap": self._handle_xml_endpoint,
            "/xml": self._handle_xml_endpoint,
            # Phase 18: JWT
            "/jwt": self._handle_jwt,
            # Phase 21: SSRF indicators
            "/proxy": self._handle_ssrf_indicator,
            "/fetch-url": self._handle_ssrf_indicator,
            "/webhook": self._handle_ssrf_indicator,
        }

        handler = routes.get(path, self._handle_not_found)
        handler()  # type: ignore[operator]

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = self._get_query_params()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if path == "/login":
            self._handle_login_post(body)
        elif path in ("/api", "/soap", "/xml", "/ws", "/xmlrpc", "/rpc", "/service"):
            content_type = self.headers.get("Content-Type", "").lower()
            if "xml" in content_type:
                self._handle_xml_post(body)
            else:
                self._handle_not_found()
        else:
            self._handle_not_found()

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Root — serves HTML that reflects query params
    # ═══════════════════════════════════════════════════════════════

    def _handle_root(self) -> None:
        """Root page — reflects query params for injection/XSS detection.
        
        Also includes debug mode indicator text and SSRF-like patterns.
        """
        params = self._get_query_params()
        q = params.get("q", "")
        name = params.get("name", "")

        # Debug mode indicator (Phase 6)
        debug_badge = "<!-- APP_DEBUG=true -->"

        # SSRF indicator patterns (Phase 21)
        ssrf_indicator = (
            '<!-- The application fetches URLs from user input --> '
            '<form action="/proxy"><input name="url" type="text"></form>'
        )

        reflected = ""
        if q:
            # Intentionally reflect unsanitized for injection detection
            reflected = f"<p>You searched for: {q}</p>"
        if name:
            reflected += f"<p>Hello, {name}!</p>"

        html = f"""<!DOCTYPE html>
<html><head><title>Vulnerable Test App</title></head><body>
{debug_badge}
<h1>Welcome to the Vulnerable Test Application</h1>
{ssrf_indicator}
{reflected}
<form method="get" action="/">
    <input type="text" name="q" placeholder="Search...">
    <input type="submit">
</form>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: Cookie security — sets cookies without flags
    # ═══════════════════════════════════════════════════════════════

    def _handle_cookie_test(self) -> None:
        """Sets cookies intentionally missing Secure/HttpOnly/SameSite."""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self._send_vulnerable_headers()
        # Additional cookies without security flags
        self.send_header("Set-Cookie", "auth_token=eyJhbGciOiJIUzI1NiJ9.test; Path=/")
        self.send_header("Set-Cookie", "user_prefs=theme=dark; Path=/")
        self.end_headers()
        self.wfile.write(b"Cookies set (insecurely)")

    # ═══════════════════════════════════════════════════════════════
    # Phase 4: CORS misconfiguration
    # ═══════════════════════════════════════════════════════════════

    def _handle_cors(self) -> None:
        """Returns CORS headers allowing all origins."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    # ═══════════════════════════════════════════════════════════════
    # Phase 6: Debug mode indicator
    # ═══════════════════════════════════════════════════════════════

    def _handle_debug(self) -> None:
        """Returns a page with debug mode indicators."""
        html = """<!DOCTYPE html>
<html><head><title>Debug Console</title></head><body>
<h1>Debug Console</h1>
<div class="debug-toolbar">
    <p>Django Debug Toolbar v3.2</p>
    <p>DEBUG=True</p>
    <p>SQL queries: 42</p>
    <pre>
        SELECT * FROM users WHERE id = 1;
        SELECT * FROM accounts WHERE user_id = 1;
    </pre>
</div>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 7/8: Injection & XSS reflection
    # ═══════════════════════════════════════════════════════════════

    def _handle_reflection(self) -> None:
        """Reflects query parameter 'q' for injection/XSS detection."""
        params = self._get_query_params()
        q = params.get("q", "")
        html = f"""<!DOCTYPE html>
<html><head><title>Search Results</title></head><body>
<h1>Search Results for: {q}</h1>
<p>Your query was: {q}</p>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 9: SSTI
    # ═══════════════════════════════════════════════════════════════

    def _handle_ssti(self) -> None:
        """Checks for SSTI probes and returns calculated results."""
        params = self._get_query_params()
        name = params.get("name", "")

        # If {{7*7}} was sent, evaluate and return 49
        if "{{7*7}}" in name or "${7*7}" in name or "<%= 7*7 %>" in name:
            name = name.replace("{{7*7}}", "49")
            name = name.replace("${7*7}", "49")
            name = name.replace("<%= 7*7 %>", "49")

        html = f"""<!DOCTYPE html>
<html><head><title>SSTI Test</title></head><body>
<h1>Hello, {name}!</h1>
<p>Welcome to our template engine.</p>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 10: Sensitive endpoints
    # ═══════════════════════════════════════════════════════════════

    def _handle_admin(self) -> None:
        """Exposed admin panel."""
        html = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head><body>
<h1>Administrator Dashboard</h1>
<ul>
    <li><a href="/admin/users">User Management</a></li>
    <li><a href="/admin/config">System Configuration</a></li>
    <li><a href="/admin/logs">System Logs</a></li>
</ul>
</body></html>"""
        self._send_html(html)

    def _handle_login_get(self) -> None:
        """Login form — used by auth checks (Phase 13)."""
        html = """<!DOCTYPE html>
<html><head><title>Login</title></head><body>
<h1>Sign In</h1>
<form method="post" action="/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <input type="submit" value="Login">
</form>
</body></html>"""
        self._send_html(html)

    def _handle_login_post(self, body: str) -> None:
        """Process login — varies response for user enumeration detection."""
        params = dict(urllib.parse.parse_qsl(body))
        username = params.get("username", "")
        global login_attempts
        login_attempts.append(username)

        # Vary response based on username
        if username == "admin":
            # Valid username — different response than invalid
            self._send_json({
                "error": "Invalid password",
                "username": username,
            }, status=401)
        else:
            # Generic error for unknown users
            self._send_json({
                "error": "Invalid username or password",
            }, status=401)

    def _handle_config(self) -> None:
        """Exposed configuration file."""
        config = """# Application Configuration
DATABASE_URL=postgresql://admin:SuperSecret123@db.internal:5432/production
SECRET_KEY=sk-prod-abc123def456ghi789
API_KEY=AIzaSyDummyKeyForTesting123456789
REDIS_URL=redis://:password@redis.internal:6379/0
MAIL_PASSWORD=smtp_secret_pass_2024
"""
        self._send_text(config)

    def _handle_env(self) -> None:
        """Exposed .env file with secrets."""
        env = """# Environment Configuration
DEBUG=True
DATABASE_URL=mysql://SENTINEL_TEST_USER:SENTINEL_TEST_PASS@localhost:3306/SENTINEL_TEST_DB
SECRET_KEY=SENTINEL_TEST_SECRET_KEY_PLACEHOLDER
AWS_ACCESS_KEY_ID=SENTINEL_TEST_AWS_KEY_PLACEHOLDER
AWS_SECRET_ACCESS_KEY=SENTINEL_TEST_AWS_SECRET_PLACEHOLDER
STRIPE_SECRET_KEY=SENTINEL_TEST_STRIPE_KEY_PLACEHOLDER
JWT_SECRET=SENTINEL_TEST_JWT_SECRET_PLACEHOLDER
"""
        self._send_text(env)

    def _handle_git_config(self) -> None:
        """Exposed .git/config file."""
        git_config = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/org/production-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""
        self._send_text(git_config)

    def _handle_backup(self) -> None:
        """Exposed backup file."""
        self._send_text("Backup created: 2024-01-15\nDatabase dump: 2.3GB\n")

    def _handle_robots(self) -> None:
        """robots.txt — standard file."""
        self._send_text("User-agent: *\nDisallow: /admin\nDisallow: /config\n")

    def _handle_sitemap(self) -> None:
        """Sitemap XML."""
        self._send_xml(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            '  <url><loc>http://localhost/</loc></url>\n'
            '</urlset>'
        )

    def _handle_phpinfo(self) -> None:
        """Fake phpinfo output."""
        html = """<!DOCTYPE html>
<html><head><title>phpinfo()</title></head><body>
<div class="center">
    <h1>PHP Version 8.1.20</h1>
    <table>
        <tr><td>PHP License</td><td>PHP License v3.01</td></tr>
        <tr><td>System</td><td>Linux server 6.2.0</td></tr>
        <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    </table>
</div>
</body></html>"""
        self._send_html(html)

    def _handle_actuator(self) -> None:
        """Spring Actuator endpoint."""
        data = {
            "_links": {
                "self": {"href": "/actuator", "templated": False},
                "health": {"href": "/actuator/health", "templated": False},
                "env": {"href": "/actuator/env", "templated": False},
                "beans": {"href": "/actuator/beans", "templated": False},
                "dump": {"href": "/actuator/dump", "templated": False},
            }
        }
        self._send_json(data)

    def _handle_swagger(self) -> None:
        """Exposed API documentation."""
        html = """<!DOCTYPE html>
<html><head><title>Swagger UI</title></head><body>
<h1>API Documentation</h1>
<div id="swagger-ui">
    <pre>{"openapi":"3.0.0","info":{"title":"Internal API","version":"1.0"}}</pre>
</div>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 11: Verbose errors
    # ═══════════════════════════════════════════════════════════════

    def _handle_verbose_error(self) -> None:
        """Returns a verbose error with stack trace."""
        error = """Traceback (most recent call last):
  File "/usr/lib/app/app.py", line 42, in process_request
    result = database.query("SELECT * FROM users WHERE id = " + user_input)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/app/database.py", line 155, in query
    cursor.execute(sql_query)
  File "/usr/lib/python3.10/site-packages/django/db/backends/utils.py", line 84, in execute
    return self.cursor.execute(sql, params)
  File "/usr/lib/python3.10/site-packages/django/db/backends/utils.py", line 82, in _execute
django.db.utils.OperationalError: near "1": syntax error
"""
        self._send_text(error, status=500)

    def _handle_null_byte(self) -> None:
        """Returns stack trace for null byte injection attempts."""
        error = """Traceback (most recent call last):
  File "/var/www/html/index.php", line 15, in require
    include($_GET['page'] . '.php')
  File "/var/www/html/config.php", line 3:
    Warning: include(/etc/passwd): failed to open stream: Permission denied
"""
        self._send_text(error, status=500)

    # ═══════════════════════════════════════════════════════════════
    # Phase 12: Directory listing
    # ═══════════════════════════════════════════════════════════════

    def _handle_directory_listing(self) -> None:
        """Returns a directory listing page."""
        path_part = urllib.parse.urlparse(self.path).path.strip("/")
        html = f"""<!DOCTYPE html>
<html><head><title>Index of /{path_part}</title></head><body>
<h1>Index of /{path_part}</h1>
<pre>
<img src="/icons/blank.gif" alt="Icon ">
<a href="../">Parent Directory</a>
<img src="/icons/folder.gif" alt="[DIR]"> <a href="images/">images/</a>    2024-01-15 10:30
<img src="/icons/folder.gif" alt="[DIR]"> <a href="css/">css/</a>        2024-01-15 10:25
<img src="/icons/folder.gif" alt="[DIR]"> <a href="js/">js/</a>          2024-01-15 10:20
<img src="/icons/text.gif" alt="[TXT]"> <a href="index.html">index.html</a>  2024-01-15 10:00  12K
<img src="/icons/lock.gif" alt="[TXT]"> <a href="secret.txt">secret.txt</a>   2024-01-15 09:00   2K
</pre>
<address>Apache/2.4.57 (Debian) Server at localhost Port 8080</address>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Phase 14: Access Control / IDOR
    # ═══════════════════════════════════════════════════════════════

    def _handle_idor(self) -> None:
        """Returns user data without authentication (IDOR vulnerability)."""
        # Extract user ID from the path
        match = re.search(r"/api/users/(\d+)", self.path)
        if match:
            user_id = int(match.group(1))
        else:
            # Return generic user data
            user_id = 1

        user = FAKE_USERS.get(user_id, FAKE_USERS[1])
        self._send_json(user)

    # ═══════════════════════════════════════════════════════════════
    # Phase 15: Open redirect
    # ═══════════════════════════════════════════════════════════════

    def _handle_open_redirect(self) -> None:
        """Redirects to a URL specified in the 'next' parameter."""
        params = self._get_query_params()
        next_url = params.get("next", "/")
        self.send_response(302)
        self.send_header("Location", next_url)
        self.send_header("Content-Type", "text/plain")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(f"Redirecting to {next_url}".encode())

    # ═══════════════════════════════════════════════════════════════
    # Phase 16: ReDoS indicator
    # ═══════════════════════════════════════════════════════════════

    def _handle_redos_probe(self) -> None:
        """Returns regex-related error messages for ReDoS detection."""
        params = self._get_query_params()
        regex = params.get("regex", "")
        pattern = params.get("pattern", "")
        reg = params.get("re", "")

        # Generate an error message based on the regex parameter
        if regex or pattern or reg:
            error_msg = (
                f"re.error: bad character range {regex or pattern or reg} at position 5\n"
                "Stack trace (most recent call last):\n"
                '  File "/usr/lib/python3.10/re.py", line 234, in _compile\n'
                "    return _compile(pattern, flags)\n"
            )
            self._send_text(error_msg, status=400)
        else:
            self._send_text("Send a regex parameter to test", status=400)

    # ═══════════════════════════════════════════════════════════════
    # Phase 17: XML Endpoint / XXE
    # ═══════════════════════════════════════════════════════════════

    def _handle_xml_endpoint(self) -> None:
        """Returns XML content type without explicit XML POST."""
        # Phase 17: XXE potential — Content-Type: application/xml
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<response><status>ok</status></response>'
        self._send_xml(xml)

    def _handle_xml_post(self, body: str) -> None:
        """Accepts XML POST request (XXE test)."""
        xml_response = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<response><status>received</status></response>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self._send_vulnerable_headers()
        self.end_headers()
        self.wfile.write(xml_response.encode())

    # ═══════════════════════════════════════════════════════════════
    # Phase 18: JWT Misconfiguration
    # ═══════════════════════════════════════════════════════════════

    def _handle_jwt(self) -> None:
        """Returns a page with multiple JWT tokens having misconfigurations."""
        html = f"""<!DOCTYPE html>
<html><head><title>JWT Test Page</title></head><body>
<h1>JWT Configuration</h1>
<p>Your access token: <code>{TOKEN_NO_EXPIRY}</code></p>
<pre>
{{
  "alg": "HS256",
  "typ": "JWT",
  "token": "{TOKEN_LONG_LIVED}"
}}
</pre>
<script>
    // Stored JWT token
    var jwtToken = "{TOKEN_ALG_NONE}";
    console.log("Session token:", jwtToken);
</script>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._send_vulnerable_headers()
        # JWT in Authorization header
        self.send_header("Authorization", f"Bearer {TOKEN_NO_EXPIRY}")
        # JWT in a cookie
        self.send_header("Set-Cookie", f"access_token={TOKEN_LONG_LIVED}; Path=/")
        self.end_headers()
        self.wfile.write(html.encode())

    # ═══════════════════════════════════════════════════════════════
    # Phase 21: SSRF Indicators
    # ═══════════════════════════════════════════════════════════════

    def _handle_ssrf_indicator(self) -> None:
        """Returns a page indicating SSRF-capable functionality."""
        html = """<!DOCTYPE html>
<html><head><title>Proxy Service</title></head><body>
<h1>URL Proxy</h1>
<form method="get">
    <label>URL to fetch: <input type="text" name="url" size="50"></label>
    <input type="submit" value="Fetch">
</form>
<p>Enter a URL and we'll fetch it for you.</p>
</body></html>"""
        self._send_html(html)

    # ═══════════════════════════════════════════════════════════════
    # Default: Health check / Not found
    # ═══════════════════════════════════════════════════════════════

    def _handle_health(self) -> None:
        """Simple health check endpoint."""
        self._send_json({"status": "healthy", "version": "1.0"})

    def _handle_not_found(self) -> None:
        """404 handler."""
        self._send_html(
            "<html><body><h1>404 Not Found</h1><p>Resource not found.</p></body></html>",
            status=404,
        )

    # Suppress default request logging for cleaner output
    def log_message(self, format: str, *args: object) -> None:
        if os.environ.get("VERBOSE"):
            super().log_message(format, *args)


# ═══════════════════════════════════════════════════════════════════════
# Server Runner
# ═══════════════════════════════════════════════════════════════════════

def create_server(port: int = 8080) -> socketserver.TCPServer:
    """Create and return the vulnerable test HTTP server."""
    server = socketserver.TCPServer(("", port), VulnerableRequestHandler)
    server.allow_reuse_address = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerable test HTTP server for Sentinel DAST scanner"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show request logs",
    )
    args = parser.parse_args()

    if args.verbose:
        os.environ["VERBOSE"] = "1"

    server = create_server(args.port)
    print(f"🔓 Vulnerable Test Server started at http://localhost:{args.port}")
    print(f"   Scan it with: python cli.py dast http://localhost:{args.port}")
    print(f"   Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
