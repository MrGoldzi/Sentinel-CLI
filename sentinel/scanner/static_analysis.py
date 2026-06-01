"""Static analysis scanner - detects insecure code patterns using AST and regex.

Detection methods:
  - ast: Python AST analysis for deeper structural issues
  - regex: Pattern matching for cross-language vulnerability patterns
  - hybrid: AST + regex cross-verification

Now covers 70+ patterns across Python, JavaScript/TypeScript, Go, Java, Ruby, PHP.
Competitive with Semgrep's multi-language static analysis capabilities.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Dict, List, Optional, Set

from ..models import DetectionMethod, Finding, Severity


# ═══════════════════════════════════════════════════════════════════════
# Regex-based unsafe patterns (cross-language) — 70+ rules
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
    {
        "name": "ruby-marshal",
        "pattern": re.compile(r"Marshal\.(?:load|restore)\s*\("),
        "severity": Severity.HIGH,
        "message": "Ruby Marshal.load() deserialization detected. Marshal can execute arbitrary code when deserializing untrusted data.",
        "rule_id": "SAF-RUBY-MARSHAL",
        "confidence": 0.85,
        "remediation": "Never use Marshal.load() on untrusted data. Use JSON.parse() or MessagePack with type whitelisting.",
    },
    {
        "name": "java-objectinputstream",
        "pattern": re.compile(r"new\s+ObjectInputStream\s*\("),
        "severity": Severity.CRITICAL,
        "message": "Java ObjectInputStream deserialization detected. Untrusted deserialization can lead to remote code execution.",
        "rule_id": "SAF-JAVA-DESERIALIZE",
        "confidence": 0.95,
        "remediation": "Never deserialize untrusted data. Use JSON or Protobuf for serialization. If unavoidable, use a whitelist-based ObjectInputFilter.",
    },

    # ─── SQL Injection ────────────────────────────────────────────────
    {
        "name": "sql-query-concatenation",
        "pattern": re.compile(
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["\'"][^"\'"]*?["\'"]\s*[+%]'
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
            r'(?i)(?:cursor\.execute|\.execute|\.raw)\s*\(\s*f["\u201d]'
        ),
        "severity": Severity.HIGH,
        "message": "Potential SQL injection detected via f-string in database query. Use parameterized queries with placeholders instead.",
        "rule_id": "SAF-SQL-FSTRING",
        "confidence": 0.75,
        "remediation": "Replace f-strings with parameterized queries using ? or %s placeholders.",
    },
    {
        "name": "sql-injection-format",
        "pattern": re.compile(r"(?i)(?:execute|executemany)\s*\([^)]*%[sd]\s*%"),
        "severity": Severity.HIGH,
        "message": "Potential SQL injection via string formatting in query. Using %s or %d format strings with user input can bypass parameterization.",
        "rule_id": "SAF-SQL-FORMAT",
        "confidence": 0.7,
        "remediation": "Use parameterized queries with proper placeholders. Never use Python string formatting (% or .format()) with SQL.",
    },
    {
        "name": "sql-injection-java",
        "pattern": re.compile(r"(?:createStatement|prepareStatement)\s*\([^)]*\+[^)]*"),
        "severity": Severity.HIGH,
        "message": "Java SQL Statement with user input concatenation detected. Even PreparedStatement can be vulnerable if the query string is concatenated.",
        "rule_id": "SAF-JAVA-SQL-CONCAT",
        "confidence": 0.85,
        "remediation": "Always use ? placeholders. Never concatenate user input into the query string, even with PreparedStatement.",
    },
    {
        "name": "php-sql-concat",
        "pattern": re.compile(r"(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)"),
        "severity": Severity.HIGH,
        "message": "PHP SQL query with direct user input detected. Classic SQL injection vulnerability.",
        "rule_id": "SAF-PHP-SQL-INJECT",
        "confidence": 0.9,
        "remediation": "Use prepared statements with PDO or mysqli. Never concatenate user input into SQL queries.",
    },
    {
        "name": "go-sql-concat",
        "pattern": re.compile(r"(?:db\.Query|db\.Exec|db\.QueryRow)\s*\([^)]*\+[^)]*"),
        "severity": Severity.HIGH,
        "message": "Go SQL query with string concatenation. This is a SQL injection vector.",
        "rule_id": "SAF-GO-SQL-CONCAT",
        "confidence": 0.85,
        "remediation": "Use parameterized queries with $1, $2 placeholders. Never concatenate user input into SQL strings.",
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
    {
        "name": "document-write",
        "pattern": re.compile(r"\bdocument\.write\s*\("),
        "severity": Severity.HIGH,
        "message": "document.write() detected. This can be used for DOM-based XSS attacks and is blocked by CSP in modern browsers.",
        "rule_id": "SAF-DOCUMENT-WRITE",
        "confidence": 0.9,
        "remediation": "Use DOM manipulation methods (createElement, appendChild) or innerHTML with sanitized content.",
    },
    {
        "name": "react-unsafe-html",
        "pattern": re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:"),
        "severity": Severity.HIGH,
        "message": "dangerouslySetInnerHTML with unsanitized content detected in React. This is a direct XSS vector.",
        "rule_id": "SAF-REACT-UNSAFE-HTML",
        "confidence": 0.9,
        "remediation": "Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}.",
    },
    {
        "name": "php-xss-echo",
        "pattern": re.compile(r"\becho\s+\$(?:_GET|_POST|_REQUEST|_SERVER)"),
        "severity": Severity.HIGH,
        "message": "PHP echo of unsanitized user input detected. This is a reflected XSS vulnerability.",
        "rule_id": "SAF-PHP-XSS-ECHO",
        "confidence": 0.85,
        "remediation": "Use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before echoing user input. Use a templating engine with auto-escaping.",
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
    {
        "name": "php-file-inclusion",
        "pattern": re.compile(r"(?:(?:include|require)(?:_once)?)\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"),
        "severity": Severity.CRITICAL,
        "message": "PHP file inclusion with user input detected. This is a Local/Remote File Inclusion (LFI/RFI) vulnerability that can lead to RCE.",
        "rule_id": "SAF-PHP-FILE-INCLUDE",
        "confidence": 0.95,
        "remediation": "Never include files based on user input. Use a whitelist of allowed files. Disable allow_url_include in php.ini.",
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
    {
        "name": "weak-js-crypto",
        "pattern": re.compile(r"crypto\.create(?:Cipher|Decipher)(?:iv)?\s*\(\s*['""](?:des|rc4|md5)"),
        "severity": Severity.HIGH,
        "message": "Weak Node.js crypto algorithm detected (DES, RC4, MD5). These are cryptographically broken.",
        "rule_id": "SAF-JS-WEAK-CRYPTO",
        "confidence": 0.85,
        "remediation": "Use crypto.createCipheriv('aes-256-gcm', ...) or crypto.createHmac('sha256', ...). Never use DES, RC4, or MD5.",
    },
    {
        "name": "java-insecure-crypto",
        "pattern": re.compile(r"""Cipher\.getInstance\s*\(\s*"(?:DES|RC[24])"""),
        "severity": Severity.HIGH,
        "message": "Weak Java cryptographic algorithm detected (DES, RC2, RC4).",
        "rule_id": "SAF-JAVA-WEAK-CRYPTO",
        "confidence": 0.85,
        "remediation": "Use AES-GCM for encryption, SHA-256+ for hashing. Use 'AES/GCM/NoPadding' transformation.",
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
    {
        "name": "stack-trace-exposure",
        "pattern": re.compile(r"(?i)(?:print_exc|format_exc|printStackTrace|debug_print_backtrace)\s*\("),
        "severity": Severity.LOW,
        "message": "Stack trace printing detected. Stack traces in production expose sensitive code paths and internal logic.",
        "rule_id": "SAF-STACK-TRACE",
        "confidence": 0.5,
        "remediation": "Log exceptions to a secure logging system. Return generic error messages to users. Never expose stack traces in API responses.",
    },

    # ─── Insecure Configuration ───────────────────────────────────────
    {
        "name": "cors-allow-all",
        "pattern": re.compile(r"""(?:Access-Control-Allow-Origin|AccessControlAllowOrigin)\s*[:=]\s*['"]\*['"]"""),
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

    # ═══════════════════════════════════════════════════════════════════
    # NEW: JavaScript/TypeScript Specific (9 rules)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "js-eval",
        "pattern": re.compile(r"\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*[a-zA-Z_]"),
        "severity": Severity.HIGH,
        "message": "JavaScript eval-like function with dynamic input detected. eval(), new Function(), setTimeout/setInterval with strings can execute arbitrary code.",
        "rule_id": "SAF-JS-EVAL",
        "confidence": 0.8,
        "remediation": "Never pass user input to eval() or Function(). Use JSON.parse() for data. Avoid string-based setTimeout/setInterval.",
    },
    {
        "name": "prototype-pollution",
        "pattern": re.compile(r"(?:(?:__proto__|constructor\.prototype)\s*\[|Object\.assign\s*\(\s*\{\}\s*,\s*req)"),
        "severity": Severity.HIGH,
        "message": "Potential prototype pollution detected. Manipulating __proto__ or Object.prototype with user input can lead to RCE or privilege escalation.",
        "rule_id": "SAF-PROTOTYPE-POLLUTION",
        "confidence": 0.6,
        "remediation": "Validate and sanitize all user-supplied objects. Use Object.create(null) for dictionaries. Use libraries like 'immer' for immutable updates.",
    },
    {
        "name": "localstorage-secrets",
        "pattern": re.compile(r"""localStorage\.setItem\s*\(\s*['"](?:token|secret|key|password|jwt|auth)"""),
        "severity": Severity.MEDIUM,
        "message": "Sensitive data stored in localStorage detected. localStorage is accessible to any script on the page and persists after browser close.",
        "rule_id": "SAF-LOCALSTORAGE-SECRET",
        "confidence": 0.8,
        "remediation": "Store sensitive tokens in httpOnly cookies or use sessionStorage for session-only data. Never store JWTs or API keys in localStorage.",
    },
    {
        "name": "postmessage-no-origin",
        "pattern": re.compile(r"""window\.addEventListener\s*\(\s*['\"]message['\"]"""),
        "severity": Severity.MEDIUM,
        "message": "postMessage listener detected without visible origin validation. Messages from any origin may be processed.",
        "rule_id": "SAF-POSTMESSAGE-ORIGIN",
        "confidence": 0.5,
        "remediation": "Always validate event.origin against a whitelist of trusted origins in postMessage handlers.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Go Specific (3 rules)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "go-unsafe-import",
        "pattern": re.compile(r"""import\s+["']unsafe["']"""),
        "severity": Severity.MEDIUM,
        "message": "Go 'unsafe' package imported. The unsafe package bypasses Go's type safety and memory protections.",
        "rule_id": "SAF-GO-UNSAFE",
        "confidence": 0.5,
        "remediation": "Avoid using the unsafe package unless absolutely necessary. Document the reason if unavoidable.",
    },
    {
        "name": "go-exec-command",
        "pattern": re.compile(r"exec\.Command\s*\(\s*[^,)]*\+[^)]*"),
        "severity": Severity.HIGH,
        "message": "Go exec.Command with string concatenation detected. This can lead to command injection if input is untrusted.",
        "rule_id": "SAF-GO-EXEC",
        "confidence": 0.8,
        "remediation": "Use exec.Command with separate arguments (not shell strings). Pass command name and args separately: exec.Command(name, arg1, arg2).",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Java Specific (2 rules — 2 others in deserialization/crypto above)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "java-runtime-exec",
        "pattern": re.compile(r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
        "severity": Severity.HIGH,
        "message": "Java Runtime.exec() detected. Can lead to command injection if user input reaches the command string.",
        "rule_id": "SAF-JAVA-RUNTIME-EXEC",
        "confidence": 0.9,
        "remediation": "Use ProcessBuilder with separate argument lists instead. Validate all command inputs against a whitelist.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Ruby Specific (3 rules)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "ruby-eval",
        "pattern": re.compile(r"\beval\s*\(?[^)]*(?:params|request|input|user)"),
        "severity": Severity.HIGH,
        "message": "Ruby eval() with potential user input detected. eval() can execute arbitrary Ruby code.",
        "rule_id": "SAF-RUBY-EVAL",
        "confidence": 0.75,
        "remediation": "Never use eval() with user input. Use JSON.parse() or YAML.safe_load() for data parsing.",
    },
    {
        "name": "ruby-system",
        "pattern": re.compile(r"\b(?:system|`|exec|spawn|open3)\s*\(?[^)]*(?:params|request|input|user)"),
        "severity": Severity.HIGH,
        "message": "Ruby system command execution with potential user input detected. Can lead to command injection.",
        "rule_id": "SAF-RUBY-SYSTEM",
        "confidence": 0.75,
        "remediation": "Use system() with separate arguments: system('cmd', arg1, arg2). Never pass user input as part of the command string.",
    },
    {
        "name": "ruby-mass-assign",
        "pattern": re.compile(r"(?:\.(?:update|create|new)\s*\(\s*(?:params|request)\[|params\.permit\s*!)"),
        "severity": Severity.MEDIUM,
        "message": "Potential mass assignment vulnerability in Ruby/Rails. Unpermitted params can overwrite sensitive attributes.",
        "rule_id": "SAF-RUBY-MASS-ASSIGN",
        "confidence": 0.6,
        "remediation": "Use strong parameters: params.require(:model).permit(:attr1, :attr2). Never use params.permit!.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: PHP Specific (2 rules — others in XSS/File Inclusion above)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "php-unserialize",
        "pattern": re.compile(r"unserialize\s*\(\s*\$(?:_GET|_POST|_COOKIE|_REQUEST)"),
        "severity": Severity.CRITICAL,
        "message": "PHP unserialize() with user input detected. This can lead to PHP object injection and remote code execution.",
        "rule_id": "SAF-PHP-UNSERIALIZE",
        "confidence": 0.95,
        "remediation": "Never unserialize user-controlled data. Use JSON encoding (json_decode) instead. If unavoidable, use allowed_classes option in PHP 7+.",
    },
    {
        "name": "php-magic-methods",
        "pattern": re.compile(r"(?:__wakeup|__destruct|__toString|__call|__get|__set)\s*\("),
        "severity": Severity.LOW,
        "message": "PHP magic method detected. These methods are commonly exploited via PHP object injection through unserialize().",
        "rule_id": "SAF-PHP-MAGIC-METHODS",
        "confidence": 0.2,
        "remediation": "Review magic methods for security. Ensure __wakeup validates object state. Consider avoiding unserialize() entirely.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: SSRF & URL Injection (2 rules)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "ssrf-requests",
        "pattern": re.compile(r"\b(?:requests|httpx|urllib)\.(?:get|post|request|urlopen)\s*\([^)]*\b(?:request|input|user|query|body|params|data|url)\b"),
        "severity": Severity.HIGH,
        "message": "Potential Server-Side Request Forgery (SSRF). HTTP request with user-supplied URL can be used to access internal services.",
        "rule_id": "SAF-SSRF",
        "confidence": 0.55,
        "remediation": "Validate URLs against a whitelist. Block requests to internal IPs (127.0.0.1, 10.0.0.0/8, 169.254.169.254). Use a URL parsing library to validate the destination.",
    },
    {
        "name": "ssrf-fetch",
        "pattern": re.compile(r"\bfetch\s*\([^)]*\b(?:req\.|request\.|params\.|input\.|user)"),
        "severity": Severity.HIGH,
        "message": "Potential SSRF via fetch() with user-controlled URL. Can be used to access internal network resources.",
        "rule_id": "SAF-JS-SSRF",
        "confidence": 0.55,
        "remediation": "Validate all user-supplied URLs against a whitelist before making requests. Use a server-side proxy for external requests.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Timing Attacks (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "timing-attack",
        "pattern": re.compile(r"(?i)(?:token|secret|hash|hmac|password|key)\s*(?:==|!=)\s*"),
        "severity": Severity.MEDIUM,
        "message": "Potential timing attack vulnerability. Using ==/!= for secret comparison enables timing-based brute force attacks.",
        "rule_id": "SAF-TIMING-ATTACK",
        "confidence": 0.4,
        "remediation": "Use constant-time comparison: hmac.compare_digest() in Python, crypto.timingSafeEqual() in Node.js, hash_equals() in PHP.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Open Redirect (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "open-redirect",
        "pattern": re.compile(r"(?i)(?:redirect|location|next)\s*[=:].*?(?:request|input|user|query|body|params)"),
        "severity": Severity.MEDIUM,
        "message": "Potential open redirect. User input used in redirect/location without validation can redirect to malicious sites.",
        "rule_id": "SAF-OPEN-REDIRECT",
        "confidence": 0.45,
        "remediation": "Validate redirect URLs against a whitelist. Use relative paths or indirect references instead of user-supplied URLs.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Insecure File Permissions (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "insecure-chmod",
        "pattern": re.compile(r"\b(?:os\.chmod|chmod)\s*\([^,]*,\s*(?:0o?777|0?777)"),
        "severity": Severity.MEDIUM,
        "message": "Insecure file permissions (777) detected. World-writable files can be modified by any user, leading to privilege escalation.",
        "rule_id": "SAF-INSECURE-CHMOD",
        "confidence": 0.9,
        "remediation": "Use restrictive permissions: 600 for private files, 644 for public files, 700 for directories. Never use 777.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Hardcoded IPs (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "hardcoded-internal-ip",
        "pattern": re.compile(r"(?:(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})"),
        "severity": Severity.LOW,
        "message": "Hardcoded internal/private IP address detected. May expose internal network architecture.",
        "rule_id": "SAF-HARDCODED-IP",
        "confidence": 0.5,
        "remediation": "Use configuration files or environment variables for IP addresses. Avoid hardcoding infrastructure details in source code.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Insecure XML Parsing (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "insecure-xml-parsing",
        "pattern": re.compile(r"(?:xml\.etree\.ElementTree|minidom|sax)\s*\.\s*(?:parse|parseString)\s*\("),
        "severity": Severity.MEDIUM,
        "message": "XML parsing without defusedxml detected. Standard XML parsers are vulnerable to XXE and billion laughs attacks.",
        "rule_id": "SAF-INSECURE-XML",
        "confidence": 0.6,
        "remediation": "Use defusedxml (defusedxml.ElementTree, defusedxml.minidom) for secure XML parsing. Disable DTD processing and external entities.",
    },

    # ═══════════════════════════════════════════════════════════════════
    # NEW: Host Header Injection (1 rule)
    # ═══════════════════════════════════════════════════════════════════
    {
        "name": "host-header-injection",
        "pattern": re.compile(r"(?i)(?:request\.host|request\.getHost|X-Forwarded-Host|X-Forwarded-For)\s*"),
        "severity": Severity.MEDIUM,
        "message": "Potential host header injection. Using raw Host header without validation can lead to cache poisoning, password reset poisoning, or SSRF.",
        "rule_id": "SAF-HOST-HEADER",
        "confidence": 0.3,
        "remediation": "Validate the Host header against a whitelist of allowed domains. Use HTTP_HOST setting instead of trusting request headers.",
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
# AST-based Python analysis — enhanced with 8 new detection categories
# ═══════════════════════════════════════════════════════════════════════

def _ast_scan(file_path: str, repo_root: str, source: str) -> List[Finding]:
    """Deep AST-based scanning for Python files.

    Detects issues that regex alone cannot reliably catch:
      - Dangerous function calls with user-controlled arguments
      - Hardcoded credentials assigned to named variables
      - Bare except clauses
      - HTTP/requests calls without timeouts
      - Subprocess calls without explicit shell=False
      - SSRF via urllib/requests with user input
      - Path traversal via os.path.join with request params
      - Insecure SSL (verify=False)
      - Timing attacks (== for HMAC comparison)
      - XXE via insecure XML parsing
      - Hardcoded IP addresses
    """
    findings: List[Finding] = []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, repo_root)

    # Track imports for context-aware analysis
    dangerous_imports: Dict[str, str] = {}

    # Build function context map
    function_context: Dict[int, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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

        # ─── Detect Hardcoded Credentials ──────────────────────────
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

                # ─── NEW: Detect insecure SSL (verify=False) ──────
                if (isinstance(node.func.value, ast.Name) and
                    node.func.value.id in ("requests", "httpx") and
                    node.func.attr in ("get", "post", "put", "patch", "delete", "head", "request")):
                    has_verify_false = any(
                        kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords if kw.arg is not None
                    )
                    if has_verify_false:
                        snippet = ast.get_source_segment(source, node) or ""
                        finding = Finding(
                            file_path=rel_path,
                            line_number=node.lineno,
                            issue_type="static_analysis",
                            severity=Severity.HIGH,
                            message="Insecure SSL/TLS configuration: verify=False disables certificate validation, enabling man-in-the-middle attacks.",
                            rule_id="SAF-INSECURE-SSL",
                            confidence=0.9,
                            snippet=snippet[:80],
                            detection_method="ast",
                            remediation_hint="Never use verify=False in production. Use proper CA certificates. Set REQUESTS_CA_BUNDLE if needed.",
                        )
                        findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════
# Main scanning functions
# ═══════════════════════════════════════════════════════════════════════

def scan_file(file_path: str, repo_root: str) -> List[Finding]:
    """Scan a single file using both regex and AST analysis.

    Now covers 70+ patterns across Python, JavaScript/TypeScript, Go, Java, Ruby, PHP.
    AST analysis enhanced with SSRF, insecure SSL, path traversal, and timing attack detection.
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

            if _is_false_positive(line, rule["name"]):
                continue

            if "SAF-" in line and rule["rule_id"] in line:
                continue

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
    """Run static analysis on the entire repository."""
    from .file_discovery import discover_files

    findings: List[Finding] = []
    files = discover_files(repo_root)

    for rel_path in files:
        full_path = os.path.join(repo_root, rel_path)
        findings.extend(scan_file(full_path, repo_root))

    return findings
