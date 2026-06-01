<div align="center">

<img src="assets/icon.png" alt="Sentinel Logo" width="278" />


**Local-first, deterministic security scanner for Git repositories and web applications.**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000)](CONTRIBUTING.md#code-style)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)

---

**Scan Git repositories and web applications for secrets, vulnerable dependencies, insecure code, and OWASP Top 10 vulnerabilities and more — offline-first, fully deterministic, minimal dependencies.**

</div>

## Features

- **Secrets Scanner** — Detects 40+ API keys, tokens, JWTs, AWS credentials, private keys, database connection strings, and more using regex pattern matching with entropy-based fallback
- **Dependency Scanner** — Auto-detects 8 package ecosystems (PyPI, npm, Maven, Go, crates.io, RubyGems, Packagist, NuGet) and queries the **OSV.dev API** (Google's open vulnerability database) by default for comprehensive, always-up-to-date CVE coverage. Equivalent to Semgrep Supply Chain's ecosystem breadth — no proprietary lock-in.
- **Static Analysis** — Detects 70+ insecure code patterns: `eval()`, `exec()`, `os.system()`, unsafe `subprocess`, `pickle` deserialization, SQL injection, XSS, SSRF, and more across 6 languages (Python, JS/TS, Go, Java, Ruby, PHP) using regex and AST analysis
- **Decision Engine** — Configurable severity thresholds (LOW/MEDIUM/HIGH/CRITICAL) with clear exit codes for CI/CD integration
- **Three Output Formats** — Human-readable terminal output, machine-readable JSON, and **SARIF v2.1.0** for GitHub Advanced Security
- **Minimal Dependencies** — Only 3 lightweight packages (`pathspec`, `packaging`, `tqdm`); no npm, no Docker
- **OSV API by default** — Queries the Google-maintained OSV.dev database (GHSA, PyPA, RustSec, Go vulndb, npm advisories, OSS-Fuzz, etc.) for real-time vulnerability data. Use `--offline` for air-gapped environments.
- **Test Repository** — Includes a sample repo with intentional vulnerabilities for testing
- **DAST Test Server** — Includes an intentionally vulnerable HTTP server at `test_servers/vulnerable_server.py` for DAST testing


## Why Sentinel?

| Feature | Sentinel | Semgrep | Other Tools |
|---------|----------|---------|-------------|
| Dependencies | **3 lightweight packages** | Requires npm/Docker | Often require npm, Docker, or cloud services |
| Vulnerability DB | **OSV.dev API (default)** — GHSA, PyPA, RustSec, Go vulndb, npm advisories | Proprietary + GHSA | Often proprietary or NVD-only |
| Ecosystem Support | **8 ecosystems** (PyPI, npm, Maven, Go, crates.io, RubyGems, Packagist, NuGet) | 10+ ecosystems | Varies widely |
| Network | **Online by default, offline via `--offline`** | Requires network | Varies |
| Deterministic | **Yes — regex + static analysis** | Yes — AST-based rules | Often use ML/heuristics with variable results |
| CI/CD Ready | **Exit codes + SARIF + JSON** | SARIF + JSON | Varies widely |
| Complexity | **One CLI command** | Complex YAML rules | Often complex configuration required |
| Accuracy | **Passive, deterministic analysis** | AST + dataflow reachability | Often use active exploitation or heuristic models |
| Open Data | **100% open OSV database** | Mixed open/proprietary | Often proprietary |
| Air-Gapped | **Yes (`--offline` mode)** | Requires network | Rarely supported |

Sentinel is ideal for:
- **CI/CD pipelines** where you want comprehensive, always-up-to-date security checks without pulling in npm/Docker
- **Multi-language monorepos** — auto-detects dependency files across 8 ecosystems
- **Air-gapped environments** — `--offline` flag with built-in vulnerability database
- **Learning and education** — the codebase is small, well-structured, and easy to understand
- **Quick local scans** before committing code
- **Replacing Semgrep Supply Chain** — comparable ecosystem coverage with zero proprietary lock-in

## Quick Start

```bash
# Install from PyPI
pip install sentinel-security

# Scan the included test repository
sentinel scan test_repo

# Scan any local directory
sentinel scan /path/to/your/project

# DAST scan a web application
sentinel dast https://example.com

# Output as SARIF for GitHub Code Scanning
sentinel scan . --output sarif -o results.sarif
```

## Installation

Sentinel requires **Python 3.8+**. Install via pip or run directly from source.

### From PyPI (recommended)

```bash
pip install sentinel-security
sentinel scan /path/to/repo
sentinel dast https://example.com
```

### From source

```bash
git clone https://github.com/your-org/sentinel.git
cd sentinel
pip install -r requirements.txt
```

### How to run Sentinel

After installation, use the `sentinel` command directly:

```bash
sentinel scan /path/to/repo
sentinel dast https://example.com
```

If you're working from the cloned repo **without installing**, use one of these:

```bash
# Run as a Python module
python -m sentinel scan /path/to/repo

# Or use the wrapper script
python cli.py scan /path/to/repo
```

To make `sentinel` available as a system command from source, install in editable mode:

```bash
pip install -e .
sentinel scan /path/to/repo   # now works from anywhere
```

### Dependencies

Sentinel depends on **3 lightweight runtime packages**:

| Package | Purpose |
|---------|---------|
| `pathspec` | .gitignore rule matching for file discovery |
| `packaging` | Semantic version comparison for dependency vulns |
| `tqdm` | Progress bar during scanning |

No heavy frameworks (Docker, npm, Node.js) required.

### `sentinel` vs `python -m sentinel`

If you installed via `pip install sentinel-security` or `pip install -e .`, use:

```bash
sentinel scan /path/to/repo
```

If you're running from a cloned repo without installing, use:

```bash
python -m sentinel scan /path/to/repo
# or
python cli.py scan /path/to/repo
```

All CLI flags and commands work identically either way.

## CLI Reference

### `scan` command

```bash
sentinel scan <path> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `path` | Path to the repository to scan (required) |

**Options:**

| Option | Description |
|--------|-------------|
| `--output {human,json,sarif}` | Output format. `human` (default) for terminal, `json` for machine parsing, `sarif` for GitHub Advanced Security. |
| `--output-file FILE`, `-o FILE` | Write output to a file. Combine with `--output` or use standalone. |
| `--json [FILE]` | *(Legacy)* Output as JSON. Use `--output json` instead. |
| `--sarif [FILE]` | *(Legacy)* Output as SARIF. Use `--output sarif` instead. |
| `--all`, `--scan-all` | Scan **ALL** files — no binary/source filtering, no `.gitignore` respect, no directory skipping. Maximum coverage mode. |
| `--offline` | Use local vulnerability database instead of OSV API. Ideal for air-gapped environments or faster CI scans. |
| `--no-gitignore` | Include `.gitignored` files in the scan (e.g., `.env` files, credential dumps). |
| `--stats` | Show detailed scan statistics: file type breakdown, per-scanner timing, bar charts. |
| `--exclude PATTERNS` | Comma-separated gitignore-style patterns to exclude (e.g. `--exclude "*.test.py,docs/*"`). |
| `--include PATTERNS` | Comma-separated gitignore-style patterns to only scan (e.g. `--include "*.py,*.js,*.yaml"`). |
| `--verbose`, `-v` | Show detailed output during scanning |
| `--severity-threshold {LOW,MEDIUM,HIGH,CRITICAL}` | Minimum severity that triggers BLOCK. Default: HIGH. `CRITICAL` threshold only blocks on critical findings. |
| `--help` | Show help message |

### `--version`

```bash
sentinel --version
# > Sentinel v0.3.0
```

## Exit Codes
| Code | Verdict | Default Threshold (HIGH) | MEDIUM Threshold | LOW Threshold | CRITICAL Threshold |
|------|---------|--------------------------|------------------|---------------|-------------------|
| `0` | ✅ PASS | No issues or LOW only | No issues | No issues | No issues |
| `1` | ⚠️ WARN | MEDIUM issues found | LOW issues found | — | MEDIUM or HIGH issues |
| `2` | ❌ BLOCK | HIGH issues found | MEDIUM+ issues | Any issue | CRITICAL issues |

```bash
# Exit codes work naturally in CI/CD pipelines
sentinel scan . --severity-threshold MEDIUM
if [ $? -eq 2 ]; then
  echo "Security issues found — blocking build"
  exit 1
fi
```

## Output Formats

### Human-readable (default)

```bash
sentinel scan test_repo
```

Displays a color-coded summary with findings grouped by file, severity badges, and line references.

### JSON

```bash
sentinel scan test_repo --output json -o report.json
```

Machine-readable JSON with verdict, total findings, file list, and all finding details.

<details>
<summary>Example JSON output</summary>

```json
{
  "verdict": "BLOCK",
  "total_findings": 30,
  "scanned_files": 4,
  "scan_time_ms": 12.34,
  "severity_threshold": "HIGH",
  "findings": [
    {
      "file_path": "app.py",
      "line_number": 9,
      "issue_type": "static_analysis",
      "severity": "HIGH",
      "message": "Use of eval() detected. eval() can execute arbitrary code and is a security risk.",
      "rule_id": "SAF-EVAL",
      "confidence": 1.0,
      "snippet": "result = eval(user_input)"
    }
  ]
}
```

</details>

### SARIF v2.1.0

```bash
sentinel scan test_repo --output sarif -o report.sarif
```

Industry-standard format compatible with [GitHub Advanced Security](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning), Azure DevOps, and other SARIF-compatible tools.

```bash
# Upload to GitHub Code Scanning (requires GitHub CLI)
gh api /repos/:owner/:repo/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" \
  -f sarif="$(cat report.sarif | base64 -w0)"
```

The SARIF output has been validated against the **official OASIS SARIF v2.1.0 JSON schema** (Errata 01) — 100% compliant.

<details>
<summary>Example SARIF output</summary>

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Sentinel",
          "version": "0.3.0",
          "informationUri": "https://github.com/sentinel-security/sentinel",
          "rules": [
            {
              "id": "SEC-aws-access-key",
              "name": "Aws Access Key",
              "shortDescription": { "text": "AWS Access Key ID detected" },
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "severity": "HIGH",
                "issueType": "secret",
                "tags": ["security", "secret"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SEC-aws-access-key",
          "level": "error",
          "message": { "text": "AWS Access Key ID detected in configuration file." },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "config.py", "uriBaseId": "%SRCROOT%" },
              "region": { "startLine": 5 }
            }
          }]
        }
      ],
      "invocations": [
        { "executionSuccessful": true }
      ],
      "properties": {
        "verdict": "BLOCK",
        "total_findings": 30,
        "scanned_files": 4,
        "scan_time_ms": 12.34,
        "severity_threshold": "HIGH"
      }
    }
  ]
}
```

</details>

```bash
# Validate SARIF output yourself
sentinel scan test_repo --output sarif -o report.sarif
python scripts/validate_sarif.py report.sarif
# > ✅ SARIF output is valid against the official schema.
```

## Examples

### Basic scan

```bash
$ sentinel scan test_repo

🔍 Sentinel v0.3.0 - Scanning: /path/to/test_repo
   Threshold: HIGH
   This may take a moment...

═══════════════════════════════════════
  Sentinel Security Scan Report
═══════════════════════════════════════

Summary:
  Files scanned:     4
  Findings found:    30
  Severity threshold: [HIGH]
  Scan time:         12ms
  File types:        .py: 2, .txt: 1, .yml: 1

Findings by severity:
  14 HIGH
  9 MEDIUM
  7 LOW

Findings by type:
  🔑 Secrets: 10
  ⚠️ Static Analysis: 18
  📦 Dependencies: 2

Detailed findings:

  📄 app.py
    [HIGH] ⚠️ Use of eval() detected... line 9 SAF-EVAL
           └─→ result = eval(user_input)
           method: regex
           confidence: 100%
           fix: Replace eval() with safer alternatives like ast.literal_eval() or a proper parser.

  📄 config.py
    [HIGH] 🔑 AWS Access Key ID detected... line 12 SEC-aws-access-key
           └─→ AWS_ACCESS_KEY_ID = "AKIA..."
           method: regex
           confidence: 90%
           fix: Rotate the key immediately. Use IAM roles or temporary credentials via STS instead of long-lived keys.

────────────────────────────────────────
  Verdict: BLOCK
  Exit code: 2
────────────────────────────────────────
```

### Scanning all files (full coverage)

By default, Sentinel skips binary files, common dependency directories (`node_modules`, `.venv`), and `.gitignored` files. Use `--all` to scan **every** file:

```bash
# Scan everything — binaries, node_modules, .git, the works
sentinel scan /path/to/repo --all

# Include .gitignored files but still skip binaries/deps
sentinel scan /path/to/repo --no-gitignore

# Only scan specific file types
sentinel scan /path/to/repo --include "*.py,*.yaml,*.env"

# Exclude test files from scanning
sentinel scan /path/to/repo --exclude "tests/*,docs/*"
```

### Viewing detailed scan statistics

```bash
# Show file type breakdown, per-scanner timing, and histograms
sentinel scan /path/to/repo --stats
```

Output includes:
- File extension distribution with bar charts
- Per-scanner timing breakdown (file discovery, dependency scan, parallel scan)
- Findings split by issue type (secrets, static analysis, dependencies)

### OSV API (default) for comprehensive, always-up-to-date vulnerability data

Sentinel queries the **OSV.dev API by default** — the same open vulnerability database used by Google, GitHub, and the OpenSSF. Covers vulnerabilities from:
- GitHub Security Advisories (GHSA)
- PyPA Advisory Database
- RustSec Advisory Database
- Go vulnerability database
- npm Security Advisories
- OSS-Fuzz findings
- And many more sources

```bash
# Default: queries OSV API for ALL detected ecosystems
sentinel scan /path/to/repo

# Combine with other options
sentinel scan /path/to/repo --severity-threshold MEDIUM

# Export online results as SARIF
sentinel scan /path/to/repo --output sarif -o results.sarif

# Offline mode: use built-in local database (air-gapped CI)
sentinel scan /path/to/repo --offline
```

#### Multi-ecosystem auto-detection

Sentinel automatically discovers and scans dependency files across all major ecosystems:

| Ecosystem | Files Detected |
|-----------|---------------|
| **PyPI** (Python) | `requirements.txt`, `Pipfile`, `Pipfile.lock` |
| **npm** (JavaScript/TypeScript) | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Maven** (Java/Kotlin) | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| **Go** | `go.mod`, `go.sum` |
| **crates.io** (Rust) | `Cargo.toml`, `Cargo.lock` |
| **RubyGems** (Ruby) | `Gemfile`, `Gemfile.lock` |
| **Packagist** (PHP) | `composer.json`, `composer.lock` |
| **NuGet** (.NET) | `packages.config`, `*.csproj` |

No configuration needed — just point Sentinel at your repo and it finds everything.

### Changing the severity threshold

```bash
# Stricter: any finding (even LOW) causes BLOCK
sentinel scan test_repo --severity-threshold LOW

# Default: only HIGH findings cause BLOCK
sentinel scan test_repo
```

### CI/CD integration

#### GitHub Actions

A ready-to-use workflow is included at `.github/workflows/sentinel-scan.yml`:

```yaml
name: Sentinel Security Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  sentinel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"
      - name: Install Sentinel
        run: pip install sentinel-security
      - name: Run Sentinel
        id: sentinel
        continue-on-error: true
        run: |
          sentinel scan . --sarif sentinel-results.sarif --severity-threshold MEDIUM || exit_code=$?
          echo "exit_code=${exit_code:-0}" >> "$GITHUB_OUTPUT"
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinel-results.sarif
          category: sentinel
      - name: Display scan summary
        if: always()
        run: |
          EXIT_CODE="${{ steps.sentinel.outputs.exit_code }}"
          echo "### Sentinel Security Scan Results" >> "$GITHUB_STEP_SUMMARY"
          if [ "$EXIT_CODE" = "2" ]; then
            echo "🔴 **BLOCKED** - High severity security issues detected!" >> "$GITHUB_STEP_SUMMARY"
          elif [ "$EXIT_CODE" = "1" ]; then
            echo "🟡 **WARNING** - Medium severity issues found" >> "$GITHUB_STEP_SUMMARY"
          else
            echo "🟢 **PASS** - No security issues found" >> "$GITHUB_STEP_SUMMARY"
          fi
```

Findings appear under **Security > Code scanning** in your repository.

#### Generic CI

```bash
sentinel scan . --output json -o report.json --severity-threshold MEDIUM
exit_code=$?

case $exit_code in
  0) echo "✅ PASS: No security issues" ;;
  1) echo "⚠️  WARNING: Low severity issues found" ;;
  2) echo "❌ BLOCKED: Security issues found! See report.json" ;;
esac

exit $exit_code
```

## Scanners

### DAST Scanner (Dynamic Application Security Testing)

The DAST scanner performs passive, observational security analysis of web applications and APIs using safe HTTP requests. No exploitation, no destructive payloads, no brute force. Covers 29 detection phases across the OWASP Top 10:

| Phase | Check | Rule ID Prefix | Severity |
|-------|-------|---------------|----------|
| 1 | Initial reconnaissance & connectivity | `DAST-CONNECTION-ERROR` | LOW |
| 2 | Security headers (HSTS, CSP, X-Frame-Options, etc.) | `DAST-STRICT-TRANSPORT-SECURITY` etc. | LOW–HIGH |
| 3 | Cookie security (Secure, HttpOnly, SameSite flags) | `DAST-COOKIE-NO-SECURE` etc. | MEDIUM–HIGH |
| 4 | CORS misconfiguration (wildcard origins, credentials) | `DAST-CORS-WILDCARD` etc. | MEDIUM–HIGH |
| 5 | TLS/HTTPS assessment (version, encryption) | `DAST-NO-HTTPS`, `DAST-WEAK-TLS` | HIGH |
| 6 | Server info disclosure (Server header, X-Powered-By, debug mode) | `DAST-SERVER-INFO-DISCLOSURE` etc. | LOW–HIGH |
| 7 | Injection reflection (SQL, NoSQL, command, LDAP, XPath) | `DAST-INJECTION-SQL` etc. | HIGH–CRITICAL |
| 8 | XSS reflection detection | `DAST-XSS-REFLECTED` | HIGH |
| 9 | Server-Side Template Injection (SSTI) | `DAST-SSTI` | MEDIUM–CRITICAL |
| 10 | Sensitive endpoint discovery (admin, debug, .env, .git) | `DAST-EXPOSED-*` | LOW–CRITICAL |
| 11 | Verbose error message detection (stack traces, SQL errors) | `DAST-VERBOSE-ERROR-*` | MEDIUM–HIGH |
| 12 | Directory listing enabled | `DAST-DIRECTORY-LISTING` | MEDIUM |
| 13 | Authentication checks (login over HTTP, user enumeration) | `DAST-LOGIN-OVER-HTTP`, `DAST-USER-ENUMERATION` | MEDIUM–CRITICAL |
| 14 | Access control / IDOR (insecure direct object references) | `DAST-IDOR-POTENTIAL` | HIGH |
| 15 | Open redirect detection | `DAST-OPEN-REDIRECT` | MEDIUM |
| 16 | ReDoS pattern detection | `DAST-REDOS`, `DAST-REDOS-TIMING` | MEDIUM–HIGH |
| 17 | XXE & insecure deserialization indicators | `DAST-XXE-POTENTIAL`, `DAST-INSECURE-DESERIALIZATION` | MEDIUM–HIGH |
| 18 | JWT misconfiguration (alg: none, no expiry, symmetric alg) | `DAST-JWT-ALG-NONE` etc. | LOW–CRITICAL |
| 19 | Rate limiting assessment | `DAST-NO-RATE-LIMITING` | LOW |
| 20 | Cloud metadata endpoint exposure (AWS/GCP/Azure IMDS) | `DAST-AWS-METADATA-ACCESSIBLE` etc. | CRITICAL |
| 21 | SSRF indicator detection | `DAST-SSRF-INDICATOR`, `DAST-SSRF-CLOUD-METADATA` | MEDIUM–CRITICAL |
| 22 | GraphQL introspection detection | `DAST-GRAPHQL-INTROSPECTION` | MEDIUM |
| 23 | CSP analysis (unsafe directives) | `DAST-CSP-INSECURE` | MEDIUM |
| 24 | HTTP method enumeration | `DAST-HTTP-METHODS` | MEDIUM |
| 25 | Framework fingerprinting | `DAST-FRAMEWORK-FINGERPRINT` | LOW |
| 26 | Cookie prefix analysis | `DAST-COOKIE-NO-PREFIX` | LOW |
| 27 | Subresource Integrity checks | `DAST-SRI-MISSING` | MEDIUM |
| 28 | WebSocket security assessment | `DAST-WEBSOCKET-NO-WSS` | MEDIUM |
| 29 | Content-Type sniffing prevention | `DAST-NOSNIFF-HEADER` | LOW |

```bash
# Run a DAST scan
sentinel dast https://example.com

# Output as SARIF
sentinel dast https://example.com --output sarif -o dast-results.sarif

# Test against the included vulnerable server
python test_servers/vulnerable_server.py --port 8080 &
sentinel dast http://localhost:8080
```

### Secrets Scanner

Detects **40+ secret patterns** across cloud providers, SaaS platforms, infrastructure, and general credentials — with entropy-based fallback detection for unknown secrets. Key patterns include:

| Pattern | Rule ID | Severity |
|---------|---------|----------|
| AWS Access Key ID | `SEC-aws-access-key` | HIGH |
| AWS Secret Access Key | `SEC-aws-secret-key` | HIGH |
| AWS Session Token | `SEC-aws-session-token` | HIGH |
| GCP Service Account Key | `SEC-gcp-service-account` | HIGH |
| GCP API Key | `SEC-gcp-api-key` | MEDIUM |
| Azure Connection String | `SEC-azure-connection-string` | HIGH |
| Azure Client Secret | `SEC-azure-client-secret` | HIGH |
| Private Keys (RSA, DSA, EC, OpenSSH, PGP) | `SEC-private-key` | HIGH |
| PGP Private Key Block | `SEC-pgp-private-key-block` | HIGH |
| GitHub Personal Access Token | `SEC-github-token` | HIGH |
| GitLab Personal Access Token | `SEC-gitlab-token` | HIGH |
| npm Access Token | `SEC-npm-token` | HIGH |
| Docker Hub PAT | `SEC-docker-hub-token` | HIGH |
| Slack Bot Token | `SEC-slack-bot-token` | HIGH |
| Slack Webhook URL | `SEC-slack-webhook-url` | HIGH |
| Discord Bot Token | `SEC-discord-bot-token` | HIGH |
| SendGrid API Key | `SEC-sendgrid-api-key` | HIGH |
| Stripe Live Secret Key | `SEC-stripe-live-key` | HIGH |
| Twilio Credentials | `SEC-twilio-account-sid`/`SEC-twilio-auth-token` | HIGH |
| Pulumi Access Token | `SEC-pulumi-access-token` | HIGH |
| Snyk Token | `SEC-snyk-token` | HIGH |
| Heroku API Key | `SEC-heroku-api-key` | HIGH |
| Database Connection Strings | `SEC-connection-string` | HIGH |
| JWT Token | `SEC-jwt-token` | MEDIUM |
| Generic API Key/Secret | `SEC-generic-api-key` | MEDIUM |
| Hardcoded Password | `SEC-password-in-code` | MEDIUM |
| Google API Key | `SEC-google-api-key` | MEDIUM |
| Datadog API Key | `SEC-datadog-api-key` | MEDIUM |
| New Relic License Key | `SEC-new-relic-key` | MEDIUM |
| Generic Secret/Token | `SEC-generic-secret` | LOW |
| High-Entropy Strings (variable-level) | `SEC-ENTROPY` | LOW–MEDIUM |

### Dependency Scanner

Queries the **OSV.dev API by default** for comprehensive, always-up-to-date vulnerability data across all supported ecosystems. The OSV database aggregates advisories from:
- **GitHub Security Advisories (GHSA)** — the industry standard for severity ratings
- **PyPA Advisory Database** — official Python packaging vulnerabilities
- **RustSec Advisory Database** — Rust crate vulnerabilities
- **Go vulnerability database** — official Go module vulnerabilities
- **npm Security Advisories** — Node.js package vulnerabilities
- **OSS-Fuzz** — continuously fuzzed open source project findings

Auto-detects and parses dependency files across **8 package ecosystems** (PyPI, npm, Maven, Go, crates.io, RubyGems, Packagist, NuGet) — comparable coverage to Semgrep Supply Chain.

Use `--offline` to fall back to the built-in local vulnerability database (`data/vulndb.json`) for air-gapped environments or ultra-fast CI scans.

### Static Analysis Scanner

Detects **70+ insecure code patterns** across **6 languages** (Python, JavaScript/TypeScript, Go, Java, Ruby, PHP) using both regex and AST analysis. Key categories include:

| Category | Patterns | Languages | Severity |
|----------|----------|-----------|----------|
| Code Execution | `eval()`, `exec()`, `compile()`, `os.system()`, `os.popen()`, `subprocess(shell=True)`, Node.js `child_process`, PHP `system()`/`exec()` | All | HIGH |
| Deserialization | `pickle.load()`, `marshal.load()`, `yaml.load()`, `jsonpickle`, Ruby `Marshal.load()`, Java `ObjectInputStream`, PHP `unserialize()` | Python, Ruby, Java, PHP | HIGH–CRITICAL |
| SQL Injection | String concatenation, f-strings, format strings in queries; Java, Go, PHP variants | Python, Java, Go, PHP | HIGH |
| XSS | `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, PHP raw echo of user input | JS/TS, PHP | HIGH |
| Path Traversal | `open()` with user input, PHP file inclusion | Python, PHP | MEDIUM–CRITICAL |
| Weak Crypto | MD5, SHA-1, DES/RC2/RC4, ECB mode, weak Node.js/Java crypto | Python, JS, Java | MEDIUM–HIGH |
| SSRF | HTTP requests with user-supplied URLs, `fetch()` with user input | Python, JS | HIGH |
| Template Injection | Jinja2 `from_string()`, `Template()` | Python | MEDIUM |
| Insecure Config | CORS allow-all, hardcoded credentials (AST), insecure chmod 777 | All | LOW–MEDIUM |
| Information Disclosure | Debug endpoints, stack traces, framework fingerprinting | All | LOW |
| Timing Attacks | Non-constant-time comparisons for secrets/tokens | All | MEDIUM |
| Open Redirect | User input used in redirects without validation | All | MEDIUM |
| Prototype Pollution | `__proto__` manipulation, `Object.assign()` with user input | JS/TS | HIGH |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

### Quick contribution guide

```bash
# Set up development environment
git clone https://github.com/your-org/sentinel.git
cd sentinel

# Run tests
python -m unittest discover tests -v

# Make your changes, then validate SARIF output
python -m sentinel scan test_repo --output sarif -o /tmp/sarif_out.json
python scripts/validate_sarif.py /tmp/sarif_out.json
```

Areas we'd love help with:

- **New scanners** — Support for more languages and frameworks
- **Additional secrets patterns** — Contributions to `SECRET_PATTERNS`
- **Expanded vulnerability database** — Pull requests for `data/vulndb.json`
- **Documentation improvements** — Better examples, guides, and troubleshooting
- **Test coverage** — Unit tests for scanners, formatters, and the CLI

## Project Structure

```
sentinel/
├── cli.py                          # CLI entry point (scan + dast commands)
├── pyproject.toml                  # Package build configuration
├── requirements.txt                # Python dependencies
├── sentinel/
│   ├── __init__.py                 # Package init, version info
│   ├── _cli.py                     # CLI argument parsing & command routing
│   ├── main.py                     # Entry point for `sentinel` command
│   ├── models.py                   # Data models (Finding, Severity, Verdict, ScanResult)
│   ├── pipeline.py                 # Scanning pipeline orchestrator
│   ├── decision.py                 # Verdict decision engine
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py               # Parallel scanner orchestration engine
│   │   ├── file_discovery.py       # File discovery with gitignore/pathspec support
│   │   ├── secrets_scanner.py      # Regex + entropy-based secrets detection (40+ patterns)
│   │   ├── dependency_scanner.py   # Multi-ecosystem dependency vuln scanner (OSV API)
│   │   ├── static_analysis.py      # 70+ insecure code pattern rules across 6 languages
│   │   └── dast_scanner.py         # 29-phase DAST web application scanner
│   └── formatters/
│       ├── __init__.py
│       ├── human.py                # Human-readable CLI output
│       ├── json_formatter.py       # Machine-readable JSON
│       └── sarif.py                # SARIF v2.1.0 output
├── data/
│   └── vulndb.json                 # Local vulnerability database (offline fallback)
├── scripts/
│   └── validate_sarif.py           # SARIF schema validation utility
├── tests/
│   ├── __init__.py
│   ├── test_cli.py                 # CLI argument parsing tests
│   ├── test_engine.py              # Scanner engine tests
│   ├── test_secrets_scanner.py     # Secrets scanner tests
│   ├── test_static_analysis.py     # Static analysis tests
│   ├── test_dependency_scanner.py  # Dependency scanner tests
│   ├── test_dast_scanner.py        # DAST scanner tests
│   ├── test_file_discovery.py      # File discovery tests
│   ├── test_decision.py            # Decision engine tests
│   ├── test_sarif_formatter.py     # SARIF formatter tests
│   └── test_end_to_end.py          # End-to-end integration tests
├── test_servers/
│   └── vulnerable_server.py        # Intentionally vulnerable HTTP server for DAST testing
├── .github/workflows/
│   └── sentinel-scan.yml           # GitHub Actions workflow
├── test_repo/                      # Sample repo with intentional vulnerabilities
├── CONTRIBUTING.md                 # Contribution guidelines
└── README.md                       # This file
```

## Roadmap

### v0.2
- [x] DAST module for OWASP Top 10 web application scanning
- [x] 21-phase inference-based vulnerability detection *(expanded to 29 phases in v0.3)*
- [x] CWE and OWASP category mapping
- [x] CRITICAL severity level
- [x] `dast` CLI subcommand with configurable options
- [x] Intentionally vulnerable test HTTP server
- [x] PyPI packaging (`pyproject.toml`, `requirements.txt`)

### v0.3
- [x] **Multi-ecosystem dependency scanning** (PyPI, npm, Maven, Go, crates.io, RubyGems, Packagist, NuGet)
- [x] **OSV API as default** — comprehensive, always-up-to-date vulnerability data
- [x] **Batch OSV queries** for efficient multi-package checks
- [x] **`--offline` flag** for air-gapped environments
- [x] **DAST expanded to 29 phases** — GraphQL introspection, CSP analysis, HTTP method enumeration, framework fingerprinting, cookie prefix analysis, SRI checks, WebSocket security, content-type sniffing
- [x] **70+ static analysis patterns** across 6 languages (Python, JS/TS, Go, Java, Ruby, PHP)
- [x] **40+ secrets patterns** with entropy-based fallback
- [x] **AST-based analysis** — hardcoded credentials, bare except, insecure SSL, missing timeouts
- [x] **Parallel scanning engine** with thread pool for large repositories
- [x] **`--stats` flag** for detailed scan statistics with bar charts
- [x] **`--exclude`/`--include`** pattern filtering
- [x] **Logo and polished README**

### v0.4 (Planned)
- [ ] Lockfile-based transitive dependency resolution
- [ ] `.env` file detection improvements
- [ ] Configurable rules (enable/disable individual rules by ID)
- [ ] `--diff` mode: scan only changed lines vs. a baseline
- [ ] Pre-commit hook support
- [ ] HTML report output

### v1.0 (Vision)
- [ ] Git history scanning (blame-aware findings)
- [ ] Custom rules DSL (define rules via YAML/JSON config files)
- [ ] IDE plugin integrations (VS Code, JetBrains)
- [ ] Performance benchmarks and optimization
- [ ] More output formats (GitLab SAST, SonarQube)

*Sentinel is a community-driven project. The roadmap evolves based on contributor interest and user feedback. Open an issue or discussion to suggest priorities!*

## Limitations (v0.3)

- **Deterministic only** — No heuristic or ML-based detection
- **Regex-based secrets scanning** — May produce false positives and false negatives
- **DAST is inference-based** — Detects vulnerabilities through observation, not exploitation; findings are validated across multiple payloads to minimize false positives
- **DAST requires network access** — Scans external URLs and may not work behind strict firewalls or without outbound HTTP access
- **Local vulnerability database is small** — The built-in `vulndb.json` covers 15 popular Python packages (used only with `--offline`). Default online mode queries all 8 ecosystems through the OSV API.
- **Static analysis is Python-focused** — AST analysis is Python-only; other languages use regex patterns
- **No transitive/lockfile dependency resolution** — Parses declared versions from manifest files but does not resolve full dependency trees
- **Binary file scanning via `--all`** — Binary files can contain secrets, but snippets may appear garbled

## Related Projects

- [**Semgrep**](https://semgrep.dev/) — Powerful static analysis with custom rules
- [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) — Secrets scanning with git history support
- [**Bandit**](https://github.com/PyCQA/bandit) — Python-focused security linter
- [**Safety**](https://github.com/pyupio/safety) — Python dependency vulnerability checker
- [**GitLeaks**](https://github.com/gitleaks/gitleaks) — Go-based secrets scanner
- [**Nuclei**](https://github.com/projectdiscovery/nuclei) — Fast vulnerability scanner with template-based DAST

Sentinel differentiates itself by being:
- **Minimal dependencies** — Only 3 lightweight runtime packages, no npm, no Docker
- **Fully deterministic** — Same input always produces the same output
- **Open vulnerability data** — OSV.dev API is 100% open source and community-maintained; no proprietary lock-in
- **Multi-ecosystem** — 8 package ecosystems detected automatically; comparable to Semgrep Supply Chain
- **Multi-language static analysis** — 70+ patterns across 6 languages with AST and regex hybrid detection
- **Built-in DAST** — 29-phase OWASP Top 10 web application scanning in the same CLI
- **Simple codebase** — Easy to understand, modify, and contribute to
- **Multi-format output** — Human, JSON, and SARIF out of the box

## License

[Apache License 2.0](LICENSE) — See [LICENSE](LICENSE) for the full license text.
