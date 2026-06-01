<div align="center">

<img src="assets/icon.png" alt="Sentinel Logo" width="228" />

# 

**Local-first, deterministic security scanner for Git repositories.**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-standard-brightgreen)](CONTRIBUTING.md#code-style)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)

---

**Scan Git repositories and web applications for secrets, vulnerable dependencies, insecure code, and OWASP Top 10 vulnerabilities and more, completely offline, fully deterministic, minimal dependencies.**

</div>

## Features

- ** Secrets Scanner** — Detects API keys, tokens, JWTs, AWS credentials, private keys, database connection strings, and more using regex pattern matching
- ** Dependency Scanner** — Parses `requirements.txt` (with basic Pipfile support) and checks package versions against a built-in mock vulnerability database
- ** Static Analysis** — Detects insecure patterns: `eval()`, `exec()`, `os.system()`, unsafe `subprocess`, `pickle` deserialization, SQL injection, and more across 9+ languages
- ** Decision Engine** — Configurable severity thresholds (LOW/MEDIUM/HIGH/CRITICAL) with clear exit codes for CI/CD integration
- ** Three Output Formats** — Human-readable terminal output, machine-readable JSON, and **SARIF v2.1.0** for GitHub Advanced Security
- ** Minimal Dependencies** — Only 3 lightweight packages (`pathspec`, `packaging`, `tqdm`)
- ** Fully Offline** — No network calls, no cloud services, no data exfiltration
- ** Test Repository** — Includes a sample repo with intentional vulnerabilities for testing
- ** DAST Test Server** — Includes an intentionally vulnerable HTTP server at `test_servers/vulnerable_server.py` for DAST testing


## Why Sentinel?

| Feature | Sentinel | Other Tools |
|---------|----------|-------------|
| Dependencies | **3 lightweight packages** | Often require npm, Docker, or cloud services |
| Network | **None — fully offline** | Many phone home or require API keys |
| Deterministic | **Yes — regex + static analysis** | Often use ML/heuristics with variable results |
| CI/CD Ready | **Exit codes + SARIF + JSON** | Varies widely |
| Complexity | **One CLI command** | Often complex configuration required |

Sentinel is ideal for:
- **CI/CD pipelines** where you want fast, deterministic security checks without pulling in heavy dependencies
- **Offline/air-gapped environments** where network access is restricted
- **Learning and education** — the codebase is small, well-structured, and easy to understand
- **Quick local scans** before committing code

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

Sentinel uses **3 lightweight packages**:

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
| `--no-gitignore` | Include `.gitignored` files in the scan (e.g., `.env` files, credential dumps). |
| `--stats` | Show detailed scan statistics: file type breakdown, per-scanner timing, bar charts. |
| `--exclude PATTERNS` | Comma-separated gitignore-style patterns to exclude (e.g. `--exclude "*.test.py,docs/*"`). |
| `--include PATTERNS` | Comma-separated gitignore-style patterns to only scan (e.g. `--include "*.py,*.js,*.yaml"`). |
| `--verbose`, `-v` | Show detailed output during scanning |
| `--online` | Use the OSV API for dependency vulnerability checking instead of the local database. Requires network access. Provides comprehensive, up-to-date CVE coverage. |
| `--severity-threshold {LOW,MEDIUM,HIGH}` | Minimum severity that triggers BLOCK. Default: HIGH. |
| `--help` | Show help message |

### `--version`

```bash
sentinel --version
# > Sentinel v0.2.0
```

## Exit Codes

| Code | Verdict | Default Threshold (HIGH) | MEDIUM Threshold | LOW Threshold |
|------|---------|--------------------------|------------------|---------------|
| `0` | ✅ PASS | No issues or LOW only | No issues | No issues |
| `1` | ⚠️ WARN | MEDIUM issues found | LOW issues found | — |
| `2` | ❌ BLOCK | HIGH issues found | MEDIUM+ issues | Any issue |

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
          "version": "0.2.0",
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

🔍 Sentinel v0.2.0 - Scanning: /path/to/test_repo
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
           fix: Replace eval() with safer alternatives

  📄 config.py
    [HIGH] 🔑 AWS Access Key ID detected... line 12 SEC-aws-access-key
           └─→ AWS_ACCESS_KEY_ID = "AKIA..."
           method: regex
           confidence: 90%

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

### Using OSV API for comprehensive vulnerability data

```bash
# Query the OSV API instead of the local database
sentinel scan /path/to/repo --online

# Combine with other options
sentinel scan /path/to/repo --online --severity-threshold MEDIUM

# Export online results as SARIF
sentinel scan /path/to/repo --online --output sarif -o online-results.sarif
```

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
  push: {branches: [main, master]}
  pull_request: {branches: [main, master]}
  schedule: [{cron: "0 6 * * 1"}]
permissions:
  contents: read
  security-events: write
jobs:
  sentinel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.11"}
      - name: Install Sentinel
        run: pip install sentinel-security
      - name: Run Sentinel
        id: sentinel
        continue-on-error: true
        run: |
          sentinel scan . --output sarif -o sentinel-results.sarif --severity-threshold MEDIUM || exit_code=$?
          echo "exit_code=${exit_code:-0}" >> "$GITHUB_OUTPUT"
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: sentinel-results.sarif}
      - name: Summary
        if: always()
        run: |
          echo "### Sentinel Results" >> "$GITHUB_STEP_SUMMARY"
          echo "Exit code: \${{ steps.sentinel.outputs.exit_code }}" >> "$GITHUB_STEP_SUMMARY"
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

The DAST scanner performs passive, observational security analysis of web applications and APIs using safe HTTP requests. No exploitation, no destructive payloads, no brute force. Covers 21 detection phases across the OWASP Top 10:

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

Detects the following types of secrets in all text files:


| Pattern | Rule ID | Severity |
|---------|---------|----------|
| AWS Access Key ID | `SEC-aws-access-key` | HIGH |
| AWS Secret Access Key | `SEC-aws-secret-key` | HIGH |
| Private Keys (RSA, DSA, EC, OpenSSH, PGP) | `SEC-private-key` | HIGH |
| GitHub Personal Access Token | `SEC-github-token` | HIGH |
| Slack API Token | `SEC-slack-token` | HIGH |
| Database Connection Strings | `SEC-connection-string` | HIGH |
| Heroku API Key | `SEC-heroku-api-key` | HIGH |
| JWT Token | `SEC-jwt-token` | MEDIUM |
| Generic API Key/Secret | `SEC-generic-api-key` | MEDIUM |
| Hardcoded Password | `SEC-password-in-code` | MEDIUM |
| Google API Key | `SEC-google-api-key` | MEDIUM |
| Generic Secret/Token | `SEC-generic-secret` | LOW |

### Dependency Scanner

Parses `requirements.txt` (with basic Pipfile support) and checks package versions against the built-in vulnerability database (`data/vulndb.json`), which now contains **real CVE data** for all entries. The database covers 15 popular Python packages with accurate CVE IDs, severity ratings, and descriptions.

Use the `--online` flag to query the **OSV (Open Source Vulnerabilities) API** at `api.osv.dev` for comprehensive, up-to-date vulnerability data. This mode queries all discovered dependencies against the OSV database for the PyPI ecosystem, including CVSS scores, fixed version information, and GitHub Advisory Database severity ratings.

### Static Analysis Scanner

Detects insecure code patterns across `.py`, `.js`, `.ts`, `.php`, `.rb`, `.sh`, `.java`, `.go`, and more:

| Pattern | Rule ID | Severity |
|---------|---------|----------|
| `eval()` | `SAF-EVAL` | HIGH |
| `exec()` | `SAF-EXEC` | HIGH |
| `os.system()` / `os.popen()` | `SAF-OS-SYSTEM` / `SAF-OS-POPEN` | HIGH |
| Unsafe subprocess `shell=True` | `SAF-SUBPROCESS-SHELL` | HIGH |
| `pickle.load()` / `pickle.loads()` | `SAF-PICKLE` | HIGH |
| Unsafe `yaml.load()` | `SAF-YAML-LOAD` | HIGH |
| SQL injection | `SAF-SQL-INJECTION` | HIGH |
| `subprocess.call()` | `SAF-SUBPROCESS-CALL` | MEDIUM |
| `tempfile.mktemp()` | `SAF-TEMPFILE-MKTEMP` | MEDIUM |
| `marshal.load()` / `marshal.loads()` | `SAF-MARSHAL` | MEDIUM |
| Jinja2 template injection | `SAF-JINJA-TEMPLATE` | MEDIUM |
| Unsanitized request parameters | `SAF-REQUEST-PARAM` | LOW |
| `assert` usage | `SAF-ASSERT` | LOW |
| `shelve.open()` | `SAF-SHELVE` | LOW |

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
│   ├── models.py                   # Data models
│   ├── pipeline.py                 # Scanning pipeline orchestrator
│   ├── decision.py                 # Verdict decision engine
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py               # Scanner orchestration engine
│   │   ├── file_discovery.py       # File discovery with gitignore support
│   │   ├── secrets_scanner.py      # Regex-based secrets detection
│   │   ├── dependency_scanner.py   # Dependency vulnerability checker
│   │   ├── static_analysis.py      # Insecure code pattern detection
│   │   └── dast_scanner.py         # DAST web application scanner
│   └── formatters/
│       ├── __init__.py
│       ├── human.py                # Human-readable CLI output
│       ├── json_formatter.py       # Machine-readable JSON
│       └── sarif.py                # SARIF v2.1.0 output
├── data/
│   └── vulndb.json                 # Mock vulnerability database
├── scripts/
│   └── validate_sarif.py           # SARIF schema validation
├── tests/
│   ├── __init__.py
│   └── test_sarif_formatter.py     # 52 unit tests for SARIF output
├── test_servers/
│   └── vulnerable_server.py        # Intentionally vulnerable HTTP server for DAST testing
├── .github/workflows/
│   └── sentinel-scan.yml           # GitHub Actions workflow
├── test_repo/                      # Sample repo with vulnerabilities
├── CONTRIBUTING.md                 # Contribution guidelines
└── README.md                       # This file
```

## Roadmap

### v0.2
- [x] DAST module for OWASP Top 10 web application scanning
- [x] 21-phase inference-based vulnerability detection
- [x] CWE and OWASP category mapping
- [x] CRITICAL severity level
- [x] `dast` CLI subcommand with configurable options
- [x] Intentionally vulnerable test HTTP server
- [x] PyPI packaging (`pyproject.toml`, `requirements.txt`)

### v0.3 (Planned)
- [ ] Language-specific static analyzers (JavaScript/TypeScript, Go)
- [ ] Expanded vulnerability database with real CVE mappings
- [ ] `.env` file detection improvements
- [ ] Configurable rules (enable/disable individual rules by ID)
- [ ] `--diff` mode: scan only changed lines vs. a baseline

### v1.0 (Vision)
- [ ] Git history scanning (blame-aware findings)
- [ ] Custom rules DSL (define rules via YAML/JSON config files)
- [ ] Pre-commit hook support
- [ ] HTML report output
- [ ] Parallel file scanning for large repositories
- [ ] Comprehensive database of real CVEs for dependencies
- [ ] IDE plugin integrations (VS Code, JetBrains)
- [ ] Performance benchmarks and optimization
- [ ] More output formats (GitLab SAST, SonarQube)

*Sentinel is a community-driven project. The roadmap evolves based on contributor interest and user feedback. Open an issue or discussion to suggest priorities!*

## Limitations (v0.2)

- **Deterministic only** — No heuristic or ML-based detection
- **Regex-based secrets scanning** — May produce false positives and false negatives
- **DAST is inference-based** — Detects vulnerabilities through observation, not exploitation; may miss some issues
- **Mock vulnerability database** — Not a comprehensive CVE database; use for testing/demo
- **Fully offline** — No network calls by design
- **Limited language support** — Static analysis focuses primarily on Python patterns
- **Basic Pipfile support** — Pipfile parsing is simplified
- **Binary file scanning via `--all`** — Binary files can contain secrets, but snippets may appear garbled
  (use `--all` to scan binaries, but expect less readable output)

## Related Projects

- [**Semgrep**](https://semgrep.dev/) — Powerful static analysis with custom rules
- [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) — Secrets scanning with git history support
- [**Bandit**](https://github.com/PyCQA/bandit) — Python-focused security linter
- [**Safety**](https://github.com/pyupio/safety) — Python dependency vulnerability checker
- [**GitLeaks**](https://github.com/gitleaks/gitleaks) — Go-based secrets scanner

Sentinel differentiates itself by being:
- **Minimal dependencies** — Only 3 lightweight packages, no npm, no Docker
- **Fully deterministic** — Same input always produces the same output
- **Simple codebase** — Easy to understand, modify, and contribute to
- **Multi-format output** — Human, JSON, and SARIF out of the box

## License

[Apache License 2.0](LICENSE) — See [LICENSE](LICENSE) for the full license text.
