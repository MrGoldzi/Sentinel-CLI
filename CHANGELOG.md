# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Sentinel logo icon to README header
- Documentation updates to match v0.3.0 implementation (DAST 29 phases, 70+ static patterns, 40+ secrets patterns, CRITICAL threshold)

## [0.3.0] — 2026-06-01

### Added

- **Multi-ecosystem dependency scanning** — Auto-detects and parses 8 package ecosystems:
  - PyPI (`requirements.txt`, `Pipfile`, `Pipfile.lock`)
  - npm (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
  - Maven (`pom.xml`, `build.gradle`, `build.gradle.kts`)
  - Go (`go.mod`, `go.sum`)
  - crates.io / Rust (`Cargo.toml`, `Cargo.lock`)
  - RubyGems (`Gemfile`, `Gemfile.lock`)
  - Packagist / PHP (`composer.json`, `composer.lock`)
  - NuGet / .NET (`packages.config`, `*.csproj`)
- **OSV API as default** — Queries the Google-maintained OSV.dev database by default
  for comprehensive, real-time vulnerability data from GHSA, PyPA, RustSec, Go vulndb,
  npm advisories, OSS-Fuzz, and more
- **OSV batch querying** — Uses the OSV `/v1/querybatch` endpoint for efficient
  multi-package vulnerability checks
- **`--offline` flag** — Opt-in offline mode using the built-in local vulnerability
  database. Ideal for air-gapped environments or ultra-fast CI runs

### Changed

- **BREAKING**: `--online` flag removed. OSV API is now the default. Use `--offline` for
  local-only mode
- **BREAKING**: `scan()` / `scan_repository()` parameter renamed from `online` to `offline`
- `dependency_scanner.scan()` now returns ecosystem-tagged findings (e.g. `[PyPI]` prefix)
- Version bumped from 0.2.0 → 0.3.0

### Removed

- `--online` CLI flag (replaced by `--offline`)

## [0.2.0] — 2026-05-31

### Added

- DAST scanner module — 21-phase deterministic web application security scanning covering OWASP Top 10
  - Security headers assessment (HSTS, CSP, X-Frame-Options, etc.)
  - Cookie security analysis (Secure, HttpOnly, SameSite flags)
  - CORS misconfiguration detection
  - TLS/HTTPS assessment with version negotiation
  - Server information disclosure checks
  - Injection reflection detection (SQL, NoSQL, command, LDAP, XPath, SSTI)
  - XSS reflection detection
  - SSTI evaluation detection (Jinja2/Twig/Handlebars)
  - Directory & endpoint enumeration
  - Verbose error message detection
  - Directory listing detection
  - Authentication checks & user enumeration
  - Access control / IDOR testing
  - Open redirect detection
  - ReDoS pattern detection
  - XXE & insecure deserialization indicators
  - JWT misconfiguration analysis
  - Rate limiting assessment
  - Cloud metadata endpoint exposure
  - SSRF indicator detection
- `dast` CLI subcommand with configurable options (`--timeout`, `--no-injection`, `--no-xss`, `--headless`, `--max-endpoints`)
- CWE and OWASP category mapping on all findings
- `CRITICAL` severity level
- Test vulnerable HTTP server at `test_servers/vulnerable_server.py`
- `scan_url()` pipeline entry point for DAST scans
- `cwe_id`, `owasp_category`, `endpoint`, `evidence` fields on `Finding` model
- `scanned_endpoints` field on `ScanResult`

### Changed

- Version bumped from 0.1.0 → 0.2.0
- Decision engine supports CRITICAL severity in verdict computation
- SARIF formatter maps CRITICAL → `"error"` level
- Human formatter displays CRITICAL severity as bold red
- CLI help text updated for both `scan` and `dast` commands

### Fixed

- Removed duplicate `to_dict()` method on `ScanResult` (second definition was silently dropping `scanned_endpoints` and `target_url`)
- Removed duplicate shebang in `cli.py`

## [0.1.0] — 2026-05-01

### Added

- Initial SAST security scanner for Git repositories
- Secrets scanner — regex-based detection of 40+ secret patterns (API keys, tokens, AWS credentials, etc.)
- Dependency scanner — `requirements.txt` parsing with built-in vulnerability database
- Static analysis scanner — 30+ insecure code pattern rules across 9+ languages
- Decision engine — PASS/WARN/BLOCK verdict with configurable severity thresholds
- Three output formats: human-readable, JSON, SARIF v2.1.0
- `scan` CLI subcommand with legacy `--json`/`--sarif` flags
- SARIF output validated against official OASIS v2.1.0 schema
- 52 unit tests for SARIF formatter
- GitHub Actions CI/CD workflow
- Sample test repository (`test_repo/`) with intentional vulnerabilities
- Mock vulnerability database (`data/vulndb.json`)
- SARIF validation script (`scripts/validate_sarif.py`)
