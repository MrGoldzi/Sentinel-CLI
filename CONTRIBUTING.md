# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel! We welcome contributions of all kinds — bug reports, feature requests, documentation improvements, and code changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Development Setup](#development-setup)
  - [Project Layout](#project-layout)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Guidelines](#development-guidelines)
  - [Code Style](#code-style)
  - [Adding a New Scanner](#adding-a-new-scanner)
  - [Adding Custom Rules](#adding-custom-rules)
  - [Testing](#testing)
  - [Output Formats](#output-formats)
- [Release Process](#release-process)

## Code of Conduct

This project is committed to providing a welcoming and inclusive experience for everyone.
Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) — we expect all
contributors to adhere to it.

All contributors are expected to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

Unacceptable behavior will not be tolerated and may result in temporary or permanent
exclusion from the project. Reports should be filed via GitHub Issues (not security-related) or via the security advisory process for vulnerabilities.

Read the full text in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Getting Started

### Development Setup

Sentinel requires **Python 3.8+** and has only **3 lightweight runtime dependencies** (pathspec, packaging, tqdm).

```bash
# Clone the repository
git clone https://github.com/your-org/sentinel.git
cd sentinel

# Create a virtual environment for development
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tests to verify your setup
python -m unittest discover tests -v

# Test with the included test repository
python cli.py scan test_repo

# Validate SARIF output against the official schema
python cli.py scan test_repo --output sarif -o /tmp/sarif_out.json
python scripts/validate_sarif.py /tmp/sarif_out.json
```

### Project Layout

```
sentinel/
├── cli.py                          # CLI entry point
├── sentinel/
│   ├── __init__.py                 # Package init, version info
│   ├── models.py                   # Data models (Finding, Severity, Verdict, ScanResult)
│   ├── pipeline.py                 # Central scanning pipeline
│   ├── decision.py                 # Decision engine (verdict logic)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── secrets_scanner.py      # Regex-based secrets detection
│   │   ├── dependency_scanner.py   # Dependency vulnerability checker
│   │   └── static_analysis.py      # Insecure code pattern detection
│   └── formatters/
│       ├── __init__.py
│       ├── human.py                # Human-readable CLI output
│       ├── json_formatter.py       # Machine-readable JSON output
│       └── sarif.py                # SARIF v2.1.0 output
├── data/
│   └── vulndb.json                 # Built-in mock vulnerability database
├── scripts/
│   └── validate_sarif.py           # SARIF schema validation utility
├── tests/
│   ├── __init__.py
│   └── test_sarif_formatter.py     # SARIF output formatter tests
├── .github/
│   └── workflows/
│       └── sentinel-scan.yml       # GitHub Actions workflow
├── test_repo/                      # Sample repo with intentional vulnerabilities
├── CONTRIBUTING.md
└── README.md
```

## How to Contribute

### Reporting Bugs

Before reporting a bug, please:

1. Check the [existing issues](https://github.com/your-org/sentinel/issues) to see if it's already been reported
2. Try the latest version to see if the bug has already been fixed

When filing a bug report, include:

- **A clear, descriptive title**
- **Steps to reproduce** — include the exact command and repository structure
- **Expected behavior** and **actual behavior**
- **Environment details** — OS, Python version, Sentinel version (`python cli.py --version`)
- **Sample output** — paste the relevant console output or SARIF/JSON file
- **Minimal reproduction** — if possible, create a minimal test case

### Suggesting Features

Feature suggestions are welcome! When suggesting a feature:

1. **Describe the problem** you're trying to solve, not just the solution
2. **Explain why** it would benefit the project
3. **Consider the scope** — does it fit Sentinel's philosophy of being local-first, deterministic, and dependency-free?
4. **Include examples** of how the feature would work

### Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Use descriptive branch names** — e.g., `feat/add-ruby-scanner`, `fix/sarif-schema-uri`, `docs/improve-readme`
3. **Follow the [development guidelines](#development-guidelines)**
4. **Write or update tests** for your changes
5. **Run the full test suite** to ensure nothing is broken
6. **Keep changes focused** — one pull request per feature or bug fix
7. **Write a clear PR description** explaining what and why

#### PR Checklist

Before submitting, ensure:

- [ ] Tests pass (`python -m unittest discover tests -v`)
- [ ] For new scanners: tested against `test_repo` or a sample repository
- [ ] For output format changes: validated against the official SARIF schema (`python scripts/validate_sarif.py <file>`)
- [ ] No new external runtime dependencies added (Sentinel uses only 3 packages: pathspec, packaging, tqdm)
- [ ] Code follows existing style and patterns
- [ ] README updated if user-facing behavior changed
- [ ] No `print()` debugging statements left behind

## Development Guidelines

### Code Style

- **Python 3.8+** — use `from __future__ import annotations` in new files
- **Follow existing patterns** — the codebase is small; read similar files before writing new ones
- **Type hints** — annotate all function signatures and public methods
- **Docstrings** — use Google-style docstrings for public functions
- **Minimal external dependencies** — use only pathspec, packaging, tqdm (keep it lean)
- **Error handling** — use `try`/`except` with specific exception types, not bare `except:`
- **File naming** — use `snake_case.py` without abbreviations (e.g., `json_formatter.py` not `json_fmt.py`)

```python
# Example style
from __future__ import annotations

from typing import List, Optional


def scan_file(file_path: str, patterns: List[Pattern]) -> List[Finding]:
    \"\"\"Scan a single file for matching patterns.

    Args:
        file_path: Path to the file to scan.
        patterns: List of compiled regex patterns to match.

    Returns:
        A list of findings for matched patterns.
    \"\"\"
    ...
```

### Adding a New Scanner

1. Create `sentinel/scanner/<your_scanner>.py`
2. Define an `EXCLUDE_DIRS` set and `EXCLUDE_EXTS` set for files to skip
3. Implement a `scan(repo_root: str) -> List[Finding]` function
4. Register the scanner in `sentinel/pipeline.py` by importing it and calling it in `scan_repository()`
5. Add tests in `tests/`
6. Test against `test_repo/` or create sample files there

```python
# sentinel/scanner/example_scanner.py
\"\"\"Example scanner template.\"\"\"

from __future__ import annotations

from typing import List, Set

from ..models import Finding, Severity


EXCLUDE_DIRS: Set[str] = {".git", "__pycache__", "node_modules"}
EXCLUDE_EXTS: Set[str] = {".pyc", ".png", ".jpg", ".svg"}


def scan(repo_root: str) -> List[Finding]:
    \"\"\"Scan a repository for example security issues.\"\"\"
    findings: List[Finding] = []
    # ... scanning logic ...
    return findings
```

### Adding Custom Rules

**Secrets Scanner** — add to the `SECRET_PATTERNS` list in `sentinel/scanner/secrets_scanner.py`:

```python
{
    "name": "my-custom-secret",
    "pattern": re.compile(r"(?i)my_secret_key\s*[:=]\s*['\"]([^'\"]+)['\"]"),
    "severity": Severity.HIGH,
    "message": "Custom secret detected.",
    "confidence": 0.9,
},
```

**Static Analysis** — add to the `UNSAFE_PATTERNS` list in `sentinel/scanner/static_analysis.py`.

**Dependency Database** — edit `data/vulndb.json`.

### Testing

- **Framework**: Python's built-in `unittest` module (no pytest needed)
- **Location**: `tests/test_<module_name>.py`
- **Run tests**: `python -m unittest discover tests -v`
- **Run a single test file**: `python -m unittest tests.test_sarif_formatter -v`

#### Test Guidelines

- Test the public API (e.g., `format_scan_result()`, `write_sarif_report()`)
- Test edge cases: empty results, mixed severities, long messages, missing snippets
- Use `tempfile.mkdtemp()` for file I/O tests and clean up in `tearDown()`
- Avoid testing internal implementation details when possible
- Name tests descriptively: `test_empty_findings`, `test_high_severity_maps_to_error`

### Output Formats

Sentinel supports three output formats:

| Format | Module | Use Case |
|--------|--------|----------|
| Human | `sentinel.formatters.human` | CLI terminal output |
| JSON | `sentinel.formatters.json_formatter` | Machine parsing, CI pipelines |
| SARIF | `sentinel.formatters.sarif` | GitHub Advanced Security integration |

When adding fields to any output format:

1. Update the relevant formatter module
2. If adding to the data model, update all three formatters
3. Update `ScanResult.to_dict()` and `Finding.to_dict()` in `models.py`
4. Add or update tests
5. Update the README examples

## Release Process

1. Update `__version__` in `sentinel/__init__.py` (semantic versioning)
2. Update the version in `README.md` examples if needed
3. Run the full test suite: `python -m unittest discover tests -v`
4. Validate SARIF output against the official schema:
   ```bash
   python cli.py scan test_repo --output sarif -o /tmp/sarif_out.json
   python scripts/validate_sarif.py /tmp/sarif_out.json
   ```
5. Tag the release: `git tag v<version> && git push origin v<version>`
6. Create a GitHub Release with release notes summarizing changes

---

**Questions?** Open a [discussion](https://github.com/your-org/sentinel/discussions) or reach out to the maintainers.
