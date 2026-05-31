#!/usr/bin/env python3
"""Sentinel - Local security scanner for Git repositories.

Usage:
    python cli.py scan <path>                          Scan a repository for security issues
    python cli.py scan <path> --output json             Output results in JSON format
    python cli.py scan <path> --output json -o report.json  Write JSON report to file
    python cli.py scan <path> --output sarif            Output results in SARIF format
    python cli.py scan <path> --output sarif -o report.sarif Write SARIF report to file
    python cli.py scan <path> --output human            Force human-readable output
    python cli.py scan <path> --json                    Output results in JSON format (legacy)
    python cli.py scan <path> --json report.json        Write JSON report to file (legacy)
    python cli.py scan <path> --sarif                   Output results in SARIF format (legacy)
    python cli.py scan <path> --sarif report.sarif      Write SARIF report to file (legacy)
    python cli.py scan <path> --verbose                 Show detailed output
    python cli.py scan <path> --severity-threshold MEDIUM  Custom severity threshold
    python cli.py --version                             Show version information
    python cli.py --help                                Show this help message

This is a thin wrapper around `sentinel._cli` — all CLI logic lives in the
`sentinel` package so that `pip install sentinel-security` works properly.
"""

import sys

from sentinel._cli import (
    main,
    parse_severity,
    setup_argparse,
    validate_path,
    run_scan,
    run_dast,
)

if __name__ == "__main__":
    sys.exit(main())
