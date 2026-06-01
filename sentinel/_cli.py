"""Sentinel CLI implementation — all core logic lives here so it survives pip install.

This module contains the CLI argument parsing, command routing, and output functions.
Both the root `cli.py` and `sentinel/main.py` import from here.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from sentinel import __version__
from sentinel.models import Severity
from sentinel.formatters import human, json_formatter, sarif
from sentinel.pipeline import scan_repository, scan_url
from sentinel.scanner.dast_scanner import DASTConfig


def parse_severity(value: str) -> Severity:
    """Parse a severity string argument into a Severity enum value."""
    upper = value.upper().strip()
    if upper == "LOW":
        return Severity.LOW
    if upper == "MEDIUM":
        return Severity.MEDIUM
    if upper == "HIGH":
        return Severity.HIGH
    if upper == "CRITICAL":
        return Severity.CRITICAL
    raise argparse.ArgumentTypeError(
        f"Invalid severity: '{value}'. Choose from: LOW, MEDIUM, HIGH, CRITICAL"
    )


def setup_argparse() -> argparse.ArgumentParser:
    """Configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel - Local security scanner for Git repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  sentinel scan /path/to/repo                              Scan a repository
  sentinel scan .                                           Scan current directory
  sentinel scan /path/to/repo --output json                Output as JSON
  sentinel scan /path/to/repo --output json -o report.json Save JSON report
  sentinel scan /path/to/repo --output sarif               Output as SARIF
  sentinel scan /path/to/repo --output sarif -o report.sarif  Save SARIF report
  sentinel scan /path/to/repo --output human               Force human-readable output
  sentinel scan /path/to/repo --severity-threshold LOW     Stricter: any issue blocks
  sentinel scan /path/to/repo --severity-threshold MEDIUM  MEDIUM+ issues block
  sentinel scan /path/to/repo --all                        Scan ALL files (no filtering)
  sentinel scan /path/to/repo --no-gitignore               Include .gitignored files
  sentinel scan /path/to/repo --stats                      Show detailed statistics
  sentinel scan /path/to/repo --exclude "*.test.py,docs/*"  Skip files matching patterns
  sentinel scan /path/to/repo --include "*.py,*.js,*.yaml"  Only scan specific file types
  sentinel --version                                       Show version

Exit codes:
  0  PASS - No security issues found (or only LOW at default threshold)
  1  WARN - Medium severity issues found (or LOW with MEDIUM threshold)
  2  BLOCK - Issues at or above severity threshold detected
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"Sentinel v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    # Scan command (local repository SAST)
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a repository for security issues",
        description="Scan a local Git repository for security vulnerabilities, secrets, and insecure code patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exit codes:
  0  PASS - No security issues found (or only LOW at default threshold)
  1  WARN - Medium severity issues found (or LOW with MEDIUM threshold)
  2  BLOCK - Issues at or above severity threshold detected
        """,
    )
    scan_parser.add_argument(
        "path",
        type=str,
        help="Path to the repository to scan",
    )
    scan_parser.add_argument(
        "--output",
        type=str.lower,
        choices=["human", "json", "sarif"],
        default=None,
        help="Output format. Choices: human (default), json, sarif. Use --output-file to specify an output file.",
        metavar="{human,json,sarif}",
    )
    scan_parser.add_argument(
        "--output-file",
        "-o",
        type=str,
        default=None,
        help="Write output to the specified file path (used with --output json or --output sarif).",
        metavar="FILE",
    )
    scan_parser.add_argument(
        "--json",
        nargs="?",
        const="",
        default=None,
        help="[Legacy] Output results as JSON. Use --output json instead. Optionally specify a file path.",
        metavar="FILE",
    )
    scan_parser.add_argument(
        "--all",
        "--scan-all",
        action="store_true",
        dest="scan_all",
        help="Scan ALL files — no binary filtering, no dir skipping, no gitignore respect. Maximum coverage mode.",
    )
    scan_parser.add_argument(
        "--no-gitignore",
        action="store_true",
        dest="no_gitignore",
        help="Include .gitignored files in the scan (e.g., .env files, credential dumps)",
    )
    scan_parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed scan statistics: file type breakdown, per-scanner timing, findings by type",
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="Comma-separated gitignore-style patterns to exclude (e.g. '*.test.py,docsen/*')",
        metavar="PATTERNS",
    )
    scan_parser.add_argument(
        "--include",
        type=str,
        default=None,
        help="Comma-separated gitignore-style patterns to include (e.g. '*.py,*.js,*.yaml')",
        metavar="PATTERNS",
    )
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output including all file processing",
    )
    scan_parser.add_argument(
        "--sarif",
        nargs="?",
        const="",
        default=None,
        help="[Legacy] Output results in SARIF v2.1.0 format. Use --output sarif instead. Optionally specify a file path.",
        metavar="FILE",
    )
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use local vulnerability database instead of OSV API. Ideal for air-gapped environments or faster CI scans.",
    )
    scan_parser.add_argument(
        "--severity-threshold",
        type=parse_severity,
        default=Severity.HIGH,
        help="Minimum severity to trigger BLOCK. Findings below threshold trigger WARN (one tier) or PASS (two tiers). Choices: LOW, MEDIUM, HIGH (default: HIGH)",
        metavar="{LOW,MEDIUM,HIGH}",
    )

    # Dast command (remote HTTP DAST)
    dast_parser = subparsers.add_parser(
        "dast",
        help="Run a DAST scan against a web application",
        description="Run a deterministic Dynamic Application Security Testing (DAST) scan against a target HTTP(S) URL. "
                    "Performs passive, observational security analysis with no exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  sentinel dast https://example.com                          Run DAST scan on target
  sentinel dast https://example.com --output json            Output as JSON
  sentinel dast https://example.com --output sarif -o report.sarif  Save SARIF report
  sentinel dast https://example.com/ --headless              Skip admin endpoint discovery
  sentinel dast https://example.com --no-injection           Skip injection checks
  sentinel dast https://example.com --no-xss                 Skip XSS checks
  sentinel dast https://example.com --severity-threshold MEDIUM  Stricter threshold

OWASP Coverage:
  A01:2021 - Broken Access Control (IDOR, privilege escalation)
  A02:2021 - Cryptographic Failures (TLS, HSTS, cookies)
  A03:2021 - Injection (SQL, NoSQL, OS command, XSS, SSTI)
  A04:2021 - Insecure Design (rate limiting, logic flaws)
  A05:2021 - Security Misconfiguration (headers, CORS, errors)
  A07:2021 - Authentication Failures (user enumeration)
  A10:2021 - Server-Side Request Forgery
        """,
    )
    dast_parser.add_argument(
        "url",
        type=str,
        help="Target URL to scan (e.g. https://example.com)",
    )
    dast_parser.add_argument(
        "--output",
        type=str.lower,
        choices=["human", "json", "sarif"],
        default=None,
        help="Output format. Choices: human (default), json, sarif. Use --output-file to specify an output file.",
        metavar="{human,json,sarif}",
    )
    dast_parser.add_argument(
        "--output-file",
        "-o",
        type=str,
        default=None,
        help="Write output to the specified file path (used with --output json or --output sarif).",
        metavar="FILE",
    )
    dast_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output during scanning",
    )
    dast_parser.add_argument(
        "--severity-threshold",
        type=parse_severity,
        default=Severity.HIGH,
        help="Minimum severity to trigger BLOCK. Choices: LOW, MEDIUM, HIGH (default: HIGH)",
        metavar="{LOW,MEDIUM,HIGH}",
    )
    dast_parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
        metavar="SECONDS",
    )
    dast_parser.add_argument(
        "--no-injection",
        action="store_true",
        help="Skip injection reflection checks (SQL, NoSQL, command, LDAP, XPath)",
    )
    dast_parser.add_argument(
        "--no-xss",
        action="store_true",
        help="Skip XSS reflection checks",
    )
    dast_parser.add_argument(
        "--headless",
        action="store_true",
        help="Skip admin endpoint discovery (quicker scan)",
    )
    dast_parser.add_argument(
        "--max-endpoints",
        type=int,
        default=30,
        help="Maximum number of endpoints to probe (default: 30)",
        metavar="COUNT",
    )

    return parser


def validate_path(path: str) -> str:
    """Validate and resolve the repository path."""
    resolved = os.path.abspath(os.path.expanduser(path))

    if not os.path.exists(resolved):
        print(f"Error: Path '{path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(resolved):
        print(f"Error: Path '{path}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    return resolved


def run_scan(args: argparse.Namespace) -> int:
    """Execute the scan command and return the exit code."""
    repo_path = validate_path(args.path)
    verbose = args.verbose
    threshold = args.severity_threshold

    # Parse scanning options
    scan_all = getattr(args, 'scan_all', False)
    no_gitignore = getattr(args, 'no_gitignore', False)
    show_stats = getattr(args, 'stats', False)
    exclude_patterns = _parse_pattern_list(getattr(args, 'exclude', None))
    include_patterns = _parse_pattern_list(getattr(args, 'include', None))

    # Determine output mode: --output takes priority over legacy --json/--sarif
    is_legacy_json = args.json is not None
    is_legacy_sarif = args.sarif is not None
    legacy_json_file = args.json if args.json and args.json.strip() else None
    legacy_sarif_file = args.sarif if args.sarif and args.sarif.strip() else None

    if args.output is not None:
        # Unified --output mode
        output_format = args.output
        output_file = args.output_file

        if is_legacy_json or is_legacy_sarif:
            print("Note: --output takes precedence over --json/--sarif.", file=sys.stderr)

        # --output-file doesn't make sense for human output
        if output_format == "human" and output_file:
            print("Warning: --output-file ignored for human output format.", file=sys.stderr)
            output_file = None
    else:
        # Legacy --json/--sarif mode (or default human)
        if is_legacy_json and is_legacy_sarif:
            print("Warning: Both --json and --sarif specified. Using --sarif.", file=sys.stderr)
            is_legacy_json = False

        if is_legacy_sarif:
            output_format = "sarif"
            output_file = legacy_sarif_file
        elif is_legacy_json:
            output_format = "json"
            output_file = legacy_json_file
        else:
            output_format = "human"
            output_file = args.output_file

    # Parse --offline flag
    offline = getattr(args, 'offline', False)

    # Print scan header (only for human output to stdout)
    if output_format == "human" and not output_file:
        print(f"\n🔍 Sentinel v{__version__} - Scanning: {repo_path}")
        print(f"   Threshold: {threshold.value}")
        if offline:
            print(f"   Database:   Local (offline)")
        if scan_all:
            print(f"   Mode:       FULL SCAN (all files)")
        elif no_gitignore:
            print(f"   Mode:       Including .gitignored files")
        if exclude_patterns:
            print(f"   Exclude:    {','.join(exclude_patterns)}")
        if include_patterns:
            print(f"   Include:    {','.join(include_patterns)}")
        print(f"   This may take a moment...\n")

    # Run the scanning pipeline
    try:
        result = scan_repository(
            repo_path,
            scan_all=scan_all,
            no_gitignore=no_gitignore,
            exclude_patterns=exclude_patterns,
            include_patterns=include_patterns,
            offline=offline,
        )
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    # Apply severity threshold
    result.severity_threshold = threshold

    verdict = result.get_verdict()
    exit_code = verdict.exit_code

    # Output results
    if output_format == "sarif":
        formatted = sarif.format_scan_result(result)
        _write_output(formatted, output_file, "SARIF")
    elif output_format == "json":
        formatted = json_formatter.format_scan_result(result)
        _write_output(formatted, output_file, "JSON")
    else:
        # Human-readable
        formatted = human.format_scan_result(result, show_stats=show_stats)
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(formatted)
                print(f"Report written to: {output_file}")
            except (IOError, OSError) as e:
                print(f"Error writing report: {e}", file=sys.stderr)
                print(formatted)
        else:
            print(formatted)

    return exit_code


def _parse_pattern_list(value: str | None) -> List[str]:
    """Parse a comma-separated list of patterns from a CLI argument."""
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def _write_output(content: str, file_path: str | None, format_name: str) -> None:
    """Write formatted output to a file or stdout."""
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"{format_name} report written to: {file_path}")
        except (IOError, OSError) as e:
            print(f"Error writing {format_name} report: {e}", file=sys.stderr)
            # Fall back to stdout
            print(content)
    else:
        print(content)


def run_dast(args: argparse.Namespace) -> int:
    """Execute the DAST scan command and return the exit code."""
    target_url = args.url.rstrip("/")
    threshold = args.severity_threshold

    # Build DAST config
    dast_config = DASTConfig(
        timeout=args.timeout,
        max_endpoints=args.max_endpoints,
        check_injection=not args.no_injection,
        check_xss=not args.no_xss,
        check_admin_endpoints=not args.headless,
    )

    # Print scan header
    if args.verbose:
        print(f"\n🔍 Sentinel v{__version__} - DAST Scan: {target_url}")
        print(f"   Threshold: {threshold.value}")
        print(f"   Timeout: {args.timeout}s")
        print(f"   Max endpoints: {args.max_endpoints}")
        print(f"   Injection checks: {'ON' if dast_config.check_injection else 'OFF'}")
        print(f"   XSS checks: {'ON' if dast_config.check_xss else 'OFF'}")
        print(f"   Endpoint discovery: {'ON' if dast_config.check_admin_endpoints else 'OFF'}")
        print()
    else:
        print(f"\n🔍 Sentinel v{__version__} - DAST Scanning: {target_url}")
        print(f"   This may take a moment...\n")

    # Run the DAST scan
    try:
        result = scan_url(
            target_url=target_url,
            severity_threshold=threshold,
            config=dast_config,
        )
    except Exception as e:
        print(f"Error during DAST scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    verdict = result.get_verdict()
    exit_code = verdict.exit_code

    # Determine output format
    output_format = args.output or "human"
    output_file = args.output_file

    # Output results
    if output_format == "sarif":
        formatted = sarif.format_scan_result(result)
        _write_output(formatted, output_file, "SARIF")
    elif output_format == "json":
        formatted = json_formatter.format_scan_result(result)
        _write_output(formatted, output_file, "JSON")
    else:
        formatted = human.format_scan_result(result)
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(formatted)
                print(f"Report written to: {output_file}")
            except (IOError, OSError) as e:
                print(f"Error writing report: {e}", file=sys.stderr)
                print(formatted)
        else:
            print(formatted)

    return exit_code


def main() -> int:
    """Main entry point for the CLI."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "dast":
        return run_dast(args)

    return 0
