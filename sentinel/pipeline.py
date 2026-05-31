"""Scanning pipeline - orchestrates all scanners via the ScannerEngine.

The pipeline uses the ScannerEngine for parallel file discovery and scanning,
while maintaining backward compatibility with the existing CLI interface.

Architecture:
    scanner (CLI) → pipeline.scan_repository() → ScannerEngine
        ├── File Discovery (pathspec + gitignore)
        ├── Secrets Analyzer (regex + entropy)       [parallel]
        ├── AST Analyzer (ast module)                [parallel]
        ├── Dependency Analyzer (packaging + local DB)
        ├── Aggregator (dedup + normalization)
        └── ScanResult

DAST scanning:
    cli.py dast <url> → pipeline.scan_url()
        ├── HTTP Client (urllib, safe requests only)
        ├── Security Headers Analysis
        ├── TLS/Cryptography Assessment
        ├── CORS Configuration Check
        ├── Injection Reflection Detection
        ├── XSS Reflection Detection
        ├── Access Control Checks
        ├── Endpoint Discovery
        └── ScanResult
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .models import Finding, ScanResult, Severity
from .scanner import secrets_scanner, dependency_scanner, static_analysis
from .scanner.engine import scan_repository as engine_scan
from .scanner.dast_scanner import DASTConfig, scan_url as dast_scan_url


def scan_repository(
    repo_root: str,
    severity_threshold: Severity = Severity.HIGH,
    show_progress: bool = False,
    scan_all: bool = False,
    no_gitignore: bool = False,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
) -> ScanResult:
    """Run the complete SAST scanning pipeline using the ScannerEngine.

    Args:
        repo_root: Root path of the repository to scan.
        severity_threshold: Minimum severity to trigger BLOCK.
        show_progress: If True, display a progress bar.
        scan_all: If True, scan ALL files (ignore binary/source filtering).
        no_gitignore: If True, include .gitignored files in scan.
        exclude_patterns: Optional gitignore-style exclude patterns.
        include_patterns: Optional gitignore-style include patterns.

    Returns:
        A ScanResult containing all findings and metadata.
    """
    return engine_scan(
        repo_root=repo_root,
        severity_threshold=severity_threshold,
        show_progress=show_progress,
        scan_all=scan_all,
        no_gitignore=no_gitignore,
        exclude_patterns=exclude_patterns,
        include_patterns=include_patterns,
    )


def scan_url(
    target_url: str,
    severity_threshold: Severity = Severity.HIGH,
    config: Optional[DASTConfig] = None,
) -> ScanResult:
    """Run a DAST scan against a target URL.

    This function performs safe, passive dynamic application security testing
    against the specified HTTP(S) endpoint. No exploitation or destructive
    requests are made.

    Args:
        target_url: The URL to scan (e.g. 'https://example.com').
        severity_threshold: Minimum severity to trigger BLOCK.
        config: Optional DAST scanner configuration.

    Returns:
        A ScanResult containing all findings and metadata.
    """
    return dast_scan_url(
        target_url=target_url,
        severity_threshold=severity_threshold,
        config=config,
    )
