"""Scanner engine - orchestrates the full scanning pipeline.

Architecture:
    ScannerEngine
     ├── File Discovery (pathspec + gitignore)
     ├── Secrets Analyzer (regex + entropy)
     ├── AST Analyzer (ast module)
     ├── Dependency Analyzer (packaging + local CVE DB)
     ├── Aggregator (dedup + normalization)
     ├── Decision Engine (PASS/WARN/BLOCK)
     └── Output Formatter (CLI + JSON)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
from typing import Callable, Dict, List, Optional, Tuple

from tqdm import tqdm

from ..models import Finding, ScanResult, Severity
from . import secrets_scanner, static_analysis, dependency_scanner
from .file_discovery import discover_files


# Maximum number of worker threads for parallel scanning
MAX_WORKERS = 4

# Minimum file count to trigger parallel scanning
PARALLEL_THRESHOLD = 10


def _scan_secrets_batch(
    file_paths: List[Tuple[str, str]],
    repo_root: str,
) -> List[Finding]:
    """Scan a batch of files for secrets."""
    findings: List[Finding] = []
    for rel_path, full_path in file_paths:
        try:
            findings.extend(secrets_scanner.scan_file(full_path, repo_root))
        except (IOError, OSError, UnicodeDecodeError, ValueError):
            continue
    return findings


def _scan_static_analysis_batch(
    file_paths: List[Tuple[str, str]],
    repo_root: str,
) -> List[Finding]:
    """Scan a batch of files for static analysis issues."""
    findings: List[Finding] = []
    for rel_path, full_path in file_paths:
        try:
            findings.extend(static_analysis.scan_file(full_path, repo_root))
        except (IOError, OSError, UnicodeDecodeError, ValueError):
            continue
    return findings


def scan_repository(
    repo_root: str,
    severity_threshold: Severity = Severity.HIGH,
    show_progress: bool = True,
    scan_all: bool = False,
    no_gitignore: bool = False,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
    offline: bool = False,
) -> ScanResult:
    """Run the complete scanning pipeline with parallel execution.

    Args:
        repo_root: Root path of the repository to scan.
        severity_threshold: Minimum severity to trigger BLOCK.
        show_progress: If True, display a progress bar (requires tqdm).
        scan_all: If True, scan ALL files (ignore binary/source filtering).
        no_gitignore: If True, include .gitignored files in scan.
        exclude_patterns: Optional gitignore-style exclude patterns.
        include_patterns: Optional gitignore-style include patterns.
        offline: If True, use local vulndb instead of OSV API for dependency checks.

    Returns:
        A ScanResult containing all findings and metadata.
    """
    start_time = time.time()
    scanner_times: Dict[str, float] = {}

    # ─── File Discovery ─────────────────────────────────────────────────
    t0 = time.time()
    gitignore_aware = not no_gitignore
    files = discover_files(
        repo_root,
        gitignore_aware=gitignore_aware,
        scan_all=scan_all,
        include_gitignored=no_gitignore,
        exclude_patterns=exclude_patterns,
        include_patterns=include_patterns,
    )
    scanner_times["file_discovery"] = (time.time() - t0) * 1000

    all_file_paths: List[Tuple[str, str]] = [
        (f, os.path.join(repo_root, f)) for f in files
    ]

    # ─── Collect file extension stats ─────────────────────────────────
    files_by_ext: Dict[str, int] = {}
    for rel_path in files:
        _, ext = os.path.splitext(rel_path)
        ext_key = ext.lower() if ext else "(no ext)"
        files_by_ext[ext_key] = files_by_ext.get(ext_key, 0) + 1

    # ─── Dependency Scan (fast, runs first) ────────────────────────────
    t0 = time.time()
    dep_findings: List[Finding] = []
    try:
        dep_findings = dependency_scanner.scan(repo_root, offline=offline)
    except (IOError, OSError, json.JSONDecodeError, ValueError):
        dep_findings = []
    except Exception:
        dep_findings = []
    scanner_times["dependency_scan"] = (time.time() - t0) * 1000

    # ├── Determine which files to scan for secrets and static analysis
    # When scan_all is True, scan every discovered file
    if scan_all:
        source_files = all_file_paths
    else:
        source_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".pl", ".pm",
            ".sh", ".bash", ".zsh", ".ksh", ".java", ".go", ".rs", ".kt",
            ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".scala", ".clj",
            ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
            ".json", ".xml", ".html", ".htm", ".env", ".sql",
            ".tf", ".tfvars", ".gradle", ".sbt",
            ".txt", ".md", ".rst", ".properties",
            ".env.example", ".env.sample",
        }
        source_files: List[Tuple[str, str]] = []
        for rel_path, full_path in all_file_paths:
            _, ext = os.path.splitext(rel_path)
            if ext.lower() in source_exts:
                source_files.append((rel_path, full_path))

    # ├── Run secrets and static analysis in parallel ──────────────────
    secret_findings: List[Finding] = []
    static_findings: List[Finding] = []

    total_scan_files = len(source_files)

    if not source_files:
        # No source files to scan
        pass
    elif total_scan_files >= PARALLEL_THRESHOLD and MAX_WORKERS > 1:
        # Parallel mode: split into batches
        batch_size = max(1, total_scan_files // MAX_WORKERS)
        batches: List[List[Tuple[str, str]]] = []
        for i in range(0, total_scan_files, batch_size):
            batches.append(source_files[i:i + batch_size])

        secrets_futures: List[concurrent.futures.Future] = []
        static_futures: List[concurrent.futures.Future] = []

        t_scan_start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for batch in batches:
                # Submit secrets scan
                secrets_futures.append(
                    executor.submit(_scan_secrets_batch, batch, repo_root)
                )
                # Submit static analysis scan
                static_futures.append(
                    executor.submit(_scan_static_analysis_batch, batch, repo_root)
                )

            # Collect results with progress bar
            if show_progress:
                all_futures = secrets_futures + static_futures
                with tqdm(total=len(all_futures), desc="Scanning", unit="batch", leave=False) as pbar:
                    for future in concurrent.futures.as_completed(all_futures):
                        try:
                            result = future.result()
                            # Categorize result
                            if future in secrets_futures:
                                secret_findings.extend(result)
                            else:
                                static_findings.extend(result)
                        except (IOError, OSError, ValueError, TypeError):
                            pass
                        pbar.update(1)
            else:
                for future in concurrent.futures.as_completed(secrets_futures):
                    try:
                        secret_findings.extend(future.result())
                    except (IOError, OSError, ValueError, TypeError):
                        pass
                for future in concurrent.futures.as_completed(static_futures):
                    try:
                        static_findings.extend(future.result())
                    except (IOError, OSError, ValueError, TypeError):
                        pass
        scanner_times["parallel_scan"] = (time.time() - t_scan_start) * 1000
    else:
        # Sequential mode (few files or single-threaded)
        t_scan_start = time.time()
        if show_progress:
            file_iter = tqdm(source_files, desc="Scanning", unit="file", leave=False)
        else:
            file_iter = source_files  # type: ignore

        for rel_path, full_path in file_iter:  # type: ignore
            try:
                secret_findings.extend(secrets_scanner.scan_file(full_path, repo_root))
                static_findings.extend(static_analysis.scan_file(full_path, repo_root))
            except (IOError, OSError, UnicodeDecodeError, ValueError):
                continue
        scanner_times["sequential_scan"] = (time.time() - t_scan_start) * 1000

    # ─── Aggregator: dedup + normalize ─────────────────────────────────
    all_findings: List[Finding] = []
    all_findings.extend(secret_findings)
    all_findings.extend(static_findings)
    all_findings.extend(dep_findings)

    result = ScanResult(
        findings=all_findings,
        scanned_files=total_scan_files,
        severity_threshold=severity_threshold,
        files_by_extension=files_by_ext,
        scanner_times_ms=scanner_times,
        scan_all=scan_all,
        no_gitignore=no_gitignore,
        exclude_patterns=exclude_patterns or [],
        include_patterns=include_patterns or [],
    )

    result.deduplicate()
    result.scan_time_ms = (time.time() - start_time) * 1000

    return result
