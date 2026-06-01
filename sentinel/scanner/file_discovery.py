"""File discovery - walks repositories with .gitignore-aware file traversal.

Uses the `pathspec` library to respect .gitignore rules, ensuring we
only scan files that would be tracked by git or are relevant for security scanning.
"""

from __future__ import annotations

import os
import pathspec
from typing import List, Optional, Set, Tuple


# Directories always excluded regardless of .gitignore
ALWAYS_EXCLUDE_DIRS: Set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".tox",
    ".eggs", "eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".cache", ".vscode", ".idea", ".vs",
    "dist", "build", "*.egg-info",
}

# Binary and irrelevant file extensions excluded by default
BINARY_EXTS: Set[str] = {
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".min.js", ".min.css",
    ".lock", ".sum", ".sig",
    ".br", ".wasm",
    ".o", ".obj", ".a", ".lib", ".class", ".jar", ".war",
}

# Source file extensions that get scanned for static analysis secrets
SOURCE_EXTS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".rb", ".pl", ".pm",
    ".sh", ".bash", ".zsh", ".ksh",
    ".java", ".go", ".rs", ".kt",
    ".c", ".cpp", ".h", ".hpp", ".cs",
    ".swift", ".scala", ".clj", ".cljs",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".json", ".xml", ".html", ".htm", ".env",
    ".sql", ".r", ".m", ".mm",
    ".gradle", ".sbt", ".ex",
    ".tf", ".tfvars",
    ".dockerfile", "dockerfile",
}

# All scannable text extensions (anything text-based can contain secrets)
TEXT_EXTS: Set[str] = SOURCE_EXTS | {
    ".txt", ".md", ".rst", ".cfg", ".properties",
    ".env.example", ".env.sample",
}


_DEFAULT_SPEC = pathspec.PathSpec.from_lines("gitignore", [])


def _load_gitignore(repo_root: str) -> pathspec.PathSpec:
    """Load .gitignore patterns from the repository root.

    Returns an empty PathSpec if no .gitignore exists.
    """
    gitignore_path = os.path.join(repo_root, ".gitignore")
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as f:
            spec = pathspec.PathSpec.from_lines("gitignore", f)
        return spec
    except (FileNotFoundError, IOError, OSError):
        return _DEFAULT_SPEC


def _load_pattern_spec(patterns: List[str]) -> pathspec.PathSpec:
    """Build a PathSpec from a list of gitignore-style patterns."""
    if not patterns:
        return _DEFAULT_SPEC
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def is_binary_file(file_path: str) -> bool:
    """Check if a file is likely binary by reading its first chunk.

    Reads up to 8192 bytes and looks for null bytes, which indicate binary content.
    Returns True for files that can't be read or are empty (no risk in skipping).
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
        if not chunk:
            return True
        # Check for null bytes (strong indicator of binary)
        return b"\x00" in chunk
    except (IOError, OSError):
        return True


def should_skip_by_name(file_path: str) -> bool:
    """Check if a file should be skipped based on its name and extension alone."""
    name = os.path.basename(file_path)
    if name in ALWAYS_EXCLUDE_DIRS:
        return True

    _, ext = os.path.splitext(name)
    if ext.lower() in BINARY_EXTS:
        return True

    return False


def discover_files(
    repo_root: str,
    include_dirs: bool = False,
    gitignore_aware: bool = True,
    scan_all: bool = False,
    include_gitignored: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
) -> List[str]:
    """Discover all scannable files in a repository.

    Args:
        repo_root: Root path of the repository.
        include_dirs: If True, also return discovered directories (for progress tracking).
        gitignore_aware: If True, respect .gitignore patterns (default: True).
        scan_all: If True, scan ALL files — no binary/source filtering, no dir skipping.
        include_gitignored: If True (default), include files even if they match .gitignore.
        exclude_patterns: Optional list of gitignore-style patterns to exclude.
        include_patterns: Optional list of gitignore-style patterns to include (only these).

    Returns:
        A list of file paths relative to repo_root that should be scanned.
    """
    # When scan_all is set, scan everything — no filtering
    if scan_all:
        return _discover_all_files(repo_root, include_dirs, exclude_patterns, include_patterns)

    # Build exclude/include specs
    exclude_spec = _load_pattern_spec(exclude_patterns or [])
    include_spec = _load_pattern_spec(include_patterns or [])
    has_include_patterns = bool(include_patterns)
    has_exclude_patterns = bool(exclude_patterns)

    should_check_gitignore = gitignore_aware and not include_gitignored
    gitignore_spec = _load_gitignore(repo_root) if should_check_gitignore else _DEFAULT_SPEC

    files: List[str] = []

    for root, dirs, filenames in os.walk(repo_root):
        # Build relative path for checking against gitignore
        rel_root = os.path.relpath(root, repo_root)
        if rel_root == ".":
            rel_root = ""

        # Filter directories: always exclude known dirs, and check gitignore
        filtered_dirs: List[str] = []
        for d in dirs:
            if d in ALWAYS_EXCLUDE_DIRS:
                continue
            if rel_root:
                dir_rel = os.path.join(rel_root, d)
            else:
                dir_rel = d
            if should_check_gitignore and gitignore_spec.match_file(dir_rel + "/"):
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs  # modify in-place for os.walk

        for filename in filenames:
            file_rel = os.path.join(rel_root, filename) if rel_root else filename

            # Apply exclude/include patterns (early check before I/O)
            if has_exclude_patterns and exclude_spec.match_file(file_rel):
                continue
            if has_include_patterns and not include_spec.match_file(file_rel):
                continue

            # Skip by name/extension
            if should_skip_by_name(filename):
                continue

            # Check gitignore
            if should_check_gitignore and gitignore_spec.match_file(file_rel):
                continue

            # Quick binary check by extension
            _, ext = os.path.splitext(filename)
            full_path = os.path.join(root, filename)
            if ext.lower() not in TEXT_EXTS:
                # For unknown extensions, do a binary content check
                if is_binary_file(full_path):
                    continue

            files.append(file_rel)

    return files


def _discover_all_files(
    repo_root: str,
    include_dirs: bool = False,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
) -> List[str]:
    """Discover ALL files in a repository with no filtering.

    Used by `--all` / `--scan-all` flag. Returns every file including
    binaries, dotfiles, node_modules, .git contents, etc.
    """
    exclude_spec = _load_pattern_spec(exclude_patterns or [])
    include_spec = _load_pattern_spec(include_patterns or [])
    has_include_patterns = bool(include_patterns)
    has_exclude_patterns = bool(exclude_patterns)

    files: List[str] = []

    for root, dirs, filenames in os.walk(repo_root):
        rel_root = os.path.relpath(root, repo_root)
        if rel_root == ".":
            rel_root = ""

        for filename in filenames:
            file_rel = os.path.join(rel_root, filename) if rel_root else filename

            # Apply exclude/include patterns
            if has_exclude_patterns and exclude_spec.match_file(file_rel):
                continue
            if has_include_patterns and not include_spec.match_file(file_rel):
                continue

            files.append(file_rel)

    return files


def count_files(
    repo_root: str,
    gitignore_aware: bool = True,
    scan_all: bool = False,
    include_gitignored: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
) -> int:
    """Quick count of scannable files without building the full list.

    Useful for progress bar initialization.
    """
    return len(discover_files(
        repo_root,
        gitignore_aware=gitignore_aware,
        scan_all=scan_all,
        include_gitignored=include_gitignored,
        exclude_patterns=exclude_patterns,
        include_patterns=include_patterns,
    ))
