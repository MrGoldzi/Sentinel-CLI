"""File discovery - walks repositories with .gitignore-aware file traversal.

Uses the `pathspec` library to respect .gitignore rules, ensuring we
only scan files that would be tracked by git or are relevant for security scanning.
"""

from __future__ import annotations

import os
import pathspec
from typing import List, Set, Tuple


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


def _load_gitignore(repo_root: str) -> pathspec.PathSpec:
    """Load .gitignore patterns from the repository root.

    Returns an empty PathSpec if no .gitignore exists.
    """
    gitignore_path = os.path.join(repo_root, ".gitignore")
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as f:
            spec = pathspec.PathSpec.from_lines("gitwildmatch", f)
        return spec
    except (FileNotFoundError, IOError, OSError):
        return pathspec.PathSpec.from_lines("gitwildmatch", [])


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
) -> List[str]:
    """Discover all scannable files in a repository.

    Args:
        repo_root: Root path of the repository.
        include_dirs: If True, also return discovered directories (for progress tracking).
        gitignore_aware: If True, respect .gitignore patterns (default: True).

    Returns:
        A list of file paths relative to repo_root that should be scanned.
    """
    gitignore_spec = _load_gitignore(repo_root) if gitignore_aware else pathspec.PathSpec.from_lines("gitwildmatch", [])

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
            if gitignore_aware and gitignore_spec.match_file(dir_rel + "/"):
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs  # modify in-place for os.walk

        for filename in filenames:
            file_rel = os.path.join(rel_root, filename) if rel_root else filename

            # Skip by name/extension
            if should_skip_by_name(filename):
                continue

            # Check gitignore
            if gitignore_aware and gitignore_spec.match_file(file_rel):
                continue

            # Quick binary check by extension
            _, ext = os.path.splitext(filename)
            if ext.lower() not in TEXT_EXTS:
                # For unknown extensions, do a binary content check
                full_path = os.path.join(root, filename)
                if is_binary_file(full_path):
                    continue

            files.append(file_rel)

    return files


def count_files(repo_root: str, gitignore_aware: bool = True) -> int:
    """Quick count of scannable files without building the full list.

    Useful for progress bar initialization.
    """
    return len(discover_files(repo_root, gitignore_aware=gitignore_aware))
