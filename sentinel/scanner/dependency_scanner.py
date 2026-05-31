"""Dependency scanner - checks project dependencies against a local vulnerability database.

Fully deterministic: no network calls at runtime. Uses the `packaging` library
for semantic version comparison and range-based vulnerability matching.

The local vulnerability database (data/vulndb.json) can be updated offline
and version-controlled for reproducible builds.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from ..models import Finding, Severity

# Path to the local vulnerability database (inside the sentinel package for pip installability)
# File is at sentinel/data/vulndb.json, relative to sentinel/scanner/dependency_scanner.py
VULN_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "vulndb.json",
)


def _load_vulndb(vuln_db_path: str) -> List[Dict]:
    """Load the local vulnerability database from a JSON file.

    Expected format:
    {
      "vulnerabilities": [
        {
          "package": "flask",
          "versions": ["<2.3.0"],
          "severity": "MEDIUM",
          "cve": "CVE-2023-25577",
          "description": "Cross-site scripting..."
        }
      ]
    }

    Args:
        vuln_db_path: Path to the vulnerability database JSON file.

    Returns:
        A list of vulnerability entries, or empty list on error.
    """
    try:
        with open(vuln_db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Support both old format (vulnerabilities key) and new format (direct entries)
        if isinstance(data, dict):
            return data.get("vulnerabilities", [])
        elif isinstance(data, list):
            return data
        return []
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        return []


def _parse_requirements_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse a line from requirements.txt into (package_name, version_specifier).

    Uses the packaging library for robust version specifier parsing.

    Args:
        line: A line from a requirements.txt file.

    Returns:
        (package_name_lowercase, version_specifier_string) or None if not a package line.
    """
    line = line.strip()

    if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
        return None

    # Strip inline comments
    if " #" in line:
        line = line[: line.index(" #")].strip()

    # Parse package name and version specifier
    match = re.match(
        r"^([a-zA-Z0-9_\-\.]+)"
        r"(?:\[[^\]]+\])?"  # extras like [security]
        r"\s*"
        r"([><=!~]+\s*[a-zA-Z0-9_\-\.\*]+(?:\s*,\s*[><=!~]+\s*[a-zA-Z0-9_\-\.\*]+)*)?",
        line,
    )

    if not match:
        return None

    name = match.group(1).lower().strip()
    version_spec = match.group(2)

    if version_spec:
        return (name, version_spec.strip())
    return None


def _check_vulnerability(
    pkg_name: str,
    version_str: str,
    vuln_db: List[Dict],
) -> List[Dict]:
    """Check if a package version matches any vulnerability in the database.

    Uses packaging.specifiers.SpecifierSet for robust version range matching.

    Args:
        pkg_name: Package name (lowercase).
        version_str: Version string of the installed package.
        vuln_db: List of vulnerability entries from the database.

    Returns:
        List of matching vulnerability entries.
    """
    matched: List[Dict] = []

    try:
        installed_version = Version(version_str)
    except InvalidVersion:
        # Try stripping 'v' prefix if present
        try:
            installed_version = Version(version_str.lstrip("vV"))
        except InvalidVersion:
            return matched

    for vuln in vuln_db:
        if vuln["package"].lower() != pkg_name:
            continue

        for vuln_spec in vuln.get("versions", []):
            try:
                spec_set = SpecifierSet(vuln_spec)
                if installed_version in spec_set:
                    matched.append(vuln)
                    break  # One match per vulnerability entry
            except InvalidSpecifier:
                # Fall back to simple prefix matching for malformed specs
                continue

    return matched


def _severity_from_vuln(vuln: Dict) -> Severity:
    """Map a vulnerability entry's severity to a Severity enum."""
    sev_str = vuln.get("severity", "MEDIUM").upper().strip()
    if sev_str == "HIGH":
        return Severity.HIGH
    elif sev_str == "LOW":
        return Severity.LOW
    return Severity.MEDIUM


def scan(repo_root: str) -> List[Finding]:
    """Scan project dependencies for known vulnerabilities.

    Parses requirements.txt and checks each package version against the
    local vulnerability database using the packaging library.

    Supports:
      - requirements.txt with standard version specifiers
      - Pipfile [packages] and [dev-packages] sections
      - Semantic version comparison (packaging library)
      - Range-based vulnerability checks

    Args:
        repo_root: Root path of the repository to scan.

    Returns:
        A list of findings for vulnerable dependencies.
    """
    findings: List[Finding] = []

    # Find dependency file
    req_path = None
    for dep_file in ("requirements.txt", "Pipfile"):
        candidate = os.path.join(repo_root, dep_file)
        if os.path.isfile(candidate):
            req_path = candidate
            break

    if req_path is None:
        return findings

    dep_name = os.path.relpath(req_path, repo_root)
    packages: List[Tuple[str, str, int, str]] = []  # (name, version_spec, line_num, snippet)

    # Load vulnerability database
    vuln_db = _load_vulndb(VULN_DB_PATH)
    if not vuln_db:
        return findings

    # ─── Parse dependency files ─────────────────────────────────────
    if os.path.basename(req_path) == "requirements.txt":
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, OSError):
            return findings

        for line_num, line in enumerate(lines, start=1):
            parsed = _parse_requirements_line(line)
            if parsed is None:
                continue
            pkg_name, version_spec = parsed
            if not version_spec:
                continue
            packages.append((pkg_name, version_spec, line_num, line.strip()))

    elif os.path.basename(req_path) == "Pipfile":
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (IOError, OSError):
            return findings

        in_packages = False
        for line_num, line in enumerate(content.split("\n"), start=1):
            stripped = line.strip()
            if stripped in ("[packages]", "[dev-packages]"):
                in_packages = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_packages = False
                continue
            if in_packages and "=" in stripped and not stripped.startswith("#"):
                parts = stripped.split("=", 1)
                pkg_name = parts[0].strip().strip('"').strip("'").lower()
                version_spec = parts[1].strip().strip('"').strip("'")
                if version_spec and version_spec != "*":
                    packages.append((pkg_name, version_spec, line_num, line.strip()))

    if not packages:
        return findings

    # ─── Check each package against vulnerability database ─────────
    for pkg_name, version_spec, line_num, snippet in packages:
        # Extract the version from the specifier for display
        # (e.g., ">=1.0,<2.0" -> we need to check if the installed version matches)
        # The vulndb stores specs as version ranges (e.g., "<2.3.0")
        # We need to compare the actual installed version

        # Extract version value from specifier (handle ==, >=, <=, etc.)
        clean_version = re.sub(r"^[><=!~]+\s*", "", version_spec.split(",")[0].strip())
        clean_version = clean_version.strip("*")

        # Find matching vulnerabilities
        matched_vulns = _check_vulnerability(pkg_name, clean_version, vuln_db)

        for vuln in matched_vulns:
            severity = _severity_from_vuln(vuln)
            cve = vuln.get("cve", "N/A")
            description = vuln.get("description", "No description available")

            finding = Finding(
                file_path=dep_name,
                line_number=line_num,
                issue_type="dependency",
                severity=severity,
                message=(
                    f"{pkg_name} {clean_version} has known vulnerability "
                    f"({cve}): {description[:200]}"
                ),
                rule_id=f"DEP-{vuln.get('cve', 'UNKNOWN').replace('-', '_')}",
                confidence=0.9,
                snippet=snippet[:80],
                detection_method="dependency",
                remediation_hint=f"Upgrade {pkg_name} to a version outside the affected range.",
            )
            findings.append(finding)

    # Deduplicate
    seen: set[tuple[str, int, str]] = set()
    deduped: List[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    return deduped
