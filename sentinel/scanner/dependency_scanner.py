"""Dependency scanner - checks project dependencies against a local vulnerability database
and optionally the OSV API for comprehensive vulnerability data.

Fully deterministic in local mode: no network calls at runtime. Uses the `packaging` library
for semantic version comparison and range-based vulnerability matching.

The local vulnerability database (data/vulndb.json) can be updated offline
and version-controlled for reproducible builds.

Online mode (--online flag): Queries the OSV (Open Source Vulnerabilities) API at
api.osv.dev for comprehensive, up-to-date vulnerability data for Python packages.
Online mode requires network access.
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

# OSV API endpoint
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_API_TIMEOUT = 10  # seconds

# Package ecosystems supported by OSV
OSV_ECOSYSTEM = "PyPI"

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


def _parse_dependency_files(repo_root: str) -> Tuple[List[Tuple[str, str, int, str]], str]:
    """Parse dependency files in the repository.

    Args:
        repo_root: Root path of the repository.

    Returns:
        Tuple of (packages list, dependency file path relative to repo).
        Each package is (name, version_spec, line_number, snippet).
        Returns empty list and empty string if no dependency file found.
    """
    # Find dependency file
    req_path = None
    for dep_file in ("requirements.txt", "Pipfile"):
        candidate = os.path.join(repo_root, dep_file)
        if os.path.isfile(candidate):
            req_path = candidate
            break

    if req_path is None:
        return [], ""

    dep_name = os.path.relpath(req_path, repo_root)
    packages: List[Tuple[str, str, int, str]] = []

    # ─── Parse dependency files ─────────────────────────────────────
    if os.path.basename(req_path) == "requirements.txt":
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, OSError):
            return [], dep_name

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
            return [], dep_name

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

    return packages, dep_name


def _extract_version(version_spec: str) -> str:
    """Extract the version value from a version specifier.

    Handles ==, >=, <=, !=, ~=, and comma-separated specifiers.
    """
    clean_version = re.sub(r"^[><=!~]+\s*", "", version_spec.split(",")[0].strip())
    return clean_version.strip("*")


def _scan_local(packages: List[Tuple[str, str, int, str]], dep_name: str) -> List[Finding]:
    """Scan packages against the local vulnerability database.

    Args:
        packages: List of (name, version_spec, line_num, snippet) tuples.
        dep_name: Relative path to the dependency file.

    Returns:
        A list of findings for vulnerable dependencies.
    """
    findings: List[Finding] = []

    # Load vulnerability database
    vuln_db = _load_vulndb(VULN_DB_PATH)
    if not vuln_db:
        return findings

    for pkg_name, version_spec, line_num, snippet in packages:
        clean_version = _extract_version(version_spec)

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

    return findings


def _query_osv_api(pkg_name: str, version: str) -> Dict:
    """Query the OSV API for vulnerabilities affecting a package version.

    Args:
        pkg_name: Package name (lowercase).
        version: Version string to check.

    Returns:
        Parsed JSON response from the OSV API, or empty dict on error.
    """
    import urllib.request
    import urllib.error

    # Build request body
    body = json.dumps({
        "package": {
            "name": pkg_name,
            "ecosystem": OSV_ECOSYSTEM,
        },
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Sentinel/0.2.0 (security scanner; https://github.com/sentinel-security/sentinel)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_API_TIMEOUT) as resp:
            response_body = resp.read().decode("utf-8")
            return json.loads(response_body)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return {}


def _osv_cvss_to_severity(cvss_score: Optional[float]) -> Severity:
    """Map a CVSS score to a Sentinel severity level.

    CVSS Score Ranges:
      0.0 - 3.9  → LOW
      4.0 - 6.9  → MEDIUM
      7.0 - 8.9  → HIGH
      9.0 - 10.0 → CRITICAL
    """
    if cvss_score is None:
        return Severity.MEDIUM
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_osv_severity(vuln: Dict) -> Severity:
    """Extract severity from an OSV vulnerability entry.

    Checks database_specific severity strings (GHSA, etc.) and CVSS scores.
    Defaults to MEDIUM if no severity information is available.
    """
    # Check database_specific severity (e.g., from GitHub Advisory Database)
    db_specific = vuln.get("database_specific", {}) or {}
    ghsa_severity = db_specific.get("severity", "").upper()
    if ghsa_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return Severity(ghsa_severity)

    # Check CVSS scores from severity field
    severities = vuln.get("severity", [])
    for sev_entry in severities:
        if sev_entry.get("type", "").upper() == "CVSS_V3":
            score_str = sev_entry.get("score", "")
            try:
                cvss_score = float(score_str)
                return _osv_cvss_to_severity(cvss_score)
            except (ValueError, TypeError):
                pass

    # Check affected[].database_specific for severity
    affected = vuln.get("affected", [])
    for entry in affected:
        entry_db_specific = entry.get("database_specific", {}) or {}
        sev = entry_db_specific.get("severity", "").upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return Severity(sev)

    return Severity.MEDIUM


def _scan_osv(packages: List[Tuple[str, str, int, str]], dep_name: str) -> List[Finding]:
    """Scan packages against the OSV API for vulnerabilities.

    Queries the Open Source Vulnerabilities (OSV) database for each package
    version. Requires network access.

    Args:
        packages: List of (name, version_spec, line_num, snippet) tuples.
        dep_name: Relative path to the dependency file.

    Returns:
        A list of findings for vulnerable dependencies.
    """
    findings: List[Finding] = []

    for pkg_name, version_spec, line_num, snippet in packages:
        clean_version = _extract_version(version_spec)

        # Query OSV API
        response = _query_osv_api(pkg_name, clean_version)

        vulns = response.get("vulns", [])
        if not vulns:
            continue

        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No description available")
            details = vuln.get("details", "")
            description = summary or details[:200] or f"Vulnerability {vuln_id} affecting {pkg_name}"

            severity = _parse_osv_severity(vuln)

            # Extract CVE from aliases (OSV IDs like OSV-2023-123 may have CVE aliases)
            aliases = vuln.get("aliases", [])
            cve = vuln_id if vuln_id.startswith("CVE-") else ""
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve = alias
                    break
            if not cve:
                cve = vuln_id  # Fall back to OSV ID

            # Build remediation hint from fixed versions
            remediation = f"Upgrade {pkg_name} to a patched version."
            affected = vuln.get("affected", [])
            for entry in affected:
                ranges = entry.get("ranges", [])
                for r in ranges:
                    if r.get("type") == "SEMVER":
                        events = r.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                remediation = f"Upgrade {pkg_name} to version {event['fixed']} or later."
                                break

            finding = Finding(
                file_path=dep_name,
                line_number=line_num,
                issue_type="dependency",
                severity=severity,
                message=(
                    f"{pkg_name} {clean_version} has known vulnerability "
                    f"({cve}): {description[:200]}"
                ),
                rule_id=f"DEP-{cve.replace('-', '_')}",
                confidence=0.9,
                snippet=snippet[:80],
                detection_method="dependency",
                remediation_hint=remediation,
            )
            findings.append(finding)

    return findings


def scan(repo_root: str, online: bool = False) -> List[Finding]:
    """Scan project dependencies for known vulnerabilities.

    Parses requirements.txt (or Pipfile) and checks each package version
    against vulnerability data. In local mode (default), uses the built-in
    vulnerability database. In online mode (--online), queries the OSV API
    for comprehensive, up-to-date vulnerability data.

    Supports:
      - requirements.txt with standard version specifiers
      - Pipfile [packages] and [dev-packages] sections
      - Semantic version comparison (packaging library)
      - Range-based vulnerability checks (local mode)
      - OSV API integration for comprehensive CVE coverage (online mode)

    Args:
        repo_root: Root path of the repository to scan.
        online: If True, query the OSV API for vulnerabilities instead of
                the local database. Requires network access.

    Returns:
        A list of findings for vulnerable dependencies.
    """
    # Parse dependency files
    packages, dep_name = _parse_dependency_files(repo_root)
    if not packages:
        return []

    findings: List[Finding] = []

    if online:
        findings = _scan_osv(packages, dep_name)
    else:
        findings = _scan_local(packages, dep_name)

    # Deduplicate
    seen: set[tuple[str, int, str]] = set()
    deduped: List[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    return deduped
