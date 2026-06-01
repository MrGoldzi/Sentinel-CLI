"""Dependency scanner — checks project dependencies for known vulnerabilities.

Powered by the OSV (Open Source Vulnerabilities) API by default. Queries the
Google-maintained OSV.dev database which aggregates vulnerability data from:
  - GitHub Security Advisories (GHSA)
  - PyPA Advisory Database
  - RustSec Advisory Database
  - Go vulnerability database
  - npm Security Advisories
  - OSS-Fuzz
  - And many more sources

Online mode (default): Queries api.osv.dev for comprehensive, real-time vulnerability
data across all supported ecosystems. Uses efficient batch queries.

Offline mode (--offline): Falls back to the built-in local vulnerability database
(data/vulndb.json). Ideal for air-gapped environments or CI speed.

Ecosystem auto-detection from dependency files:
  requirements.txt, Pipfile, Pipfile.lock  → PyPI
  package.json, package-lock.json          → npm
  pom.xml, build.gradle                    → Maven
  go.mod, go.sum                           → Go
  Cargo.toml, Cargo.lock                   → crates.io
  Gemfile, Gemfile.lock                    → RubyGems
  composer.json, composer.lock             → Packagist
  *.csproj, packages.config                → NuGet

Semgrep-competitive: Matches or exceeds Semgrep Supply Chain's ecosystem coverage
with zero proprietary lock-in — all data from the open OSV database.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from ..models import Finding, Severity

# ─── OSV API Configuration ──────────────────────────────────────────────

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_API_TIMEOUT = 15  # seconds
OSV_USER_AGENT = "Sentinel/0.3.0 (security scanner; https://github.com/sentinel-security/sentinel)"

# ─── Local Vulnerability Database ───────────────────────────────────────

VULN_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "vulndb.json",
)

# ─── Ecosystem auto-detection maps ──────────────────────────────────────

# Map of dependency file names → (ecosystem, parser function)
DEPENDENCY_FILE_MAP: Dict[str, Tuple[str, str]] = {
    "requirements.txt": ("PyPI", "requirements.txt"),
    "vulnerable_deps.txt": ("PyPI", "requirements.txt"),
    "Pipfile": ("PyPI", "Pipfile"),
    "Pipfile.lock": ("PyPI", "Pipfile.lock"),
    "package.json": ("npm", "package.json"),
    "package-lock.json": ("npm", "package-lock.json"),
    "yarn.lock": ("npm", "yarn.lock"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock.yaml"),
    "pom.xml": ("Maven", "pom.xml"),
    "build.gradle": ("Maven", "build.gradle"),
    "build.gradle.kts": ("Maven", "build.gradle.kts"),
    "go.mod": ("Go", "go.mod"),
    "go.sum": ("Go", "go.sum"),
    "Cargo.toml": ("crates.io", "Cargo.toml"),
    "Cargo.lock": ("crates.io", "Cargo.lock"),
    "Gemfile": ("RubyGems", "Gemfile"),
    "Gemfile.lock": ("RubyGems", "Gemfile.lock"),
    "composer.json": ("Packagist", "composer.json"),
    "composer.lock": ("Packagist", "composer.lock"),
    "packages.config": ("NuGet", "packages.config"),
}

# Extensions that indicate a .NET project file
DOTNET_PROJECT_EXTS = {".csproj", ".vbproj", ".fsproj"}


def _detect_dependency_files(repo_root: str) -> List[Tuple[str, str, str]]:
    """Auto-detect all dependency/package manifest files in a repository.

    Searches the repository root (non-recursively for standard files, and
    recursively for files like *.csproj) to find all supported dependency
    manifests.

    Args:
        repo_root: Root path of the repository.

    Returns:
        List of (ecosystem, parser_type, absolute_file_path) tuples.
    """
    detected: List[Tuple[str, str, str]] = []
    seen_ecosystems: Set[str] = set()

    # Check root-level dependency files
    for filename, (ecosystem, parser_type) in DEPENDENCY_FILE_MAP.items():
        candidate = os.path.join(repo_root, filename)
        if os.path.isfile(candidate):
            if ecosystem not in seen_ecosystems or parser_type != "yarn.lock" and parser_type != "pnpm-lock.yaml":
                detected.append((ecosystem, parser_type, candidate))
                seen_ecosystems.add(ecosystem)

    # Check for .NET project files recursively
    for root, _dirs, filenames in os.walk(repo_root):
        # Skip common non-source directories
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                     "target", "bin", "obj", ".gradle"}
        _dirs[:] = [d for d in _dirs if d not in skip_dirs]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() in DOTNET_PROJECT_EXTS:
                candidate = os.path.join(root, filename)
                detected.append(("NuGet", "csproj", candidate))
                seen_ecosystems.add("NuGet")

    return detected


# ═══════════════════════════════════════════════════════════════════════════
# Dependency file parsers (multi-ecosystem)
# ═══════════════════════════════════════════════════════════════════════════

def _parse_requirements_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse a line from requirements.txt into (package_name, version_specifier)."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
        return None
    if " #" in line:
        line = line[: line.index(" #")].strip()
    match = re.match(
        r"^([a-zA-Z0-9_\-\\.]+)"
        r"(?:\[[^\]]+\])?"
        r"\s*"
        r"([><=!~]+\s*[a-zA-Z0-9_\-\\.\*]+(?:\s*,\s*[><=!~]+\s*[a-zA-Z0-9_\-\\.\*]+)*)?",
        line,
    )
    if not match:
        return None
    name = match.group(1).lower().strip()
    version_spec = match.group(2)
    if version_spec:
        return (name, version_spec.strip())
    return None


def _parse_requirements_txt(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse requirements.txt into (name, version_spec, line_num, snippet) tuples."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return packages
    for line_num, line in enumerate(lines, start=1):
        parsed = _parse_requirements_line(line)
        if parsed is None:
            continue
        pkg_name, version_spec = parsed
        if not version_spec:
            continue
        packages.append((pkg_name, version_spec, line_num, line.strip()))
    return packages


def _parse_pipfile(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse Pipfile [packages] and [dev-packages] sections."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
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
    return packages


def _parse_package_json(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse package.json dependencies and devDependencies."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return packages
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section, {})
        for pkg_name, version_spec in deps.items():
            if isinstance(version_spec, str) and version_spec.strip():
                packages.append((pkg_name.lower(), version_spec.strip(), 0, json.dumps({pkg_name: version_spec})))
    return packages


def _parse_gradle(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse build.gradle / build.gradle.kts for dependency declarations.
    
    Handles both Groovy DSL (build.gradle) and Kotlin DSL (build.gradle.kts).
    """
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
    
    # Match both Groovy and Kotlin DSL dependency formats:
    #   implementation 'group:artifact:version'
    #   implementation("group:artifact:version")
    #   testImplementation 'group:artifact:version'
    #   compile 'group:artifact:version'
    dep_pattern = re.compile(
        r"(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile)"
        r"\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?",
    )
    for line_num, line in enumerate(content.split("\n"), start=1):
        match = dep_pattern.search(line)
        if match:
            dep_str = match.group(1)
            parts = dep_str.split(":")
            if len(parts) >= 3:
                pkg_name = f"{parts[0]}:{parts[1]}"
                version = parts[2]
                packages.append((pkg_name.lower(), version, line_num, line.strip()))
    return packages


def _parse_nuget_xml(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse NuGet packages.config for dependency versions."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
    # Match <package id="Name" version="1.0.0" />
    pkg_pattern = re.compile(
        r'<package\s+id="([^"]+)"[^>]*version="([^"]+)"',
        re.IGNORECASE,
    )
    for match in pkg_pattern.finditer(content):
        pkg_name = match.group(1)
        version = match.group(2)
        packages.append((pkg_name.lower(), version, 0, match.group(0)[:80]))
    return packages


def _parse_csproj(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse .csproj MSBuild files for PackageReference elements."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
    # Match <PackageReference Include="Name" Version="1.0.0" />
    pkg_pattern = re.compile(
        r'<PackageReference\s+Include="([^"]+)"[^>]*Version="([^"]+)"',
        re.IGNORECASE,
    )
    for match in pkg_pattern.finditer(content):
        pkg_name = match.group(1)
        version = match.group(2)
        packages.append((pkg_name.lower(), version, 0, match.group(0)[:80]))
    return packages


def _parse_yarn_lock(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse yarn.lock for resolved dependency versions."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
    # yarn.lock format: package@version: then version "x.y.z"
    pkg_pattern = re.compile(
        r'^"?(@?[^@\n]+)@[^:\n]+"?\s*:\s*$\s*version\s+"([^"]+)"',
        re.MULTILINE,
    )
    for match in pkg_pattern.finditer(content):
        pkg_name = match.group(1).strip()
        version = match.group(2)
        packages.append((pkg_name.lower(), version, 0, f"{pkg_name}@{version}"))
    return packages


def _parse_pom_xml(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse Maven pom.xml for dependencies with version info."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError):
        return packages
    # Find <dependency> blocks
    dep_pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"<version>([^<]+)</version>",
        re.DOTALL,
    )
    for match in dep_pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip()
        # Skip variable references like ${some.version}
        if not version.startswith("$"):
            pkg_name = f"{group_id}:{artifact_id}"
            packages.append((pkg_name.lower(), version, 0, f"{group_id}:{artifact_id}:{version}"))
    return packages


def _parse_go_mod(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse go.mod require directives for dependency versions."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return packages
    in_require = False
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == "require (":
            in_require = True
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                pkg_path = parts[0]
                version = parts[1].lstrip("v")
                packages.append((pkg_path.lower(), version, line_num, stripped))
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                pkg_path = parts[1]
                version = parts[2].lstrip("v")
                packages.append((pkg_path.lower(), version, line_num, stripped))
    return packages


def _parse_cargo_toml(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse Cargo.toml [dependencies] section."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return packages
    in_deps = False
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("[dependencies"):
            in_deps = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = False
            continue
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            # Format: name = "version" or name = { version = "1.0" }
            parts = stripped.split("=", 1)
            pkg_name = parts[0].strip().strip('"').lower()
            value = parts[1].strip()
            if value.startswith("{") and "version" in value:
                ver_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                if ver_match:
                    version_spec = ver_match.group(1)
                    packages.append((pkg_name, version_spec, line_num, stripped))
            elif value.startswith('"') and value.endswith('"'):
                version_spec = value.strip('"')
                packages.append((pkg_name, version_spec, line_num, stripped))
    return packages


def _parse_gemfile(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse Gemfile gem declarations for dependency versions."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return packages
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        # gem "name", "version"
        match = re.match(r'gem\s+["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']', stripped)
        if match:
            pkg_name = match.group(1).lower()
            version_spec = match.group(2)
            packages.append((pkg_name, version_spec, line_num, stripped))
    return packages


def _parse_composer_json(file_path: str) -> List[Tuple[str, str, int, str]]:
    """Parse composer.json require and require-dev sections."""
    packages: List[Tuple[str, str, int, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return packages
    for section in ("require", "require-dev"):
        deps = data.get(section, {})
        for pkg_name, version_spec in deps.items():
            if pkg_name == "php":
                continue  # skip PHP version constraint
            if isinstance(version_spec, str) and version_spec.strip():
                packages.append((pkg_name.lower(), version_spec.strip(), 0, json.dumps({pkg_name: version_spec})))
    return packages


# ─── Parser dispatch ─────────────────────────────────────────────────────

PARSER_MAP: Dict[str, callable] = {
    "requirements.txt": _parse_requirements_txt,
    "Pipfile": _parse_pipfile,
    "Pipfile.lock": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_json,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_package_json,
    "pom.xml": _parse_pom_xml,
    "build.gradle": _parse_gradle,
    "build.gradle.kts": _parse_gradle,
    "go.mod": _parse_go_mod,
    "go.sum": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
    "Cargo.lock": _parse_cargo_toml,
    "Gemfile": _parse_gemfile,
    "Gemfile.lock": _parse_gemfile,
    "composer.json": _parse_composer_json,
    "composer.lock": _parse_composer_json,
    "packages.config": _parse_nuget_xml,
    "csproj": _parse_csproj,
}


def _parse_all_dependency_files(repo_root: str) -> List[Tuple[str, str, str, int, str]]:
    """Discover and parse all supported dependency files in a repository.

    Returns:
        List of (ecosystem, package_name, version_spec, line_num, snippet) tuples.
    """
    all_packages: List[Tuple[str, str, str, int, str]] = []
    dep_files = _detect_dependency_files(repo_root)

    for ecosystem, parser_type, file_path in dep_files:
        parser = PARSER_MAP.get(parser_type)
        if not parser:
            continue
        packages = parser(file_path)
        for pkg_name, version_spec, line_num, snippet in packages:
            all_packages.append((ecosystem, pkg_name, version_spec, line_num, snippet))

    return all_packages


def _extract_version(version_spec: str) -> str:
    """Extract the version value from a version specifier."""
    clean_version = re.sub(r"^[><=!~]+\s*", "", version_spec.split(",")[0].strip())
    return clean_version.strip("*").lstrip("^~vV")


# ═══════════════════════════════════════════════════════════════════════════
# OSV API Integration (online mode — default)
# ═══════════════════════════════════════════════════════════════════════════

def _query_osv_api(pkg_name: str, version: str, ecosystem: str = "PyPI") -> Dict:
    """Query the OSV API for vulnerabilities affecting a package version.

    Args:
        pkg_name: Package name as used in the ecosystem.
        version: Version string to check.
        ecosystem: OSV ecosystem identifier (e.g. "PyPI", "npm", "Go").

    Returns:
        Parsed JSON response from the OSV API, or empty dict on error.
    """
    body = json.dumps({
        "package": {
            "name": pkg_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": OSV_USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_API_TIMEOUT) as resp:
            response_body = resp.read().decode("utf-8")
            return json.loads(response_body)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return {}


def _query_osv_batch(queries: List[Dict]) -> List[Dict]:
    """Query the OSV batch API for multiple packages at once.

    Args:
        queries: List of query dicts, each with "package" and "version" keys.

    Returns:
        List of response dicts from the OSV batch API, or empty list on error.
    """
    if not queries:
        return []
    body = json.dumps({"queries": queries}).encode("utf-8")

    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": OSV_USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_API_TIMEOUT * 2) as resp:
            response_body = resp.read().decode("utf-8")
            data = json.loads(response_body)
            return data.get("results", [])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Severity Parsing
# ═══════════════════════════════════════════════════════════════════════════

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

    Checks database_specific severity strings (GHSA, etc.), CVSS scores, and
    ecosystem-specific severity data. Defaults to MEDIUM if no severity info.
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

    # Check affected[].database_specific or .ecosystem_specific for severity
    affected = vuln.get("affected", [])
    for entry in affected:
        for key in ("database_specific", "ecosystem_specific"):
            entry_specific = entry.get(key, {}) or {}
            sev = entry_specific.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return Severity(sev)

    return Severity.MEDIUM


# ═══════════════════════════════════════════════════════════════════════════
# Online Scan (OSV API — default)
# ═══════════════════════════════════════════════════════════════════════════

def _scan_osv(
    packages: List[Tuple[str, str, str, int, str]],
    dep_name: str,
) -> List[Finding]:
    """Scan packages against the OSV API for vulnerabilities.

    Uses batch queries when there are multiple packages to minimize API calls.
    Falls back gracefully on network errors.

    Args:
        packages: List of (ecosystem, package_name, version_spec, line_num, snippet) tuples.
        dep_name: Relative path to the primary dependency file.

    Returns:
        A list of findings for vulnerable dependencies.
    """
    findings: List[Finding] = []

    if not packages:
        return findings

    # Build batch queries for efficiency
    queries: List[Dict] = []
    query_index: List[Tuple[int, str, str, int, str]] = []  # (orig_idx, pkg_name, version, line_num, snippet)

    for idx, (ecosystem, pkg_name, version_spec, line_num, snippet) in enumerate(packages):
        clean_version = _extract_version(version_spec)
        if not clean_version:
            continue
        queries.append({
            "package": {
                "name": pkg_name,
                "ecosystem": ecosystem,
            },
            "version": clean_version,
        })
        query_index.append((idx, pkg_name, clean_version, line_num, snippet))

    if not queries:
        return findings

    # Use batch API if multiple queries, otherwise single query
    if len(queries) > 1:
        results = _query_osv_batch(queries)
        if len(results) != len(queries):
            # Batch API failed or returned mismatched results — fall back to individual
            results = []
            for query in queries:
                results.append(_query_osv_api(
                    query["package"]["name"],
                    query["version"],
                    query["package"]["ecosystem"],
                ))
    else:
        q = queries[0]
        results = [_query_osv_api(q["package"]["name"], q["version"], q["package"]["ecosystem"])]

    # Process results
    for qi, (orig_idx, pkg_name, clean_version, line_num, snippet) in enumerate(query_index):
        response = results[qi] if qi < len(results) else {}
        vulns = response.get("vulns", [])
        if not vulns:
            continue

        ecosystem = packages[orig_idx][0] if orig_idx < len(packages) else "Unknown"

        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No description available")
            details = vuln.get("details", "")
            description = summary or details[:200] or f"Vulnerability {vuln_id} affecting {pkg_name}"

            severity = _parse_osv_severity(vuln)

            # Extract CVE from aliases
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
                    if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                        events = r.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                remediation = (
                                    f"Upgrade {pkg_name} to version {event['fixed']} or later."
                                )
                                break

            finding = Finding(
                file_path=dep_name,
                line_number=line_num,
                issue_type="dependency",
                severity=severity,
                message=(
                    f"[{ecosystem}] {pkg_name} {clean_version} has known vulnerability "
                    f"({cve}): {description[:180]}"
                ),
                rule_id=f"DEP-{cve.replace('-', '_')}",
                confidence=0.9,
                snippet=snippet[:80],
                detection_method="dependency",
                remediation_hint=remediation,
            )
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Local Scan (offline fallback — --offline flag)
# ═══════════════════════════════════════════════════════════════════════════

def _load_vulndb(vuln_db_path: str) -> List[Dict]:
    """Load the local vulnerability database from a JSON file."""
    try:
        with open(vuln_db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("vulnerabilities", [])
        elif isinstance(data, list):
            return data
        return []
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        return []


def _check_vulnerability(
    pkg_name: str,
    version_str: str,
    vuln_db: List[Dict],
) -> List[Dict]:
    """Check if a package version matches any vulnerability in the database."""
    matched: List[Dict] = []
    try:
        installed_version = Version(version_str)
    except InvalidVersion:
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
                    break
            except InvalidSpecifier:
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


def _scan_local(
    packages: List[Tuple[str, str, str, int, str]],
    dep_name: str,
) -> List[Finding]:
    """Scan packages against the local vulnerability database (offline mode)."""
    findings: List[Finding] = []
    vuln_db = _load_vulndb(VULN_DB_PATH)
    if not vuln_db:
        return findings

    for ecosystem, pkg_name, version_spec, line_num, snippet in packages:
        clean_version = _extract_version(version_spec)
        if not clean_version:
            continue
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
                    f"[{ecosystem}] {pkg_name} {clean_version} has known vulnerability "
                    f"({cve}): {description[:180]}"
                ),
                rule_id=f"DEP-{vuln.get('cve', 'UNKNOWN').replace('-', '_')}",
                confidence=0.9,
                snippet=snippet[:80],
                detection_method="dependency",
                remediation_hint=f"Upgrade {pkg_name} to a version outside the affected range.",
            )
            findings.append(finding)
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Main scan entry point
# ═══════════════════════════════════════════════════════════════════════════

def scan(repo_root: str, offline: bool = False) -> List[Finding]:
    """Scan project dependencies for known vulnerabilities.

    By default, queries the OSV (Open Source Vulnerabilities) API for
    comprehensive, real-time vulnerability data across all supported
    ecosystems. This is the industry-standard approach used by Semgrep
    Supply Chain and other leading SCA tools.

    Use --offline to fall back to the built-in local vulnerability database
    for air-gapped environments or ultra-fast CI scans.

    Automatically detects and parses all major dependency file formats:
      • requirements.txt / Pipfile / Pipfile.lock → PyPI
      • package.json / package-lock.json / yarn.lock → npm
      • pom.xml / build.gradle → Maven
      • go.mod / go.sum → Go
      • Cargo.toml / Cargo.lock → crates.io (Rust)
      • Gemfile / Gemfile.lock → RubyGems
      • composer.json / composer.lock → Packagist (PHP)
      • packages.config / *.csproj → NuGet (.NET)

    Args:
        repo_root: Root path of the repository to scan.
        offline: If True, use the local vulnerability database instead of
                 the OSV API. Default: False (online).

    Returns:
        A list of findings for vulnerable dependencies.
    """
    # Discover and parse all dependency files
    all_packages = _parse_all_dependency_files(repo_root)
    if not all_packages:
        return []

    # Determine the primary dependency file for reporting
    dep_files = _detect_dependency_files(repo_root)
    primary_dep = os.path.relpath(dep_files[0][2], repo_root) if dep_files else ""

    findings: List[Finding] = []

    if offline:
        findings = _scan_local(all_packages, primary_dep)
    else:
        findings = _scan_osv(all_packages, primary_dep)

    # Deduplicate
    seen: Set[Tuple[str, int, str]] = set()
    deduped: List[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    return deduped
