"""Unit tests for the dependency scanner module.

Tests requirements.txt parsing, vulnerability database loading,
version comparison, and finding generation.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sentinel.models import Finding, Severity
from sentinel.scanner.dependency_scanner import (
    _load_vulndb,
    _parse_requirements_line,
    _check_vulnerability,
    _extract_version,
    _parse_dependency_files,
    _scan_local,
    scan,
    VULN_DB_PATH,
)


class TestLoadVulndb(unittest.TestCase):
    """Tests for loading the vulnerability database."""

    def test_load_real_vulndb_exists(self):
        """The built-in vulnerability database should load successfully."""
        vulndb = _load_vulndb(VULN_DB_PATH)
        self.assertGreater(len(vulndb), 0)
        # Should have the expected packages
        packages = {v["package"].lower() for v in vulndb}
        self.assertIn("django", packages)
        self.assertIn("flask", packages)

    def test_load_nonexistent_file_returns_empty(self):
        vulndb = _load_vulndb("/nonexistent/path/vulndb.json")
        self.assertEqual(vulndb, [])

    def test_load_invalid_json_returns_empty(self):
        path = os.path.join(tempfile.mkdtemp(), "bad.json")
        with open(path, "w") as f:
            f.write("not json")
        vulndb = _load_vulndb(path)
        self.assertEqual(vulndb, [])

    def test_database_entries_have_required_fields(self):
        vulndb = _load_vulndb(VULN_DB_PATH)
        for entry in vulndb:
            self.assertIn("package", entry)
            self.assertIn("versions", entry)
            self.assertIn("severity", entry)
            self.assertIn("cve", entry)
            self.assertIn("description", entry)
            self.assertIsInstance(entry["versions"], list)
            self.assertGreater(len(entry["versions"]), 0)
            self.assertIn(entry["severity"].upper(), ("LOW", "MEDIUM", "HIGH"))

    def test_database_cve_format(self):
        vulndb = _load_vulndb(VULN_DB_PATH)
        for entry in vulndb:
            cve = entry.get("cve", "")
            self.assertTrue(
                cve.startswith("CVE-"),
                f"Entry for {entry['package']} has invalid CVE: {cve}",
            )


class TestParseRequirementsLine(unittest.TestCase):
    """Tests for parsing requirements.txt lines."""

    def test_simple_package(self):
        result = _parse_requirements_line("flask==2.0.0")
        self.assertIsNotNone(result)
        name, spec = result
        self.assertEqual(name, "flask")
        self.assertEqual(spec, "==2.0.0")

    def test_package_with_inequality(self):
        result = _parse_requirements_line("django>=3.2,<4.0")
        self.assertIsNotNone(result)
        name, spec = result
        self.assertEqual(name, "django")
        self.assertIn(">=", spec)

    def test_package_with_extras(self):
        result = _parse_requirements_line("bcrypt[security]==4.0.0")
        self.assertIsNotNone(result)
        name, spec = result
        self.assertEqual(name, "bcrypt")
        self.assertEqual(spec, "==4.0.0")

    def test_empty_line_returns_none(self):
        self.assertIsNone(_parse_requirements_line(""))

    def test_comment_line_returns_none(self):
        self.assertIsNone(_parse_requirements_line("# This is a comment"))

    def test_option_line_returns_none(self):
        self.assertIsNone(_parse_requirements_line("-r other-requirements.txt"))
        self.assertIsNone(_parse_requirements_line("--index-url https://example.com"))

    def test_package_inline_comment(self):
        result = _parse_requirements_line("requests==2.28.0 # HTTP library")
        self.assertIsNotNone(result)
        name, spec = result
        self.assertEqual(name, "requests")
        self.assertEqual(spec, "==2.28.0")

    def test_package_name_normalized_to_lowercase(self):
        result = _parse_requirements_line("Flask==2.0.0")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "flask")

    def test_package_version_only(self):
        result = _parse_requirements_line("click>=8.0")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "click")
        self.assertEqual(result[1], ">=8.0")

    def test_package_with_dashes(self):
        result = _parse_requirements_line("python-dateutil==2.8.2")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "python-dateutil")


class TestCheckVulnerability(unittest.TestCase):
    """Tests for version matching against vulnerability database."""

    def setUp(self):
        self.vuln_db = [
            {
                "package": "flask",
                "versions": ["<2.3.0"],
                "severity": "MEDIUM",
                "cve": "CVE-2023-25577",
                "description": "XSS vulnerability",
            },
            {
                "package": "django",
                "versions": ["<3.2.0", ">=4.0a1,<4.0.0"],
                "severity": "HIGH",
                "cve": "CVE-2023-23969",
                "description": "SQL injection",
            },
        ]

    def test_vulnerable_version_matches(self):
        matched = _check_vulnerability("flask", "2.0.0", self.vuln_db)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["cve"], "CVE-2023-25577")

    def test_safe_version_no_match(self):
        matched = _check_vulnerability("flask", "2.3.0", self.vuln_db)
        self.assertEqual(len(matched), 0)

    def test_safe_version_above_range(self):
        matched = _check_vulnerability("flask", "2.5.0", self.vuln_db)
        self.assertEqual(len(matched), 0)

    def test_package_not_in_db(self):
        matched = _check_vulnerability("nonexistent", "1.0.0", self.vuln_db)
        self.assertEqual(len(matched), 0)

    def test_invalid_version_returns_empty(self):
        matched = _check_vulnerability("flask", "not-a-version", self.vuln_db)
        self.assertEqual(len(matched), 0)

    def test_django_multiple_ranges(self):
        matched = _check_vulnerability("django", "3.0.0", self.vuln_db)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["cve"], "CVE-2023-23969")

    def test_version_with_v_prefix(self):
        matched = _check_vulnerability("flask", "v2.0.0", self.vuln_db)
        self.assertEqual(len(matched), 1)


class TestExtractVersion(unittest.TestCase):
    """Tests for extracting version from specifier."""

    def test_exact_version(self):
        self.assertEqual(_extract_version("==2.0.0"), "2.0.0")

    def test_greater_or_equal(self):
        self.assertEqual(_extract_version(">=2.0.0"), "2.0.0")

    def test_comma_separated(self):
        self.assertEqual(_extract_version(">=2.0.0,<3.0.0"), "2.0.0")

    def test_tilde_match(self):
        self.assertEqual(_extract_version("~=2.0.0"), "2.0.0")

    def test_not_equal(self):
        self.assertEqual(_extract_version("!=2.0.0"), "2.0.0")

    def test_star_wildcard(self):
        self.assertEqual(_extract_version("==2.0.*"), "2.0.")


class TestParseDependencyFiles(unittest.TestCase):
    """Tests for parsing dependency files."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_dependency_file(self):
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        self.assertEqual(packages, [])
        self.assertEqual(dep_name, "")

    def test_requirements_txt_parsed(self):
        req_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("flask==2.0.0\ndjango>=3.2,<4.0\n# comment\nclick==8.0.0\n")
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        self.assertEqual(dep_name, "requirements.txt")
        self.assertEqual(len(packages), 3)
        names = [p[0] for p in packages]
        self.assertIn("flask", names)
        self.assertIn("django", names)
        self.assertIn("click", names)

    def test_pipfile_parsed(self):
        pipfile_path = os.path.join(self.temp_dir, "Pipfile")
        with open(pipfile_path, "w") as f:
            f.write("[packages]\nflask = \"==2.0.0\"\ndjango = \">=3.2\"\n")
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        self.assertEqual(dep_name, "Pipfile")
        self.assertEqual(len(packages), 2)

    def test_requirements_txt_io_error(self):
        packages, dep_name = _parse_dependency_files("/nonexistent")
        self.assertEqual(packages, [])


class TestScanLocal(unittest.TestCase):
    """Tests for local vulnerability scanning."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_requirements(self, content: str):
        path = os.path.join(self.temp_dir, "requirements.txt")
        with open(path, "w") as f:
            f.write(content)

    def test_no_vulnerabilities_found(self):
        self._create_requirements("click==8.0.0\n")
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        findings = _scan_local(packages, dep_name)
        self.assertEqual(len(findings), 0)

    def test_vulnerable_package_found(self):
        self._create_requirements("flask==2.0.0\n")
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        findings = _scan_local(packages, dep_name)
        self.assertGreater(len(findings), 0)
        # Flask 2.0.0 should be flagged (CVE-2023-25577, <2.3.0)
        flask_findings = [f for f in findings if "flask" in f.message.lower()]
        self.assertGreater(len(flask_findings), 0)

    def test_multiple_vulnerable_packages(self):
        self._create_requirements(
            "flask==2.0.0\ndjango==3.0.0\npyyaml==5.3.0\n"
        )
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        findings = _scan_local(packages, dep_name)
        self.assertGreaterEqual(len(findings), 3)

    def test_finding_has_correct_structure(self):
        self._create_requirements("flask==2.0.0\n")
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        findings = _scan_local(packages, dep_name)
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertEqual(finding.issue_type, "dependency")
        self.assertIn(finding.severity, (Severity.LOW, Severity.MEDIUM, Severity.HIGH))
        self.assertEqual(finding.file_path, "requirements.txt")
        self.assertIn("flask", finding.message.lower())
        self.assertIn("CVE", finding.rule_id)

    def test_version_edge_case_boundary(self):
        """Test vulnerability at the version boundary."""
        self._create_requirements("flask==2.3.0\n")  # Just above the <2.3.0 range
        packages, dep_name = _parse_dependency_files(self.temp_dir)
        findings = _scan_local(packages, dep_name)
        # Should NOT be flagged since 2.3.0 is the fix version
        self.assertEqual(len(findings), 0)


class TestScan(unittest.TestCase):
    """Tests for the top-level scan function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_requirements_file(self):
        findings = scan(self.temp_dir)
        self.assertEqual(findings, [])

    def test_scan_with_vulnerabilities(self):
        req_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("flask==2.0.0\npyyaml==5.3.0\n")
        findings = scan(self.temp_dir)
        self.assertGreaterEqual(len(findings), 2)

    def test_scan_online_not_available_graceful(self):
        """When online mode is used but network is unavailable, should return gracefully."""
        req_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("flask==2.0.0\n")
        # This should not crash even if OSV API is unreachable
        findings = scan(self.temp_dir, online=True)
        # May or may not find results depending on network, but shouldn't crash
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
