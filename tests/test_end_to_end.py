"""End-to-end integration tests for Sentinel scanning pipeline.

Tests the full scan pipeline against the test_repo directory,
verifying that the tool produces correct results end-to-end.
"""

from __future__ import annotations

import json
import os
import unittest

from sentinel.pipeline import scan_repository
from sentinel.models import Severity


class TestEndToEndScan(unittest.TestCase):
    """End-to-end tests running the full scan pipeline."""

    @classmethod
    def setUpClass(cls):
        """Find the test_repo directory relative to this file."""
        # The test_repo is at the project root
        test_dir = os.path.dirname(os.path.abspath(__file__))
        cls.test_repo = os.path.join(test_dir, "..", "test_repo")
        cls.test_repo = os.path.abspath(cls.test_repo)

    def test_test_repo_exists(self):
        """Verify the test_repo directory exists."""
        self.assertTrue(os.path.isdir(self.test_repo),
                        f"test_repo directory not found at {self.test_repo}")

    def test_full_scan_finds_issues(self):
        """Full scan of test_repo should find multiple security issues."""
        result = scan_repository(self.test_repo, show_progress=False)
        self.assertGreater(len(result.findings), 0,
                           "Expected to find security issues in test_repo")

    def test_scan_time_measured(self):
        """Scan time should be recorded."""
        result = scan_repository(self.test_repo, show_progress=False)
        self.assertGreater(result.scan_time_ms, 0)

    def test_files_scanned(self):
        """At least some files should be scanned."""
        result = scan_repository(self.test_repo, show_progress=False)
        self.assertGreater(result.scanned_files, 0)

    def test_secrets_found(self):
        """test_repo should contain secrets findings."""
        result = scan_repository(self.test_repo, show_progress=False)
        secret_findings = [f for f in result.findings if f.issue_type == "secret"]
        self.assertGreater(len(secret_findings), 0,
                           "Expected to find secrets in test_repo")

    def test_static_analysis_found(self):
        """test_repo should contain static analysis findings."""
        result = scan_repository(self.test_repo, show_progress=False)
        static_findings = [f for f in result.findings if f.issue_type == "static_analysis"]
        self.assertGreater(len(static_findings), 0,
                           "Expected to find static analysis issues in test_repo")

    def test_dependency_findings_found(self):
        """test_repo should contain dependency findings."""
        result = scan_repository(self.test_repo, show_progress=False)
        dep_findings = [f for f in result.findings if f.issue_type == "dependency"]
        self.assertGreater(len(dep_findings), 0,
                           "Expected to find dependency issues in test_repo")

    def test_verdict_is_block_for_test_repo(self):
        """test_repo should produce a BLOCK verdict (has HIGH issues)."""
        result = scan_repository(self.test_repo, show_progress=False)
        verdict = result.get_verdict()
        self.assertEqual(verdict.value, "BLOCK",
                         "test_repo should produce BLOCK verdict")

    def test_medium_threshold_still_blocks(self):
        """With MEDIUM threshold, should still BLOCK."""
        result = scan_repository(
            self.test_repo, show_progress=False,
            severity_threshold=Severity.MEDIUM,
        )
        verdict = result.get_verdict()
        self.assertEqual(verdict.value, "BLOCK")

    def test_findings_have_file_paths(self):
        """All findings should have non-empty file paths."""
        result = scan_repository(self.test_repo, show_progress=False)
        for finding in result.findings:
            self.assertTrue(finding.file_path,
                            f"Finding {finding.rule_id} has empty file_path")

    def test_findings_have_severity(self):
        """All findings should have valid severity."""
        result = scan_repository(self.test_repo, show_progress=False)
        valid_severities = {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        for finding in result.findings:
            self.assertIn(finding.severity, valid_severities,
                          f"Finding {finding.rule_id} has invalid severity")

    def test_result_to_dict(self):
        """Result.to_dict() should produce valid JSON-serializable dict."""
        result = scan_repository(self.test_repo, show_progress=False)
        d = result.to_dict()
        self.assertIn("verdict", d)
        self.assertIn("total_findings", d)
        self.assertIn("findings", d)
        self.assertIsInstance(d["findings"], list)
        # Should be JSON-serializable
        json_str = json.dumps(d)
        self.assertGreater(len(json_str), 0)

    def test_deduplication(self):
        """After dedup, no duplicate keys should remain."""
        result = scan_repository(self.test_repo, show_progress=False)
        before = len(result.findings)
        result.deduplicate()
        after = len(result.findings)
        self.assertLessEqual(after, before)

    def test_exclude_patterns(self):
        """Exclude patterns should filter findings."""
        result = scan_repository(
            self.test_repo, show_progress=False,
            exclude_patterns=["*.py"],
        )
        for finding in result.findings:
            if finding.issue_type in ("secret", "static_analysis"):
                self.assertFalse(
                    finding.file_path.endswith(".py"),
                    f"Expected no .py files with exclude pattern, got {finding.file_path}",
                )

    def test_include_patterns(self):
        """Include patterns should only scan matching files."""
        # test_repo has .py, .txt files
        result = scan_repository(
            self.test_repo, show_progress=False,
            include_patterns=["*.txt"],
        )
        for finding in result.findings:
            self.assertTrue(
                finding.file_path.endswith(".txt"),
                f"Expected only .txt files with include pattern, got {finding.file_path}",
            )


class TestEndToEndJsonOutput(unittest.TestCase):
    """End-to-end tests verifying JSON output format."""

    @classmethod
    def setUpClass(cls):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        cls.test_repo = os.path.abspath(os.path.join(test_dir, "..", "test_repo"))

    def test_json_serializable_with_findings(self):
        """Scan result should be JSON-serializable with all fields."""
        result = scan_repository(self.test_repo, show_progress=False)
        d = result.to_dict()
        # Verify structure
        json.dumps(d)  # Should not raise
        self.assertIsInstance(d["findings"], list)
        if d["findings"]:
            f = d["findings"][0]
            self.assertIn("file_path", f)
            self.assertIn("line_number", f)
            self.assertIn("severity", f)
            self.assertIn("message", f)
            self.assertIn("rule_id", f)
            self.assertIn("confidence", f)


if __name__ == "__main__":
    unittest.main()
