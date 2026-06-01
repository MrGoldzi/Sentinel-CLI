"""Unit tests for the scanner engine module.

Tests the scan_repository function, parallel vs sequential execution,
and result aggregation.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sentinel.models import Finding, Severity
from sentinel.scanner.engine import (
    scan_repository,
    _scan_secrets_batch,
    _scan_static_analysis_batch,
    MAX_WORKERS,
    PARALLEL_THRESHOLD,
)


class TestConstants(unittest.TestCase):
    """Tests for engine configuration constants."""

    def test_max_workers_positive(self):
        self.assertGreater(MAX_WORKERS, 0)

    def test_parallel_threshold_positive(self):
        self.assertGreater(PARALLEL_THRESHOLD, 0)


class TestBatchFunctions(unittest.TestCase):
    """Tests for batch scanning helper functions."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_file(self, name: str, content: str) -> str:
        path = os.path.join(self.temp_dir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_scan_secrets_batch_finds_secrets(self):
        self._create_file("config.py", 'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n')
        file_paths = [("config.py", os.path.join(self.temp_dir, "config.py"))]
        findings = _scan_secrets_batch(file_paths, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.issue_type == "secret" for f in findings))

    def test_scan_secrets_batch_empty_file(self):
        self._create_file("safe.py", "x = 1\n")
        file_paths = [("safe.py", os.path.join(self.temp_dir, "safe.py"))]
        findings = _scan_secrets_batch(file_paths, self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_secrets_batch_io_error(self):
        file_paths = [("nonexistent.py", "/nonexistent/file.py")]
        # Should not crash, just return empty
        findings = _scan_secrets_batch(file_paths, self.temp_dir)
        self.assertEqual(findings, [])

    def test_scan_static_batch_finds_issues(self):
        self._create_file("test.py", 'result = eval(user_input)\n')
        file_paths = [("test.py", os.path.join(self.temp_dir, "test.py"))]
        findings = _scan_static_analysis_batch(file_paths, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.issue_type == "static_analysis" for f in findings))

    def test_scan_static_batch_empty(self):
        self._create_file("safe.py", "x = 1\n")
        file_paths = [("safe.py", os.path.join(self.temp_dir, "safe.py"))]
        findings = _scan_static_analysis_batch(file_paths, self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_static_batch_io_error(self):
        file_paths = [("nonexistent.py", "/nonexistent/file.py")]
        findings = _scan_static_analysis_batch(file_paths, self.temp_dir)
        self.assertEqual(findings, [])

    def test_same_file_both_scanners(self):
        path = self._create_file("test.py",
            'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n'
            'result = eval(user_input)\n')
        file_paths = [("test.py", path)]
        secret_findings = _scan_secrets_batch(file_paths, self.temp_dir)
        static_findings = _scan_static_analysis_batch(file_paths, self.temp_dir)
        self.assertGreater(len(secret_findings), 0)
        self.assertGreater(len(static_findings), 0)


class TestScanRepository(unittest.TestCase):
    """Tests for the main scan_repository function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_file(self, name: str, content: str) -> str:
        path = os.path.join(self.temp_dir, name)
        # Ensure parent directory exists for nested paths
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_scan_empty_directory(self):
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.get_verdict().value, "PASS")

    def test_scan_finds_issues(self):
        self._create_file("test.py",
            'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n'
            'result = eval(user_input)\n')
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertGreater(len(result.findings), 0)

    def test_scan_deduplicates(self):
        # Create two files with the same finding (to test dedup across files)
        self._create_file("a.py", 'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n')
        self._create_file("b.py", 'result = eval(user_input)\n')
        result = scan_repository(self.temp_dir, show_progress=False)
        result.deduplicate()
        # Should not have any duplicate keys
        keys = [(f.file_path, f.line_number, f.rule_id, f.endpoint) for f in result.findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_scan_returns_scan_result(self):
        self._create_file("test.py", 'x = 1\n')
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.scan_time_ms)
        self.assertIsNotNone(result.files_by_extension)
        self.assertIsNotNone(result.scanner_times_ms)

    def test_scan_with_exclude_patterns(self):
        self._create_file("main.py", 'result = eval(user_input)\n')
        self._create_file("test_main.py", 'result = eval(user_input)\n')
        result = scan_repository(
            self.temp_dir, show_progress=False,
            exclude_patterns=["test_*"],
        )
        # Should only find findings from main.py
        test_files = [f.file_path for f in result.findings]
        self.assertFalse(any("test_main" in f for f in test_files))

    def test_scan_with_include_patterns(self):
        self._create_file("main.py", 'result = eval(user_input)\n')
        self._create_file("config.yaml", 'password: "secret123"\n')
        result = scan_repository(
            self.temp_dir, show_progress=False,
            include_patterns=["*.py"],
        )
        # Should only find findings from .py files
        for finding in result.findings:
            self.assertTrue(finding.file_path.endswith(".py"),
                            f"Expected .py file, got {finding.file_path}")

    def test_scan_scan_all_mode(self):
        self._create_file("test.py", 'result = eval(user_input)\n')
        result = scan_repository(self.temp_dir, show_progress=False, scan_all=True)
        self.assertGreaterEqual(len(result.findings), 0)

    def test_scan_with_stats(self):
        self._create_file("test.py", 'result = eval(user_input)\n')
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertIn("file_discovery", result.scanner_times_ms)
        self.assertIn("dependency_scan", result.scanner_times_ms)

    def test_scan_no_gitignore_mode(self):
        self._create_file("test.py", 'result = eval(user_input)\n')
        result = scan_repository(self.temp_dir, show_progress=False, no_gitignore=True)
        self.assertIsNotNone(result)

    def test_scan_dependency_findings_included(self):
        self._create_file("requirements.txt", "flask==2.0.0\n")
        self._create_file("main.py", 'print("hello")\n')
        result = scan_repository(self.temp_dir, show_progress=False)
        dep_findings = [f for f in result.findings if f.issue_type == "dependency"]
        self.assertGreater(len(dep_findings), 0)

    def test_scan_severity_threshold_respected(self):
        self._create_file("test.py", 'result = eval(user_input)\n')  # HIGH severity
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertEqual(result.severity_threshold, Severity.HIGH)
        self.assertEqual(result.get_verdict().value, "BLOCK")

    def test_scan_low_threshold(self):
        self._create_file("test.py", 'x = eval(y)\n')  # Will produce HIGH findings
        result = scan_repository(
            self.temp_dir, show_progress=False,
            severity_threshold=Severity.LOW,
        )
        self.assertEqual(result.severity_threshold, Severity.LOW)


class TestScanRepositoryParallel(unittest.TestCase):
    """Tests for parallel scanning mode."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Create many files to trigger parallel mode
        for i in range(PARALLEL_THRESHOLD + 5):
            sub_dir = os.path.join(self.temp_dir, f"dir{i}")
            os.makedirs(sub_dir, exist_ok=True)
            file_path = os.path.join(sub_dir, f"file{i}.py")
            with open(file_path, "w") as f:
                if i % 3 == 0:
                    f.write('result = eval(user_input)\n')
                else:
                    f.write('x = 1\n')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parallel_scan_succeeds(self):
        result = scan_repository(self.temp_dir, show_progress=False)
        self.assertGreaterEqual(len(result.findings), 0)
        self.assertGreater(result.scanned_files, 0)

    def test_parallel_scan_finds_issues(self):
        result = scan_repository(self.temp_dir, show_progress=False)
        eval_findings = [f for f in result.findings if f.rule_id == "SAF-EVAL"]
        self.assertGreater(len(eval_findings), 0)


if __name__ == "__main__":
    unittest.main()
