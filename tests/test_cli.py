"""Unit tests for the Sentinel CLI (argument parsing, validation, command routing)."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from sentinel._cli import parse_severity, setup_argparse, validate_path
from sentinel.models import Severity


class TestParseSeverity(unittest.TestCase):
    """Tests for parse_severity() helper."""

    def test_low(self):
        self.assertEqual(parse_severity("low"), Severity.LOW)
        self.assertEqual(parse_severity("LOW"), Severity.LOW)

    def test_medium(self):
        self.assertEqual(parse_severity("medium"), Severity.MEDIUM)

    def test_high(self):
        self.assertEqual(parse_severity("high"), Severity.HIGH)

    def test_critical(self):
        self.assertEqual(parse_severity("critical"), Severity.CRITICAL)

    def test_case_insensitive(self):
        self.assertEqual(parse_severity("Low"), Severity.LOW)
        self.assertEqual(parse_severity("HIGH"), Severity.HIGH)

    def test_invalid_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_severity("invalid")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_severity("")


class TestSetupArgparse(unittest.TestCase):
    """Tests for CLI argument parser setup."""

    def setUp(self):
        self.parser = setup_argparse()

    def test_parser_has_scan_command(self):
        for action in self.parser._subparsers._actions:
            if isinstance(action, argparse._SubParsersAction):
                self.assertIn("scan", action.choices)
                self.assertIn("dast", action.choices)

    def test_scan_command_args(self):
        args = self.parser.parse_args(["scan", "/some/path"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.path, "/some/path")

    def test_scan_default_severity_threshold(self):
        args = self.parser.parse_args(["scan", "/some/path"])
        self.assertEqual(args.severity_threshold, Severity.HIGH)

    def test_scan_custom_threshold(self):
        args = self.parser.parse_args([
            "scan", "/some/path", "--severity-threshold", "LOW",
        ])
        self.assertEqual(args.severity_threshold, Severity.LOW)

    def test_scan_verbose_flag(self):
        args = self.parser.parse_args(["scan", "/some/path", "--verbose"])
        self.assertTrue(args.verbose)

    def test_scan_output_json(self):
        args = self.parser.parse_args(["scan", "/some/path", "--output", "json"])
        self.assertEqual(args.output, "json")

    def test_scan_output_file(self):
        args = self.parser.parse_args([
            "scan", "/some/path", "--output", "sarif", "-o", "results.sarif",
        ])
        self.assertEqual(args.output_file, "results.sarif")

    def test_scan_all_flag(self):
        args = self.parser.parse_args(["scan", "/some/path", "--all"])
        self.assertTrue(args.scan_all)

    def test_scan_all_alt_name(self):
        """--scan-all should work as an alias for --all."""
        args = self.parser.parse_args(["scan", "/some/path", "--scan-all"])
        self.assertTrue(args.scan_all)

    def test_scan_no_gitignore(self):
        args = self.parser.parse_args(["scan", "/some/path", "--no-gitignore"])
        self.assertTrue(args.no_gitignore)

    def test_scan_stats_flag(self):
        args = self.parser.parse_args(["scan", "/some/path", "--stats"])
        self.assertTrue(args.stats)

    def test_scan_exclude(self):
        args = self.parser.parse_args(["scan", "/some/path", "--exclude", "*.test.py,docs/*"])
        self.assertEqual(args.exclude, "*.test.py,docs/*")

    def test_scan_include(self):
        args = self.parser.parse_args(["scan", "/some/path", "--include", "*.py,*.js"])
        self.assertEqual(args.include, "*.py,*.js")

    def test_dast_command_args(self):
        args = self.parser.parse_args(["dast", "https://example.com"])
        self.assertEqual(args.command, "dast")
        self.assertEqual(args.url, "https://example.com")

    def test_dast_timeout_default(self):
        args = self.parser.parse_args(["dast", "https://example.com"])
        self.assertEqual(args.timeout, 15)

    def test_dast_custom_timeout(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--timeout", "30"])
        self.assertEqual(args.timeout, 30)

    def test_dast_no_injection(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--no-injection"])
        self.assertTrue(args.no_injection)

    def test_dast_no_xss(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--no-xss"])
        self.assertTrue(args.no_xss)

    def test_dast_headless(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--headless"])
        self.assertTrue(args.headless)

    def test_dast_max_endpoints(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--max-endpoints", "50"])
        self.assertEqual(args.max_endpoints, 50)

    def test_dast_output_json(self):
        args = self.parser.parse_args(["dast", "https://example.com", "--output", "json"])
        self.assertEqual(args.output, "json")

    def test_version_flag(self):
        """--version prints version and exits."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--version"])


class TestValidatePath(unittest.TestCase):
    """Tests for validate_path()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_file = os.path.join(self.temp_dir, "file.txt")
        open(self.temp_file, "w").close()

    def tearDown(self):
        os.remove(self.temp_file)
        os.rmdir(self.temp_dir)

    def test_valid_directory(self):
        resolved = validate_path(self.temp_dir)
        self.assertEqual(resolved, self.temp_dir)

    def test_path_not_found_exits(self):
        with self.assertRaises(SystemExit):
            validate_path("/nonexistent/path")

    def test_path_is_file_exits(self):
        with self.assertRaises(SystemExit):
            validate_path(self.temp_file)

    def test_expands_user(self):
        """Should expand ~ to home directory."""
        home = os.path.expanduser("~")
        resolved = validate_path("~")
        self.assertEqual(resolved, home)

    def test_resolves_relative(self):
        """Should resolve relative paths to absolute."""
        resolved = validate_path(".")
        self.assertTrue(os.path.isabs(resolved))


class TestCliIntegration(unittest.TestCase):
    """Minimal integration smoke tests."""

    def test_scan_help_text_contains_expected(self):
        """Help text should mention key features."""
        parser = setup_argparse()
        help_text = parser.format_help()
        self.assertIn("scan", help_text)
        self.assertIn("dast", help_text)
        self.assertIn("severity", help_text)

    def _get_subparser(self, name: str):
        """Get a subparser by name by iterating through parser actions."""
        parser = setup_argparse()
        for action in parser._actions:
            if hasattr(action, "choices") and action.choices is not None and name in action.choices:
                return action.choices[name]
        return None

    def test_dast_command_has_owasp_in_epilog(self):
        """DAST command epilog should mention OWASP coverage."""
        dast_parser = self._get_subparser("dast")
        self.assertIsNotNone(dast_parser)
        self.assertIn("OWASP", dast_parser.epilog)

    def test_scan_epilog_has_exit_codes(self):
        """Scan epilog should document exit codes."""
        scan_parser = self._get_subparser("scan")
        self.assertIsNotNone(scan_parser)
        self.assertIn("BLOCK", scan_parser.epilog)


if __name__ == "__main__":
    unittest.main()
