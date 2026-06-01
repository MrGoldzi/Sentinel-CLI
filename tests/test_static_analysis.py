"""Unit tests for the static analysis scanner module.

Tests regex-based unsafe pattern detection and AST-based Python analysis.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sentinel.models import Finding, Severity
from sentinel.scanner.static_analysis import (
    scan_file,
    scan,
    UNSAFE_PATTERNS,
    _is_false_positive,
)


class TestUnsafePatterns(unittest.TestCase):
    """Tests that UNSAFE_PATTERNS are well-formed."""

    def test_all_patterns_have_required_fields(self):
        for rule in UNSAFE_PATTERNS:
            self.assertIn("name", rule)
            self.assertIn("pattern", rule)
            self.assertIn("severity", rule)
            self.assertIn("message", rule)
            self.assertIn("rule_id", rule)
            self.assertIn("confidence", rule)

    def test_all_rule_ids_have_saf_prefix(self):
        for rule in UNSAFE_PATTERNS:
            self.assertTrue(
                rule["rule_id"].startswith("SAF-"),
                f"Rule {rule['name']} has id {rule['rule_id']} without SAF- prefix",
            )

    def test_confidence_in_range(self):
        for rule in UNSAFE_PATTERNS:
            self.assertGreaterEqual(rule["confidence"], 0.0)
            self.assertLessEqual(rule["confidence"], 1.0)

    def test_eval_pattern(self):
        for rule in UNSAFE_PATTERNS:
            if rule["name"] == "eval-usage":
                self.assertTrue(rule["pattern"].search("eval(user_input)"))
                self.assertTrue(rule["pattern"].search("result = eval(data)"))
                self.assertFalse(rule["pattern"].search("evaluate(data)"))
                break
        else:
            self.fail("eval-usage pattern not found")

    def test_exec_pattern(self):
        for rule in UNSAFE_PATTERNS:
            if rule["name"] == "exec-usage":
                self.assertTrue(rule["pattern"].search("exec(user_code)"))
                self.assertFalse(rule["pattern"].search("execution()"))
                break
        else:
            self.fail("exec-usage pattern not found")


class TestIsFalsePositive(unittest.TestCase):
    """Tests for false positive filtering."""

    def test_test_file_assert_is_fp(self):
        self.assertTrue(_is_false_positive("def test_something():", "assert-usage"))

    def test_import_is_fp(self):
        # Lines with both "import " and "from " are skipped as false positives
        self.assertTrue(_is_false_positive("from os import system", "eval-usage"))

    def test_comment_is_fp(self):
        self.assertTrue(_is_false_positive("# This is a comment", "eval-usage"))

    def test_code_is_not_fp(self):
        self.assertFalse(_is_false_positive('result = eval(user_input)', "eval-usage"))


class TestScanFile(unittest.TestCase):
    """Tests for scan_file function."""

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

    def test_scan_file_no_issues(self):
        path = self._create_file("safe.py", "x = 1\ny = 2\nprint(x + y)\n")
        findings = scan_file(path, self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_file_eval_detected(self):
        path = self._create_file("test.py", 'result = eval(user_input)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SAF-EVAL" for f in findings))

    def test_scan_file_exec_detected(self):
        path = self._create_file("test.py", 'exec(user_code)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-EXEC" for f in findings))

    def test_scan_file_os_system(self):
        path = self._create_file("test.py", 'os.system("ls -la")\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-OS-SYSTEM" for f in findings))

    def test_scan_file_subprocess_shell(self):
        path = self._create_file("test.py", 'subprocess.call(cmd, shell=True)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-SUBPROCESS-SHELL" for f in findings))

    def test_scan_file_pickle_load(self):
        path = self._create_file("test.py", 'data = pickle.loads(data)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-PICKLE" for f in findings))

    def test_scan_file_marshal_load(self):
        path = self._create_file("test.py", 'data = marshal.load(f)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-MARSHAL" for f in findings))

    def test_scan_file_sql_injection_concat(self):
        path = self._create_file("test.py",
            """query = "SELECT * FROM users WHERE id = '" + user_id + "'"\n""")
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-SQL-CONCAT" for f in findings))

    def test_scan_file_sql_injection_fstring(self):
        path = self._create_file("test.py",
            """cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n""")
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-SQL-FSTRING" for f in findings))

    def test_scan_file_tempfile_mktemp(self):
        path = self._create_file("test.py", 'tmp = tempfile.mktemp()\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-TEMPFILE-MKTEMP" for f in findings))

    def test_scan_file_md5(self):
        path = self._create_file("test.py", 'hashlib.md5(data)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-MD5" for f in findings))

    def test_scan_file_assert(self):
        path = self._create_file("test.py", 'assert x > 0\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-ASSERT" for f in findings))

    def test_scan_file_js_inner_html(self):
        path = self._create_file("app.js", 'element.innerHTML = userInput\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-INNER-HTML" for f in findings))

    def test_scan_file_php_exec(self):
        path = self._create_file("app.php", 'shell_exec($cmd);\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-PHP-EXEC" for f in findings))

    def test_scan_file_react_dangerous_html(self):
        path = self._create_file("app.jsx",
            '<div dangerouslySetInnerHTML={{__html: content}} />\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-REACT-HTML" for f in findings))

    def test_scan_file_yaml_unsafe_load(self):
        path = self._create_file("test.py", 'yaml.load(data)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-YAML-LOAD" for f in findings))

    def test_scan_file_node_child_process(self):
        path = self._create_file("server.js",
            'child_process.exec("ls -la", callback)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-NODE-EXEC" for f in findings))

    def test_scan_file_dangerous_compile(self):
        path = self._create_file("test.py", 'compile(source, filename, mode)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-COMPILE" for f in findings))

    def test_scan_file_weak_algorithm(self):
        # The pattern requires algorithm name followed by parentheses
        path = self._create_file("test.py", 'cipher = DES(key)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAF-WEAK-CIPHER" for f in findings),
                        f"Expected SAF-WEAK-CIPHER in findings: {[f.rule_id for f in findings]}")

    def test_scan_file_io_error_empty(self):
        findings = scan_file("/nonexistent/file.py", "/nonexistent")
        self.assertEqual(findings, [])

    def test_finding_has_correct_fields(self):
        path = self._create_file("test.py", 'result = eval(user_input)\n')
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertEqual(finding.issue_type, "static_analysis")
        self.assertIn(finding.severity, (Severity.LOW, Severity.MEDIUM, Severity.HIGH))
        self.assertGreater(finding.confidence, 0)
        self.assertGreater(finding.line_number, 0)

    def test_multiple_issues_in_one_file(self):
        path = self._create_file("test.py",
            'result = eval(user_input)\n'
            'exec(user_code)\n'
            'os.system("ls")\n')
        findings = scan_file(path, self.temp_dir)
        self.assertGreaterEqual(len(findings), 3)

    def test_ast_scan_hardcoded_credentials(self):
        content = (
            'password = "SuperSecretPassword123!"\n'
            'SECRET_KEY = "my-secret-key-value"\n'
        )
        path = self._create_file("test.py", content)
        findings = scan_file(path, self.temp_dir)
        # Should find static analysis patterns and AST-based hardcoded creds
        self.assertGreater(len(findings), 0)

    def test_scan_file_skip_comments(self):
        path = self._create_file("test.py", '# eval(user_input)\n')
        findings = scan_file(path, self.temp_dir)
        # Commented lines should not be flagged
        self.assertEqual(len(findings), 0)

    def test_re_compile_not_flagged(self):
        path = self._create_file("test.py", 'pattern = re.compile(r"test")\n')
        findings = scan_file(path, self.temp_dir)
        # re.compile should not trigger compile-call rule
        compile_findings = [f for f in findings if f.rule_id == "SAF-COMPILE"]
        self.assertEqual(len(compile_findings), 0)


class TestScan(unittest.TestCase):
    """Tests for the top-level scan function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_empty_repo(self):
        findings = scan(self.temp_dir)
        self.assertEqual(findings, [])

    def test_scan_repo_with_issues(self):
        os.makedirs(os.path.join(self.temp_dir, "src"))
        path = os.path.join(self.temp_dir, "src", "test.py")
        with open(path, "w") as f:
            f.write('result = eval(user_input)\n')
        findings = scan(self.temp_dir)
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
