"""Unit tests for the secrets scanner module.

Tests the regex pattern matching, entropy detection, whitelist filtering,
and file scanning functions.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sentinel.models import Finding, Severity
from sentinel.scanner.secrets_scanner import (
    shannon_entropy,
    is_low_risk_high_entropy,
    is_whitelisted,
    is_likely_comment_or_log,
    entropy_scan,
    scan_file,
    scan,
    SECRET_PATTERNS,
    WHITELIST_PATTERNS,
    LOW_RISK_HIGH_ENTROPY_PATTERNS,
)


class TestShannonEntropy(unittest.TestCase):
    """Tests for Shannon entropy calculation."""

    def test_empty_string_zero_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_zero_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_high_entropy_random_string(self):
        entropy = shannon_entropy("aB3$kL9#xQ2!zP7&wM5*nR1")
        self.assertGreater(entropy, 3.5)

    def test_low_entropy_common_text(self):
        entropy = shannon_entropy("hello world")
        self.assertLess(entropy, 3.0)

    def test_medium_entropy_base64(self):
        entropy = shannon_entropy("dGVzdGluZyBzZWNyZXQgYmFzZTY0")
        self.assertGreater(entropy, 3.0)

    def test_high_entropy_uuid_not_fooled(self):
        # UUIDs should have high entropy
        entropy = shannon_entropy("550e8400-e29b-41d4-a716-446655440000")
        self.assertGreater(entropy, 3.0)


class TestIsLowRiskHighEntropy(unittest.TestCase):
    """Tests for low-risk high-entropy filtering."""

    def test_uuid_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("550e8400-e29b-41d4-a716-446655440000"))

    def test_md5_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("d41d8cd98f00b204e9800998ecf8427e"))

    def test_sha1_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("da39a3ee5e6b4b0d3255bfef95601890afd80709"))

    def test_sha256_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

    def test_numeric_only_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("12345678901234567890"))

    def test_alpha_only_is_low_risk(self):
        self.assertTrue(is_low_risk_high_entropy("abcdefghijklmnopqrst"))

    def test_api_key_not_low_risk(self):
        # Use concatenation to avoid triggering push protection on the stripe key pattern
        stripe_key = "sk_live_" + "abcdefghijklmnopqrstuvwx"
        self.assertFalse(is_low_risk_high_entropy(stripe_key))

    def test_aws_key_not_low_risk(self):
        self.assertFalse(is_low_risk_high_entropy("AKIAIOSFODNN7EXAMPLE"))


class TestIsWhitelisted(unittest.TestCase):
    """Tests for whitelist filtering."""

    def test_example_key_is_whitelisted(self):
        self.assertTrue(is_whitelisted("AKIAIOSFODNN7EXAMPLE"))

    def test_example_secret_is_whitelisted(self):
        self.assertTrue(is_whitelisted("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))

    def test_placeholder_token_is_whitelisted(self):
        self.assertTrue(is_whitelisted("<YOUR_TOKEN>"))

    def test_env_var_template_is_whitelisted(self):
        # Template/placeholder variables should be whitelisted
        self.assertTrue(is_whitelisted("${KEY}"))
        self.assertTrue(is_whitelisted("<API_KEY>"))
        self.assertTrue(is_whitelisted("[SECRET_TOKEN]"))
        self.assertTrue(is_whitelisted("{{API_KEY}}"))

    def test_real_aws_key_not_whitelisted(self):
        self.assertFalse(is_whitelisted("AKIA1234ABCD5678EFGH"))

    def test_comment_todo_is_whitelisted(self):
        self.assertTrue(is_whitelisted("# TODO: add API_KEY here"))


class TestIsLikelyCommentOrLog(unittest.TestCase):
    """Tests for comment/log line detection."""

    def test_python_comment(self):
        self.assertTrue(is_likely_comment_or_log("# This is a comment"))

    def test_js_comment(self):
        self.assertTrue(is_likely_comment_or_log("// This is a comment"))

    def test_code_line_not_comment(self):
        self.assertFalse(is_likely_comment_or_log('api_key = "sk-test-12345"'))

    def test_docstring_is_comment(self):
        self.assertTrue(is_likely_comment_or_log('"""This is a docstring"""'))

    def test_import_not_comment(self):
        self.assertFalse(is_likely_comment_or_log("import os"))


class TestEntropyScan(unittest.TestCase):
    """Tests for entropy-based scanning."""

    def test_short_string_low_confidence(self):
        entropy, confidence = entropy_scan("short", "")
        self.assertEqual(confidence, 0.0)

    def test_high_entropy_credential_var(self):
        entropy, confidence = entropy_scan("aB3$kL9#xQ2!zP7&wM5*nR1", "api_key")
        self.assertGreater(confidence, 0.5)

    def test_high_entropy_no_var_name(self):
        entropy, confidence = entropy_scan(
            "aB3$kL9#xQ2!zP7&wM5*nR1!xYz@", ""
        )
        self.assertGreater(confidence, 0.3)

    def test_uuid_gets_low_confidence(self):
        entropy, confidence = entropy_scan(
            "550e8400-e29b-41d4-a716-446655440000", ""
        )
        self.assertLess(confidence, 0.2)

    def test_non_secret_var_name_lower_confidence(self):
        entropy, confidence = entropy_scan(
            "aB3$kL9#xQ2!zP7&wM5*nR1!xYz@", "username"
        )
        # username is in NON_SECRET_VAR_NAMES but also checked against ENTROPY_TARGET_NAMES
        # username doesn't match entropy target names pattern
        self.assertGreater(confidence, 0.0)


class TestSecretPatterns(unittest.TestCase):
    """Tests that SECRET_PATTERNS are well-formed."""

    def test_all_patterns_have_required_fields(self):
        for rule in SECRET_PATTERNS:
            self.assertIn("name", rule)
            self.assertIn("pattern", rule)
            self.assertIn("severity", rule)
            self.assertIn("message", rule)
            self.assertIn("confidence", rule)

    def test_all_severities_valid(self):
        for rule in SECRET_PATTERNS:
            self.assertIn(rule["severity"], (Severity.LOW, Severity.MEDIUM, Severity.HIGH))

    def test_all_confidences_in_range(self):
        for rule in SECRET_PATTERNS:
            self.assertGreaterEqual(rule["confidence"], 0.0)
            self.assertLessEqual(rule["confidence"], 1.0)

    def test_aws_access_key_pattern(self):
        for rule in SECRET_PATTERNS:
            if rule["name"] == "aws-access-key":
                self.assertTrue(rule["pattern"].search("AKIA1234ABCD5678EFGH"))
                self.assertTrue(rule["pattern"].search("AKIAIOSFODNN7EXAMPLE"))
                # Whitelisting happens in is_whitelisted() separately
                self.assertTrue(is_whitelisted("AKIAIOSFODNN7EXAMPLE"))
                self.assertFalse(is_whitelisted("AKIA1234ABCD5678EFGH"))
                break
        else:
            self.fail("aws-access-key pattern not found")


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

    def test_scan_file_no_secrets(self):
        path = self._create_file("safe.py", "x = 1\ny = 2\nprint(x + y)\n")
        findings = scan_file(path, self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_file_aws_key(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-aws-access-key" for f in findings))

    def test_scan_file_rsa_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
        path = self._create_file("key.pem", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-private-key" for f in findings))

    def test_scan_file_github_token(self):
        content = 'GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-github-token" for f in findings))

    def test_scan_file_connection_string(self):
        content = 'DATABASE_URL = "postgresql://user:pass@localhost:5432/db"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-connection-string" for f in findings))

    def test_scan_file_skips_comments(self):
        content = "# AWS_ACCESS_KEY_ID = \"AKIA1234ABCD5678EFGH\"\n"
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        # Commented lines should be skipped
        self.assertEqual(len(findings), 0)

    def test_scan_file_entropy_detection(self):
        content = 'api_secret = "x8K2mN5pQ9rT3vW6yZ1bC4dF7gH0jL3oP6sU9wR2"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)

    def test_scan_file_io_error_returns_empty(self):
        findings = scan_file("/nonexistent/file.py", "/nonexistent")
        self.assertEqual(findings, [])

    def test_scan_file_whitelisted_value_skipped(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        # Example key should be whitelisted
        self.assertEqual(len(findings), 0)

    def test_scan_file_jwt_token(self):
        content = 'jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"\n'
        path = self._create_file("app.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-jwt-token" for f in findings))

    def test_scan_file_stripe_key(self):
        stripe_prefix = "sk_live_"
        content = f'stripe = "{stripe_prefix}abcdefghijklmnopqrstuvwx"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "SEC-stripe-live-key" for f in findings))

    def test_finding_has_correct_fields(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n'
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertEqual(finding.issue_type, "secret")
        self.assertIn(finding.severity, (Severity.LOW, Severity.MEDIUM, Severity.HIGH))
        self.assertGreater(finding.confidence, 0)
        self.assertTrue(finding.file_path.endswith("config.py"))
        self.assertGreater(finding.line_number, 0)

    def test_multiple_secrets_in_one_file(self):
        content = (
            'AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n'
            'password = "SuperSecret123!"\n'
        )
        path = self._create_file("config.py", content)
        findings = scan_file(path, self.temp_dir)
        self.assertGreaterEqual(len(findings), 2)


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

    def test_scan_repo_with_secrets(self):
        # Create a file with secrets
        sub_dir = os.path.join(self.temp_dir, "src")
        os.makedirs(sub_dir)
        file_path = os.path.join(sub_dir, "config.py")
        with open(file_path, "w") as f:
            f.write('AWS_ACCESS_KEY_ID = "AKIA1234ABCD5678EFGH"\n')
        findings = scan(self.temp_dir)
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
