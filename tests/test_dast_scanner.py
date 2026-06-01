"""Unit tests for the DAST scanner module.

These tests cover the DASTScanner class, SafeResponse, make_request, helper
functions, and scan logic. Live HTTP tests are deferred to end-to-end testing.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Optional

from sentinel.models import Finding, Severity
from sentinel.scanner.dast_scanner import (
    DASTScanner,
    DASTConfig,
    SafeResponse,
    build_url,
    extract_domain,
    extract_scheme,
    get_origin_url,
    is_https,
    INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    SECURITY_HEADERS,
    SENSITIVE_ENDPOINTS,
    CLOUD_METADATA_PATTERNS,
)


class TestHelpers(unittest.TestCase):
    """Tests for DAST helper functions."""

    def test_build_url_with_trailing_slash(self):
        self.assertEqual(build_url("https://example.com/", "/api"), "https://example.com/api")

    def test_build_url_without_trailing_slash(self):
        self.assertEqual(build_url("https://example.com", "api"), "https://example.com/api")

    def test_build_url_subpath(self):
        self.assertEqual(
            build_url("https://example.com/app", "api/v1"),
            "https://example.com/app/api/v1",
        )

    def test_extract_domain_simple(self):
        self.assertEqual(extract_domain("https://example.com/path"), "example.com")

    def test_extract_domain_with_port(self):
        self.assertEqual(extract_domain("http://localhost:8080/"), "localhost")

    def test_extract_domain_no_host(self):
        self.assertEqual(extract_domain("not-a-url"), "not-a-url")

    def test_extract_scheme_https(self):
        self.assertEqual(extract_scheme("https://example.com"), "https")

    def test_extract_scheme_http(self):
        self.assertEqual(extract_scheme("http://example.com"), "http")

    def test_extract_scheme_fallback(self):
        self.assertEqual(extract_scheme("example.com"), "http")

    def test_get_origin_url(self):
        self.assertEqual(
            get_origin_url("https://example.com/path/to/page"),
            "https://example.com",
        )

    def test_get_origin_url_with_port(self):
        self.assertEqual(
            get_origin_url("http://localhost:8080/test"),
            "http://localhost:8080",
        )

    def test_is_https_true(self):
        self.assertTrue(is_https("https://example.com"))

    def test_is_https_false(self):
        self.assertFalse(is_https("http://example.com"))


class TestSafeResponse(unittest.TestCase):
    """Tests for the SafeResponse dataclass."""

    def test_default_content_type(self):
        resp = SafeResponse(200, {"Content-Type": "text/html"}, "<html>", "http://x.com", 10)
        self.assertEqual(resp.content_type, "")

    def test_all_fields(self):
        resp = SafeResponse(
            status_code=200,
            headers={"Server": "nginx"},
            body="OK",
            url="http://x.com",
            elapsed_ms=5.5,
            content_type="text/plain",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["Server"], "nginx")
        self.assertEqual(resp.body, "OK")
        self.assertEqual(resp.elapsed_ms, 5.5)
        self.assertEqual(resp.content_type, "text/plain")


class TestDASTConfig(unittest.TestCase):
    """Tests for DASTConfig dataclass."""

    def test_default_values(self):
        config = DASTConfig()
        self.assertEqual(config.timeout, 15)
        self.assertTrue(config.check_injection)
        self.assertTrue(config.check_headers)
        self.assertTrue(config.check_tls)
        self.assertEqual(config.max_endpoints, 30)
        self.assertEqual(config.custom_headers, {})

    def test_custom_values(self):
        config = DASTConfig(
            timeout=30,
            check_injection=False,
            max_endpoints=50,
            custom_headers={"X-Custom": "test"},
        )
        self.assertEqual(config.timeout, 30)
        self.assertFalse(config.check_injection)
        self.assertEqual(config.max_endpoints, 50)
        self.assertEqual(config.custom_headers, {"X-Custom": "test"})


class TestConstants(unittest.TestCase):
    """Tests that constants are well-formed."""

    def test_injection_payloads_has_expected_keys(self):
        expected = {"sql", "nosql", "command", "ldap", "xpath", "ssti"}
        self.assertEqual(set(INJECTION_PAYLOADS.keys()), expected)

    def test_injection_payloads_all_nonempty(self):
        for key, payloads in INJECTION_PAYLOADS.items():
            self.assertGreater(len(payloads), 0, f"{key} has no payloads")

    def test_xss_payloads_nonempty(self):
        self.assertGreater(len(XSS_PAYLOADS), 0)
        # New structured format: each payload has payload, context, description
        for entry in XSS_PAYLOADS:
            self.assertIn("payload", entry)
            self.assertIn("context", entry)
            self.assertIn("description", entry)
            self.assertIsInstance(entry["payload"], str)
            self.assertIsInstance(entry["context"], str)
            self.assertIsInstance(entry["description"], str)

    def test_security_headers_has_expected_keys(self):
        expected = {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cache-Control",
        }
        self.assertEqual(set(SECURITY_HEADERS.keys()), expected)

    def test_security_headers_well_formed(self):
        for name, (msg, cwe, severity) in SECURITY_HEADERS.items():
            self.assertIsInstance(msg, str)
            self.assertGreater(len(msg), 10)
            self.assertIsInstance(cwe, str)
            self.assertTrue(cwe.startswith("CWE-"))
            self.assertIn(severity, (Severity.LOW, Severity.MEDIUM, Severity.HIGH))

    def test_sensitive_endpoints_not_empty(self):
        self.assertGreater(len(SENSITIVE_ENDPOINTS), 0)

    def test_sensitive_endpoints_start_with_slash(self):
        for ep in SENSITIVE_ENDPOINTS:
            self.assertTrue(ep.startswith("/"), f"{ep} doesn't start with /")

    def test_cloud_metadata_well_formed(self):
        for provider, mtype, url, msg, severity in CLOUD_METADATA_PATTERNS:
            self.assertIn(provider, ("aws", "gcp", "azure"))
            self.assertTrue(url.startswith("http"))
            self.assertIn(severity, (Severity.CRITICAL, Severity.HIGH))


class TestDASTScannerInit(unittest.TestCase):
    """Tests for DASTScanner initialization."""

    def test_init_strips_trailing_slash(self):
        scanner = DASTScanner("https://example.com/")
        self.assertEqual(scanner.target_url, "https://example.com")

    def test_init_preserves_path(self):
        scanner = DASTScanner("https://example.com/api/v1")
        self.assertEqual(scanner.target_url, "https://example.com/api/v1")

    def test_init_sets_origin(self):
        scanner = DASTScanner("https://example.com/path")
        self.assertEqual(scanner.origin, "https://example.com")

    def test_init_sets_domain(self):
        scanner = DASTScanner("https://example.com")
        self.assertEqual(scanner.domain, "example.com")

    def test_init_default_config(self):
        scanner = DASTScanner("https://example.com")
        self.assertIsNotNone(scanner.config)
        self.assertEqual(scanner.config.timeout, 15)

    def test_init_custom_config(self):
        config = DASTConfig(timeout=5, check_xss=False)
        scanner = DASTScanner("https://example.com", config=config)
        self.assertEqual(scanner.config.timeout, 5)
        self.assertFalse(scanner.config.check_xss)

    def test_init_empty_findings(self):
        scanner = DASTScanner("https://example.com")
        self.assertEqual(scanner.findings, [])

    def test_init_empty_scanned_endpoints(self):
        scanner = DASTScanner("https://example.com")
        self.assertEqual(scanner.scanned_endpoints, [])


class TestAddFinding(unittest.TestCase):
    """Tests for _add_finding."""

    def setUp(self):
        self.scanner = DASTScanner("https://example.com")

    def test_add_finding(self):
        self.scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.HIGH,
            message="Test finding",
            cwe_id="CWE-200",
            owasp_category="A05:2021",
        )
        self.assertEqual(len(self.scanner.findings), 1)
        finding = self.scanner.findings[0]
        self.assertEqual(finding.rule_id, "DAST-TEST")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.cwe_id, "CWE-200")
        self.assertEqual(finding.owasp_category, "A05:2021")

    def test_add_finding_default_endpoint(self):
        self.scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.LOW,
            message="Default endpoint",
        )
        self.assertEqual(
            self.scanner.findings[0].endpoint,
            "https://example.com",
        )

    def test_add_finding_custom_endpoint(self):
        self.scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.MEDIUM,
            message="Custom endpoint",
            endpoint="https://example.com/admin",
        )
        self.assertEqual(
            self.scanner.findings[0].endpoint,
            "https://example.com/admin",
        )

    def test_add_finding_evidence_truncated(self):
        long_evidence = "A" * 1000
        self.scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.HIGH,
            message="Long evidence",
            evidence=long_evidence,
        )
        self.assertEqual(len(self.scanner.findings[0].evidence), 500)

    def test_add_finding_confidence_default(self):
        self.scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.HIGH,
            message="Default confidence",
        )
        self.assertEqual(self.scanner.findings[0].confidence, 0.8)


class TestBuildResult(unittest.TestCase):
    """Tests for _build_result."""

    def test_build_result_deduplicates(self):
        scanner = DASTScanner("https://example.com")
        # Add two identical findings
        scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.HIGH,
            message="Testing dedup",
            endpoint="https://example.com/test",
        )
        scanner._add_finding(
            rule_id="DAST-TEST",
            issue_type="dast_test",
            severity=Severity.LOW,
            message="Same key diff severity",
            endpoint="https://example.com/test",
        )
        result = scanner._build_result(0.0)
        # Dedup removes the second because dedup_key = (file_path, line_number, rule_id, endpoint)
        # file_path = endpoint for DAST findings, and both have line_number=0 and same endpoint
        self.assertEqual(len(result.findings), 1)  # Dedup removes the duplicate

    def test_build_result_has_target_url(self):
        scanner = DASTScanner("https://example.com")
        result = scanner._build_result(0.0)
        self.assertEqual(result.target_url, "https://example.com")

    def test_build_result_scan_time_ms(self):
        scanner = DASTScanner("https://example.com")
        result = scanner._build_result(100.0)
        self.assertGreater(result.scan_time_ms, 0)


class TestMakeRequest(unittest.TestCase):
    """Tests for make_request function."""

    def test_make_request_connection_error(self):
        """Should gracefully handle connection failures."""
        from sentinel.scanner.dast_scanner import make_request
        resp = make_request("http://127.0.0.1:1", timeout=1)
        self.assertEqual(resp.status_code, 0)
        self.assertIn("Connection error", resp.body)

    def test_make_request_timeout(self):
        """Should gracefully handle timeouts."""
        from sentinel.scanner.dast_scanner import make_request
        resp = make_request("http://192.0.2.1:80", timeout=1)
        self.assertEqual(resp.status_code, 0)
        self.assertIn("error", resp.body.lower())


if __name__ == "__main__":
    unittest.main()
