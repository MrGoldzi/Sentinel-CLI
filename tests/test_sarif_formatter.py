"""Unit tests for the SARIF v2.1.0 output formatter."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from sentinel.models import Finding, ScanResult, Severity, Verdict
from sentinel.formatters import sarif


class TestBuildRules(unittest.TestCase):
    """Tests for the _build_rules function."""

    def test_empty_findings(self):
        """No findings should produce an empty rules array."""
        rules = sarif._build_rules([])
        self.assertEqual(rules, [])

    def test_single_finding(self):
        """A single finding should produce one rule entry."""
        finding = Finding(
            file_path="app.py",
            line_number=10,
            issue_type="secrets",
            severity=Severity.HIGH,
            message="AWS Access Key ID detected.",
            rule_id="SEC-aws-access-key",
        )
        rules = sarif._build_rules([finding])
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["id"], "SEC-aws-access-key")
        self.assertEqual(rule["name"], "Aws Access Key")
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")
        self.assertEqual(rule["properties"]["severity"], "HIGH")
        self.assertEqual(rule["properties"]["issueType"], "secrets")
        self.assertEqual(rule["properties"]["tags"], ["security", "secrets"])

    def test_duplicate_rule_ids_deduplicated(self):
        """Multiple findings with the same rule_id should produce only one rule."""
        findings = [
            Finding("app.py", 10, "secrets", Severity.HIGH, "First", "SEC-aws-key"),
            Finding("config.py", 20, "secrets", Severity.HIGH, "Second", "SEC-aws-key"),
        ]
        rules = sarif._build_rules(findings)
        self.assertEqual(len(rules), 1)

    def test_multiple_unique_rules(self):
        """Multiple findings with different rule_ids should produce multiple rules."""
        findings = [
            Finding("a.py", 1, "secrets", Severity.HIGH, "Key found", "SEC-key"),
            Finding("b.py", 2, "sast", Severity.MEDIUM, "Eval used", "SAF-eval"),
            Finding("c.py", 3, "deps", Severity.LOW, "Old dep", "DEP-requests"),
        ]
        rules = sarif._build_rules(findings)
        self.assertEqual(len(rules), 3)
        rule_ids = {r["id"] for r in rules}
        self.assertEqual(rule_ids, {"SEC-key", "SAF-eval", "DEP-requests"})

    def test_rule_level_matches_highest_severity(self):
        """Rule defaultConfiguration.level should reflect the severity of its finding."""
        # HIGH -> error
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1")
        ])
        self.assertEqual(rules[0]["defaultConfiguration"]["level"], "error")

        # MEDIUM -> warning
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.MEDIUM, "msg", "RULE-1")
        ])
        self.assertEqual(rules[0]["defaultConfiguration"]["level"], "warning")

        # LOW -> note
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.LOW, "msg", "RULE-1")
        ])
        self.assertEqual(rules[0]["defaultConfiguration"]["level"], "note")

    def test_rule_name_without_dash_prefix(self):
        """Rule ID without a dash should use the full ID as the name."""
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "NOSEPARATOR")
        ])
        self.assertEqual(rules[0]["name"], "NOSEPARATOR")

    def test_rule_name_multiple_dashes(self):
        """Rule ID with multiple dashes should only split on the first."""
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "PREFIX-some-rule-name")
        ])
        self.assertEqual(rules[0]["name"], "Some Rule Name")

    def test_short_description_truncation(self):
        """Short description should be truncated to 120 chars."""
        long_msg = "X." * 200  # Well over 120 chars
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, long_msg, "RULE-1")
        ])
        short_desc = rules[0]["shortDescription"]["text"]
        self.assertLessEqual(len(short_desc), 120)
        # Should contain the part before the first period
        self.assertTrue(short_desc.startswith("X"))

    def test_full_description_truncation(self):
        """Full description should be truncated to 200 chars."""
        long_msg = "A" * 500
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, long_msg, "RULE-1")
        ])
        full_desc = rules[0]["fullDescription"]["text"]
        self.assertLessEqual(len(full_desc), 200)

    def test_short_description_no_period(self):
        """Message without a period should use the full message (truncated to 120)."""
        msg = "Hello world without period"
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, msg, "RULE-1")
        ])
        self.assertEqual(rules[0]["shortDescription"]["text"], msg)


class TestBuildResults(unittest.TestCase):
    """Tests for the _build_results function."""

    def test_empty_findings(self):
        """No findings should produce an empty results array."""
        results = sarif._build_results([])
        self.assertEqual(results, [])

    def test_single_finding_basic_fields(self):
        """A single finding should have all required SARIF result fields."""
        finding = Finding(
            file_path="src/app.py",
            line_number=42,
            issue_type="secrets",
            severity=Severity.HIGH,
            message="API key detected in source code.",
            rule_id="SEC-api-key",
            confidence=0.95,
            snippet="api_key = 'sk-12345'",
        )
        results = sarif._build_results([finding])
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["ruleId"], "SEC-api-key")
        self.assertEqual(r["level"], "error")
        self.assertEqual(r["message"]["text"], "API key detected in source code.")
        self.assertEqual(r["properties"]["confidence"], 0.95)

        # Location fields
        loc = r["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/app.py")
        self.assertEqual(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%")
        self.assertEqual(loc["region"]["startLine"], 42)

    def test_severity_level_mapping(self):
        """Each severity should map to the correct SARIF level."""
        for severity, expected_level in [
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
        ]:
            finding = Finding("a.py", 1, "sast", severity, "msg", "RULE-1")
            results = sarif._build_results([finding])
            self.assertEqual(results[0]["level"], expected_level,
                             f"{severity.value} should map to '{expected_level}'")

    def test_snippet_included(self):
        """Snippet text should be included in the region when present."""
        finding = Finding(
            "a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1",
            snippet="console.log('hello')",
        )
        results = sarif._build_results([finding])
        snippet = results[0]["locations"][0]["physicalLocation"]["region"]["snippet"]
        self.assertEqual(snippet["text"], "console.log('hello')")

    def test_snippet_truncated_to_80_chars(self):
        """Long snippets should be truncated to 80 characters."""
        long_snippet = "A" * 200
        finding = Finding(
            "a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1",
            snippet=long_snippet,
        )
        results = sarif._build_results([finding])
        snippet = results[0]["locations"][0]["physicalLocation"]["region"]["snippet"]
        self.assertLessEqual(len(snippet["text"]), 80)

    def test_no_snippet_omits_field(self):
        """When snippet is empty, the snippet field should NOT be present."""
        finding = Finding(
            "a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1",
            snippet="",
        )
        results = sarif._build_results([finding])
        region = results[0]["locations"][0]["physicalLocation"]["region"]
        self.assertNotIn("snippet", region)

    def test_confidence_in_properties(self):
        """Confidence should be included in result properties."""
        finding = Finding(
            "a.py", 1, "sast", Severity.MEDIUM, "msg", "RULE-1",
            confidence=0.5,
        )
        results = sarif._build_results([finding])
        self.assertEqual(results[0]["properties"]["confidence"], 0.5)

    def test_zero_confidence(self):
        """Zero confidence should be preserved."""
        finding = Finding(
            "a.py", 1, "sast", Severity.MEDIUM, "msg", "RULE-1",
            confidence=0.0,
        )
        results = sarif._build_results([finding])
        self.assertEqual(results[0]["properties"]["confidence"], 0.0)

    def test_multiple_results(self):
        """Multiple findings should produce multiple results."""
        findings = [
            Finding("a.py", 1, "sast", Severity.HIGH, "First", "RULE-A"),
            Finding("b.py", 2, "sast", Severity.MEDIUM, "Second", "RULE-B"),
            Finding("c.py", 3, "sast", Severity.LOW, "Third", "RULE-C"),
        ]
        results = sarif._build_results(findings)
        self.assertEqual(len(results), 3)


class TestBuildSarifLog(unittest.TestCase):
    """Tests for the _build_sarif_log function."""

    def assertSarifStructure(self, log: dict):
        """Assert the top-level SARIF structure is valid."""
        self.assertIn("$schema", log)
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("runs", log)
        self.assertEqual(len(log["runs"]), 1)
        run = log["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("results", run)
        self.assertIn("properties", run)
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "Sentinel")
        self.assertIn("rules", driver)
        self.assertIn("informationUri", driver)

    def test_empty_result(self):
        """An empty scan result should produce a valid SARIF log with PASS verdict."""
        result = ScanResult()
        log = sarif._build_sarif_log(result)
        self.assertSarifStructure(log)
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["runs"][0]["tool"]["driver"]["rules"], [])
        self.assertEqual(log["runs"][0]["properties"]["verdict"], "PASS")
        self.assertEqual(log["runs"][0]["properties"]["total_findings"], 0)
        self.assertEqual(log["runs"][0]["properties"]["scanned_files"], 0)
        # No invocations when there are no results
        self.assertNotIn("invocations", log["runs"][0])

    def test_result_with_findings(self):
        """A scan result with findings should include rules, results, and invocations."""
        findings = [
            Finding("app.py", 10, "secrets", Severity.HIGH, "Key found", "SEC-key"),
        ]
        result = ScanResult(findings=findings, scanned_files=5, scan_time_ms=123.456)
        log = sarif._build_sarif_log(result)
        self.assertSarifStructure(log)
        run = log["runs"][0]
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(run["properties"]["verdict"], "BLOCK")
        self.assertEqual(run["properties"]["total_findings"], 1)
        self.assertEqual(run["properties"]["scanned_files"], 5)
        self.assertEqual(run["properties"]["scan_time_ms"], 123.46)
        self.assertEqual(run["properties"]["severity_threshold"], "HIGH")
        # Invocations should be present
        self.assertIn("invocations", run)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_verdict_warn(self):
        """Scan with MEDIUM findings and HIGH threshold should produce WARN verdict."""
        findings = [
            Finding("app.py", 10, "sast", Severity.MEDIUM, "Medium issue", "SAF-medium"),
        ]
        result = ScanResult(findings=findings)
        log = sarif._build_sarif_log(result)
        self.assertEqual(log["runs"][0]["properties"]["verdict"], "WARN")

    def test_verdict_pass(self):
        """Scan with only LOW findings and HIGH threshold should produce PASS verdict."""
        findings = [
            Finding("app.py", 10, "sast", Severity.LOW, "Low issue", "SAF-low"),
        ]
        result = ScanResult(findings=findings)
        log = sarif._build_sarif_log(result)
        self.assertEqual(log["runs"][0]["properties"]["verdict"], "PASS")

    def test_no_invocations_without_results(self):
        """Invocations should be omitted when there are no results (empty findings)."""
        result = ScanResult()
        log = sarif._build_sarif_log(result)
        self.assertNotIn("invocations", log["runs"][0])

    def test_invocations_with_results(self):
        """Invocations should be present when there are findings."""
        result = ScanResult(findings=[
            Finding("a.py", 1, "sast", Severity.LOW, "msg", "RULE-1"),
        ])
        log = sarif._build_sarif_log(result)
        self.assertIn("invocations", log["runs"][0])
        self.assertTrue(log["runs"][0]["invocations"][0]["executionSuccessful"])


class TestFormatScanResult(unittest.TestCase):
    """Tests for the format_scan_result function."""

    def test_returns_valid_json(self):
        """format_scan_result should return a valid JSON string."""
        result = ScanResult()
        output = sarif.format_scan_result(result)
        parsed = json.loads(output)
        self.assertEqual(parsed["version"], "2.1.0")

    def test_pretty_print_default(self):
        """Default indent should produce multi-line JSON."""
        result = ScanResult()
        output = sarif.format_scan_result(result)
        # Multi-line JSON has newlines in the string
        self.assertIn("\n", output)

    def test_custom_indent(self):
        """Custom indent value should be respected."""
        result = ScanResult()
        output = sarif.format_scan_result(result, indent=4)
        self.assertIn("\n        ", output)  # Deeply nested indentation


class TestFormatCompact(unittest.TestCase):
    """Tests for the format_compact function."""

    def test_compact_no_newlines(self):
        """Compact format should be single-line JSON (no newlines)."""
        result = ScanResult(findings=[
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1"),
        ])
        output = sarif.format_compact(result)
        self.assertNotIn("\n", output)
        # Verify it's still valid JSON
        parsed = json.loads(output)
        self.assertEqual(parsed["version"], "2.1.0")

    def test_compact_empty(self):
        """Compact format should work with empty results."""
        result = ScanResult()
        output = sarif.format_compact(result)
        self.assertNotIn("\n", output)
        parsed = json.loads(output)
        self.assertEqual(parsed["runs"][0]["properties"]["verdict"], "PASS")


class TestWriteSarifReport(unittest.TestCase):
    """Tests for the write_sarif_report function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_writes_file(self):
        """write_sarif_report should write a valid JSON file."""
        result = ScanResult(findings=[
            Finding("app.py", 10, "secrets", Severity.HIGH, "Key found", "SEC-key"),
        ])
        file_path = os.path.join(self.temp_dir, "report.sarif")
        sarif.write_sarif_report(result, file_path)

        self.assertTrue(os.path.exists(file_path))
        with open(file_path) as f:
            data = json.load(f)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 1)

    def test_writes_empty_report(self):
        """write_sarif_report should work with empty results."""
        result = ScanResult()
        file_path = os.path.join(self.temp_dir, "empty.sarif")
        sarif.write_sarif_report(result, file_path)

        self.assertTrue(os.path.exists(file_path))
        with open(file_path) as f:
            data = json.load(f)
        self.assertEqual(data["runs"][0]["properties"]["total_findings"], 0)
        self.assertEqual(data["runs"][0]["results"], [])

    def test_custom_indent(self):
        """Custom indent should be used when writing."""
        result = ScanResult()
        file_path = os.path.join(self.temp_dir, "indent.sarif")
        sarif.write_sarif_report(result, file_path, indent=4)

        with open(file_path) as f:
            content = f.read()
        self.assertIn("        ", content)  # 8-space indent in deeply nested fields


class TestIntegrationWithModels(unittest.TestCase):
    """Integration tests verifying the SARIF formatter works with ScanResult properly."""

    def test_full_scan_round_trip(self):
        """Simulate a full scan result and verify SARIF output is complete."""
        findings = [
            Finding(
                file_path="src/config.py",
                line_number=15,
                issue_type="secrets",
                severity=Severity.HIGH,
                message="AWS Access Key ID detected in configuration file.",
                rule_id="SEC-aws-access-key",
                confidence=0.95,
                snippet="aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'",
            ),
            Finding(
                file_path="src/app.py",
                line_number=42,
                issue_type="sast",
                severity=Severity.MEDIUM,
                message="Use of eval() detected. This can lead to code injection attacks.",
                rule_id="SAF-eval",
                confidence=0.85,
                snippet="result = eval(user_input)",
            ),
            Finding(
                file_path="requirements.txt",
                line_number=1,
                issue_type="dependencies",
                severity=Severity.LOW,
                message="Package 'requests' version 2.12.0 has known vulnerabilities.",
                rule_id="DEP-requests",
                confidence=0.70,
                snippet="requests==2.12.0",
            ),
        ]
        result = ScanResult(
            findings=findings,
            scanned_files=15,
            scan_time_ms=350.0,
        )
        log = sarif._build_sarif_log(result)

        # Verify structure
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]

        # 3 unique rules
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 3)

        # 3 results
        self.assertEqual(len(run["results"]), 3)

        # Levels mapped correctly
        levels = {r["level"] for r in run["results"]}
        self.assertEqual(levels, {"error", "warning", "note"})

        # Verdict should be BLOCK (HIGH finding with default HIGH threshold)
        self.assertEqual(run["properties"]["verdict"], "BLOCK")

        # Properties populated
        self.assertEqual(run["properties"]["total_findings"], 3)
        self.assertEqual(run["properties"]["scanned_files"], 15)
        self.assertEqual(run["properties"]["scan_time_ms"], 350.0)

        # Invocations present
        self.assertIn("invocations", run)

        # Verify specific result content
        result_map = {r["ruleId"]: r for r in run["results"]}
        self.assertIn("SEC-aws-access-key", result_map)
        self.assertIn("SAF-eval", result_map)
        self.assertIn("DEP-requests", result_map)

        # Check locations
        sec_result = result_map["SEC-aws-access-key"]
        loc = sec_result["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/config.py")
        self.assertEqual(loc["region"]["startLine"], 15)

        # Check snippets
        self.assertIn("snippet", loc["region"])
        self.assertIn("AKIAIOSFODNN7", loc["region"]["snippet"]["text"])

    def test_large_number_of_findings(self):
        """Should handle a large number of findings efficiently."""
        findings = [
            Finding(
                f"file_{i % 10}.py", i, "sast", Severity.HIGH,
                f"Finding number {i}", f"RULE-{i % 5}",
            )
            for i in range(100)
        ]
        result = ScanResult(findings=findings, scanned_files=10, scan_time_ms=500)
        log = sarif._build_sarif_log(result)

        # 5 unique rules (0-4)
        self.assertEqual(len(log["runs"][0]["tool"]["driver"]["rules"]), 5)
        # 100 results
        self.assertEqual(len(log["runs"][0]["results"]), 100)
        self.assertEqual(log["runs"][0]["properties"]["total_findings"], 100)

    def test_zero_scan_time(self):
        """Zero scan time should be preserved."""
        result = ScanResult(scanned_files=5, scan_time_ms=0)
        log = sarif._build_sarif_log(result)
        self.assertEqual(log["runs"][0]["properties"]["scan_time_ms"], 0.0)

    def test_custom_severity_threshold(self):
        """Custom severity threshold should appear in properties."""
        result = ScanResult(
            findings=[Finding("a.py", 1, "sast", Severity.LOW, "msg", "RULE-1")],
            severity_threshold=Severity.LOW,
        )
        log = sarif._build_sarif_log(result)
        self.assertEqual(log["runs"][0]["properties"]["severity_threshold"], "LOW")
        # With LOW threshold, even a LOW finding should result in BLOCK
        self.assertEqual(log["runs"][0]["properties"]["verdict"], "BLOCK")


class TestEdgeCases(unittest.TestCase):
    """Edge case tests for the SARIF formatter."""

    def test_unknown_severity_falls_back_to_warning(self):
        """A severity not in the mapping should fall back to 'warning'."""
        # Create a finding with a custom severity-like object
        # The SEVERITY_TO_LEVEL dict only has LOW, MEDIUM, HIGH
        # If a new Severity value is added without updating the mapping,
        # .get() returns 'warning'
        from sentinel.formatters.sarif import SEVERITY_TO_LEVEL
        self.assertEqual(SEVERITY_TO_LEVEL.get(Severity.HIGH, "warning"), "error")
        self.assertEqual(SEVERITY_TO_LEVEL.get(Severity.MEDIUM, "warning"), "warning")
        self.assertEqual(SEVERITY_TO_LEVEL.get(Severity.LOW, "warning"), "note")
        # Verify fallback for unknown
        class FakeSeverity:
            value = "CRITICAL"
        self.assertEqual(SEVERITY_TO_LEVEL.get(FakeSeverity(), "warning"), "warning")

    def test_rule_id_with_only_prefix(self):
        """Rule ID with only a prefix and no dash should split on first dash and title-case."""
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "NO-DASH-HERE")
        ])
        # Split on first dash: ["NO", "DASH-HERE"] -> "Dash Here"
        self.assertEqual(rules[0]["name"], "Dash Here")

    def test_very_long_message_edge_cases(self):
        """Very long messages should be truncated correctly."""
        msg = "A" * 300
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, msg, "RULE-1")
        ])
        self.assertLessEqual(len(rules[0]["shortDescription"]["text"]), 120)
        self.assertLessEqual(len(rules[0]["fullDescription"]["text"]), 200)

    def test_version_in_sarif_output(self):
        """The Sentinel version should appear in the SARIF tool driver."""
        from sentinel import __version__
        result = ScanResult()
        log = sarif._build_sarif_log(result)
        self.assertEqual(
            log["runs"][0]["tool"]["driver"]["version"],
            __version__,
        )

    def test_results_order_matches_findings_order(self):
        """SARIF results should be in the same order as the findings list."""
        findings = [
            Finding("z.py", 3, "secrets", Severity.HIGH, "Third", "RULE-Z"),
            Finding("a.py", 1, "sast", Severity.MEDIUM, "First", "RULE-A"),
            Finding("m.py", 2, "deps", Severity.LOW, "Second", "RULE-M"),
        ]
        log = sarif._build_sarif_log(ScanResult(findings=findings))
        result_messages = [r["message"]["text"] for r in log["runs"][0]["results"]]
        self.assertEqual(result_messages, ["Third", "First", "Second"])

    def test_confidence_round_trip(self):
        """Various confidence values should survive the JSON serialization."""
        for confidence in [0.0, 0.5, 1.0, 0.33333]:
            findings = [
                Finding("a.py", 1, "sast", Severity.MEDIUM, "msg", "RULE-1",
                        confidence=confidence),
            ]
            result = ScanResult(findings=findings)
            output = sarif.format_scan_result(result)
            parsed = json.loads(output)
            result_conf = parsed["runs"][0]["results"][0]["properties"]["confidence"]
            self.assertAlmostEqual(result_conf, confidence)

    def test_multiple_same_rule_different_lines(self):
        """Findings with same rule_id but different lines should produce one rule, multiple results."""
        findings = [
            Finding("a.py", 10, "sast", Severity.HIGH, "First eval", "SAF-eval"),
            Finding("a.py", 20, "sast", Severity.HIGH, "Second eval", "SAF-eval"),
            Finding("a.py", 30, "sast", Severity.HIGH, "Third eval", "SAF-eval"),
        ]
        result = ScanResult(findings=findings)
        log = sarif._build_sarif_log(result)
        run = log["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)  # One rule
        self.assertEqual(len(run["results"]), 3)  # Three results
        line_numbers = [
            r["locations"][0]["physicalLocation"]["region"]["startLine"]
            for r in run["results"]
        ]
        self.assertEqual(line_numbers, [10, 20, 30])

    def test_file_path_with_spaces(self):
        """File paths with spaces should be handled correctly."""
        finding = Finding(
            "my project/src/main.py", 1, "sast", Severity.HIGH, "msg", "RULE-1"
        )
        results = sarif._build_results([finding])
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "my project/src/main.py")

    def test_snippet_truncation_boundary(self):
        """Snippet exactly at 80 chars should not be truncated."""
        snippet = "A" * 80
        finding = Finding("a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1",
                          snippet=snippet)
        results = sarif._build_results([finding])
        result_snippet = results[0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        self.assertEqual(result_snippet, snippet)
        self.assertEqual(len(result_snippet), 80)

    def test_snippet_over_80_boundary(self):
        """Snippet at 81 chars should be truncated to 80."""
        snippet = "A" * 81
        finding = Finding("a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1",
                          snippet=snippet)
        results = sarif._build_results([finding])
        result_snippet = results[0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        self.assertEqual(len(result_snippet), 80)


class TestSarifSpecCompliance(unittest.TestCase):
    """Verify the output conforms to key SARIF v2.1.0 spec requirements."""

    def test_required_top_level_fields(self):
        """SARIF v2.1.0 requires $schema, version, and runs."""
        log = sarif._build_sarif_log(ScanResult())
        self.assertIn("$schema", log)
        self.assertEqual(log["version"], "2.1.0")
        self.assertIsInstance(log["runs"], list)

    def test_required_run_fields(self):
        """Each run requires tool.driver and results fields."""
        log = sarif._build_sarif_log(ScanResult(findings=[
            Finding("a.py", 1, "sast", Severity.HIGH, "msg", "RULE-1"),
        ]))
        run = log["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("driver", run["tool"])
        self.assertIn("results", run)

    def test_required_result_fields(self):
        """Each result requires ruleId, message, and locations."""
        log = sarif._build_sarif_log(ScanResult(findings=[
            Finding("a.py", 1, "sast", Severity.HIGH, "Test message", "RULE-1"),
        ]))
        result = log["runs"][0]["results"][0]
        self.assertIn("ruleId", result)
        self.assertIn("message", result)
        self.assertIn("text", result["message"])
        self.assertIn("locations", result)
        self.assertIsInstance(result["locations"], list)
        self.assertGreater(len(result["locations"]), 0)

    def test_required_location_fields(self):
        """Location requires physicalLocation with artifactLocation and region."""
        log = sarif._build_sarif_log(ScanResult(findings=[
            Finding("a.py", 42, "sast", Severity.HIGH, "msg", "RULE-1"),
        ]))
        loc = log["runs"][0]["results"][0]["locations"][0]
        self.assertIn("physicalLocation", loc)
        phys = loc["physicalLocation"]
        self.assertIn("artifactLocation", phys)
        self.assertIn("uri", phys["artifactLocation"])
        self.assertIn("region", phys)
        self.assertIn("startLine", phys["region"])

    def test_required_rule_fields(self):
        """Each rule requires id and shortDescription."""
        rules = sarif._build_rules([
            Finding("a.py", 1, "sast", Severity.HIGH, "Test message.", "RULE-1"),
        ])
        rule = rules[0]
        self.assertIn("id", rule)
        self.assertIn("shortDescription", rule)
        self.assertIn("text", rule["shortDescription"])


if __name__ == "__main__":
    unittest.main()
