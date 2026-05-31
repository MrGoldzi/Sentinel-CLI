"""Unit tests for the Sentinel decision engine."""

from __future__ import annotations

import unittest

from sentinel.models import Finding, ScanResult, Severity, Verdict


class TestGetVerdict(unittest.TestCase):
    """Tests for ScanResult.get_verdict() logic."""

    def test_empty_findings_returns_pass(self):
        """No findings should always return PASS."""
        result = ScanResult()
        self.assertEqual(result.get_verdict(), Verdict.PASS)

    def test_high_finding_with_default_threshold_block(self):
        """HIGH (at or above default HIGH threshold) → BLOCK."""
        result = ScanResult(findings=[
            _finding(severity=Severity.HIGH),
        ])
        self.assertEqual(result.get_verdict(), Verdict.BLOCK)

    def test_medium_finding_with_default_threshold_warn(self):
        """MEDIUM (one below default HIGH threshold) → WARN."""
        result = ScanResult(findings=[
            _finding(severity=Severity.MEDIUM),
        ])
        self.assertEqual(result.get_verdict(), Verdict.WARN)

    def test_low_finding_with_default_threshold_pass(self):
        """LOW (two below default HIGH threshold) → PASS."""
        result = ScanResult(findings=[
            _finding(severity=Severity.LOW),
        ])
        self.assertEqual(result.get_verdict(), Verdict.PASS)

    def test_medium_threshold_medium_block(self):
        """MEDIUM threshold, MEDIUM finding → BLOCK."""
        result = ScanResult(
            findings=[_finding(severity=Severity.MEDIUM)],
            severity_threshold=Severity.MEDIUM,
        )
        self.assertEqual(result.get_verdict(), Verdict.BLOCK)

    def test_medium_threshold_low_warn(self):
        """MEDIUM threshold, LOW finding → WARN."""
        result = ScanResult(
            findings=[_finding(severity=Severity.LOW)],
            severity_threshold=Severity.MEDIUM,
        )
        self.assertEqual(result.get_verdict(), Verdict.WARN)

    def test_low_threshold_low_block(self):
        """LOW threshold, LOW finding → BLOCK."""
        result = ScanResult(
            findings=[_finding(severity=Severity.LOW)],
            severity_threshold=Severity.LOW,
        )
        self.assertEqual(result.get_verdict(), Verdict.BLOCK)

    def test_critical_finding_with_default_threshold_block(self):
        """CRITICAL (above default HIGH threshold) → BLOCK."""
        result = ScanResult(findings=[
            _finding(severity=Severity.CRITICAL),
        ])
        self.assertEqual(result.get_verdict(), Verdict.BLOCK)

    def test_critical_threshold_high_warn(self):
        """CRITICAL threshold, HIGH finding → WARN."""
        result = ScanResult(
            findings=[_finding(severity=Severity.HIGH)],
            severity_threshold=Severity.CRITICAL,
        )
        self.assertEqual(result.get_verdict(), Verdict.WARN)

    def test_critical_threshold_medium_pass(self):
        """CRITICAL threshold, MEDIUM finding → PASS (two below)."""
        result = ScanResult(
            findings=[_finding(severity=Severity.MEDIUM)],
            severity_threshold=Severity.CRITICAL,
        )
        self.assertEqual(result.get_verdict(), Verdict.PASS)

    def test_mixed_findings_highest_wins(self):
        """Multiple findings: highest severity determines verdict."""
        result = ScanResult(findings=[
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
        ])
        self.assertEqual(result.get_verdict(), Verdict.BLOCK)

    def test_medium_threshold_mixed(self):
        """Multiple findings under MEDIUM threshold."""
        result = ScanResult(
            findings=[
                _finding(severity=Severity.LOW),
                _finding(severity=Severity.LOW),
            ],
            severity_threshold=Severity.MEDIUM,
        )
        self.assertEqual(result.get_verdict(), Verdict.WARN)


class TestVerdictExitCode(unittest.TestCase):
    """Tests for Verdict.exit_code property."""

    def test_pass_exit_code(self):
        self.assertEqual(Verdict.PASS.exit_code, 0)

    def test_warn_exit_code(self):
        self.assertEqual(Verdict.WARN.exit_code, 1)

    def test_block_exit_code(self):
        self.assertEqual(Verdict.BLOCK.exit_code, 2)


class TestSummarizeFindings(unittest.TestCase):
    """Tests for the decision engine's summarize_findings function."""

    def test_empty_result(self):
        from sentinel.decision import summarize_findings
        result = ScanResult()
        summary = summarize_findings(result)
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["verdict"], "PASS")

    def test_counts_by_severity(self):
        from sentinel.decision import summarize_findings
        result = ScanResult(findings=[
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
            _finding(severity=Severity.LOW),
        ])
        summary = summarize_findings(result)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["by_severity"]["HIGH"], 2)
        self.assertEqual(summary["by_severity"]["MEDIUM"], 1)
        self.assertEqual(summary["by_severity"]["LOW"], 1)

    def test_threshold_in_summary(self):
        from sentinel.decision import summarize_findings
        result = ScanResult(
            findings=[_finding(severity=Severity.HIGH)],
            severity_threshold=Severity.MEDIUM,
        )
        summary = summarize_findings(result)
        self.assertEqual(summary["severity_threshold"], "MEDIUM")


class TestEvaluateFunction(unittest.TestCase):
    """Tests for the evaluate() function."""

    def test_evaluate_delegates_to_get_verdict(self):
        from sentinel.decision import evaluate
        result = ScanResult()
        self.assertEqual(evaluate(result), Verdict.PASS)

        result2 = ScanResult(findings=[_finding(severity=Severity.HIGH)])
        self.assertEqual(evaluate(result2), Verdict.BLOCK)


class TestEdgeCases(unittest.TestCase):
    """Edge case tests for the decision engine."""

    def test_deduplicate_removes_duplicates(self):
        """findings with same file_path, line_number, rule_id, and endpoint are deduplicated."""
        result = ScanResult(findings=[
            _finding(severity=Severity.HIGH, file_path="a.py", line=1, rule="RULE-1"),
            _finding(severity=Severity.HIGH, file_path="a.py", line=1, rule="RULE-1"),
        ])
        # Before dedup, there are 2
        self.assertEqual(len(result.findings), 2)
        result.deduplicate()
        self.assertEqual(len(result.findings), 1)

    def test_dedup_preserves_different_rules(self):
        """Different rule_ids on same file/line are kept."""
        result = ScanResult(findings=[
            _finding(severity=Severity.HIGH, file_path="a.py", line=1, rule="RULE-1"),
            _finding(severity=Severity.HIGH, file_path="a.py", line=1, rule="RULE-2"),
        ])
        result.deduplicate()
        self.assertEqual(len(result.findings), 2)

    def test_highest_severity_none_for_empty(self):
        result = ScanResult()
        self.assertIsNone(result.highest_severity)

    def test_highest_severity_returns_max(self):
        result = ScanResult(findings=[
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.CRITICAL),
        ])
        self.assertEqual(result.highest_severity, Severity.CRITICAL)

    def test_severity_ordering(self):
        """Verify Severity comparison operators work correctly."""
        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.CRITICAL)
        self.assertTrue(Severity.CRITICAL > Severity.HIGH)
        self.assertTrue(Severity.LOW <= Severity.LOW)
        self.assertTrue(Severity.HIGH >= Severity.HIGH)


def _finding(
    severity: Severity = Severity.HIGH,
    file_path: str = "test.py",
    line: int = 1,
    rule: str = "TEST-RULE",
) -> Finding:
    """Helper to create a Finding with minimal boilerplate."""
    return Finding(
        file_path=file_path,
        line_number=line,
        issue_type="test",
        severity=severity,
        message=f"Test {severity.value} finding",
        rule_id=rule,
    )


if __name__ == "__main__":
    unittest.main()
