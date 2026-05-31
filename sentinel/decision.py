"""Decision engine - produces final security verdict from scan findings."""

from __future__ import annotations

from typing import Dict, Optional

from .models import Finding, ScanResult, Severity, Verdict


def evaluate(result: ScanResult) -> Verdict:
    """Evaluate scan results and produce a security verdict.

    The verdict is determined by the `severity_threshold` on the ScanResult:
    - Findings at or above the threshold → BLOCK (exit code 2)
    - Findings one tier below the threshold → WARN (exit code 1)
    - No findings or findings further below → PASS (exit code 0)

    Default threshold (HIGH):
      HIGH→BLOCK, MEDIUM→WARN, LOW→PASS
    """
    return result.get_verdict()


def get_exit_code(verdict: Verdict) -> int:
    """Get the appropriate process exit code for a verdict."""
    return verdict.exit_code


def summarize_findings(result: ScanResult) -> Dict:
    """Produce a summary of findings by severity level."""
    summary: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in result.findings:
        severity = finding.severity.value
        summary[severity] = summary.get(severity, 0) + 1

    return {
        "total": len(result.findings),
        "by_severity": summary,
        "verdict": result.get_verdict().value,
        "severity_threshold": result.severity_threshold.value,
    }
