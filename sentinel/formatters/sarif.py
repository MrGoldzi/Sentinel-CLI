"""SARIF v2.1.0 output formatter for integration with GitHub Advanced Security.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard format
for static analysis tool output. GitHub Advanced Security, Azure DevOps,
and other tools can ingest SARIF reports to display code scanning alerts.
"""

from __future__ import annotations

import json
from typing import Dict, List, Set

from .. import __version__
from ..models import Finding, ScanResult, Severity

# SARIF schema URI
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Mapping from Sentinel severity to SARIF levels
SEVERITY_TO_LEVEL: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _build_rules(findings: List[Finding]) -> List[Dict]:
    """Build the SARIF rules array from findings.

    Collects unique rules across all findings with metadata.
    """
    seen_rule_ids: Set[str] = set()
    rules: List[Dict] = []

    for finding in findings:
        if finding.rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(finding.rule_id)

        level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")

        # Derive a human-readable rule name from the rule ID
        rule_parts = finding.rule_id.split("-", 1)
        if len(rule_parts) > 1:
            rule_name = rule_parts[1].replace("-", " ").title()
        else:
            rule_name = finding.rule_id

        rule: Dict = {
            "id": finding.rule_id,
            "name": rule_name,
            "shortDescription": {
                "text": finding.message.split(".")[0][:120],
            },
            "fullDescription": {
                "text": finding.message[:200],
            },
            "defaultConfiguration": {
                "level": level,
            },
            "properties": {
                "severity": finding.severity.value,
                "issueType": finding.issue_type,
                "tags": ["security", finding.issue_type],
            },
        }
        rules.append(rule)

    return rules


def _build_results(findings: List[Finding]) -> List[Dict]:
    """Build the SARIF results array from findings."""
    results: List[Dict] = []

    for finding in findings:
        level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")

        result: Dict = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {
                "text": finding.message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                        },
                    },
                },
            ],
            "properties": {
                "confidence": finding.confidence,
                "detectionMethod": finding.detection_method,
                "remediationHint": finding.remediation_hint,
            },
        }

        # Add snippet if available
        if finding.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet[:80],
            }

        results.append(result)

    return results


def format_scan_result(result: ScanResult, indent: int = 2) -> str:
    """Format scan results as a SARIF v2.1.0 JSON string.

    Args:
        result: The scan result to format.
        indent: JSON indentation level (use None for compact output).

    Returns:
        A SARIF v2.1.0 JSON string.
    """
    sarif_log = _build_sarif_log(result)
    return json.dumps(sarif_log, indent=indent, ensure_ascii=False)


def write_sarif_report(result: ScanResult, file_path: str, indent: int = 2) -> None:
    """Write scan results to a SARIF JSON file.

    Args:
        result: The scan result to write.
        file_path: Path to write the SARIF report to.
        indent: JSON indentation level.
    """
    sarif_log = _build_sarif_log(result)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(sarif_log, f, indent=indent, ensure_ascii=False)


def format_compact(result: ScanResult) -> str:
    """Format scan results as a compact (single-line) SARIF JSON string."""
    return format_scan_result(result, indent=None)


def _build_sarif_log(result: ScanResult) -> Dict:
    """Build the complete SARIF log object from scan results."""
    rules = _build_rules(result.findings)
    results = _build_results(result.findings)

    # Build the SARIF log
    sarif_log: Dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/sentinel-security/sentinel",
                        "rules": rules,
                    },
                },
                "results": results,
                "properties": {
                    "verdict": result.get_verdict().value,
                    "total_findings": len(result.findings),
                    "scanned_files": result.scanned_files,
                    "scan_time_ms": round(result.scan_time_ms, 2),
                    "severity_threshold": result.severity_threshold.value,
                },
            },
        ],
    }

    # Add invocation info if there are results
    if results:
        sarif_log["runs"][0]["invocations"] = [
            {
                "executionSuccessful": True,
            },
        ]

    return sarif_log
