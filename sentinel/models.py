"""Data models for Sentinel security scanner findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class Severity(enum.Enum):
    """Severity levels for security findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self < other

    def __gt__(self, other: Severity) -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other: Severity) -> bool:
        return self == other or self > other


class DetectionMethod(enum.Enum):
    """Method used to detect a security finding."""
    REGEX = "regex"
    AST = "ast"
    ENTROPY = "entropy"
    HYBRID = "hybrid"
    DEPENDENCY = "dependency"

    def __str__(self) -> str:
        return self.value


class Verdict(enum.Enum):
    """Final security verdict for a scan."""

    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"

    @property
    def exit_code(self) -> int:
        """Get the process exit code for this verdict."""
        return {"PASS": 0, "WARN": 1, "BLOCK": 2}[self.value]

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """A single security finding discovered during scanning.

    Attributes:
        file_path: Relative path to the file containing the issue.
        line_number: Line number where the issue was found.
        issue_type: Category of issue ("secret", "static_analysis", "dependency").
        severity: Severity level (LOW, MEDIUM, HIGH).
        message: Human-readable description of the finding.
        rule_id: Unique identifier for the detection rule (e.g. "SEC-AWS-KEY").
        confidence: Confidence score from 0.0 to 1.0.
        snippet: Relevant code snippet showing the issue.
        detection_method: How the finding was detected (regex, ast, entropy, hybrid, dependency).
        remediation_hint: Optional suggestion for fixing the issue.
    """

    file_path: str
    line_number: int
    issue_type: str
    severity: Severity
    message: str
    rule_id: str
    confidence: float = 1.0
    snippet: str = ""
    detection_method: str = "regex"
    remediation_hint: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    endpoint: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict:
        """Convert finding to a JSON-serializable dictionary."""
        d: Dict = {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "issue_type": self.issue_type,
            "severity": self.severity.value,
            "message": self.message,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "snippet": self.snippet,
            "detection_method": self.detection_method,
            "remediation_hint": self.remediation_hint,
        }
        if self.cwe_id:
            d["cwe_id"] = self.cwe_id
        if self.owasp_category:
            d["owasp_category"] = self.owasp_category
        if self.endpoint:
            d["endpoint"] = self.endpoint
        if self.evidence:
            d["evidence"] = self.evidence
        return d

    def dedup_key(self) -> tuple:
        """Return a key used for deduplication."""
        return (self.file_path, self.line_number, self.rule_id, self.endpoint)


@dataclass
class ScanResult:
    """Aggregated result from running all scanners."""

    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_endpoints: int = 0
    scan_time_ms: float = 0.0
    severity_threshold: Severity = Severity.HIGH
    target_url: str = ""
    files_by_extension: Dict[str, int] = field(default_factory=dict)
    scanner_times_ms: Dict[str, float] = field(default_factory=dict)
    scan_all: bool = False
    no_gitignore: bool = False
    exclude_patterns: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)

    def deduplicate(self) -> None:
        """Remove duplicate findings based on file_path, line_number, and rule_id."""
        seen: set = set()
        unique: List[Finding] = []
        for finding in self.findings:
            key = finding.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        self.findings = unique

    @property
    def highest_severity(self) -> Optional[Severity]:
        """Get the highest severity level among all findings."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def findings_by_type(self) -> Dict[str, int]:
        """Get findings grouped by issue_type (secret, static_analysis, dependency)."""
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.issue_type] = counts.get(f.issue_type, 0) + 1
        return counts

    def get_verdict(self) -> Verdict:
        """Determine the final verdict based on findings and severity threshold.

        The severity threshold defines the minimum severity that triggers a BLOCK:
        - Findings at or above the threshold → BLOCK
        - Findings one tier below the threshold → WARN
        - Findings two tiers below the threshold or no findings → PASS

        Default threshold (HIGH) preserves original behavior:
          HIGH→BLOCK, MEDIUM→WARN, LOW→PASS

        CRITICAL threshold:
          CRITICAL→BLOCK, HIGH→WARN, MEDIUM→PASS, LOW→PASS
        """
        highest = self.highest_severity
        if highest is None:
            return Verdict.PASS

        threshold = self.severity_threshold
        _order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

        # At or above threshold → BLOCK
        if highest >= threshold:
            return Verdict.BLOCK

        # One tier below threshold → WARN
        if _order.index(threshold) - _order.index(highest) == 1:
            return Verdict.WARN

        # Two+ tiers below threshold → PASS
        return Verdict.PASS

    def to_dict(self) -> Dict:
        """Convert the full scan result to a dictionary."""
        d: Dict = {
            "verdict": self.get_verdict().value,
            "total_findings": len(self.findings),
            "scanned_files": self.scanned_files,
            "scanned_endpoints": self.scanned_endpoints,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "severity_threshold": self.severity_threshold.value,
            "findings": [f.to_dict() for f in self.findings],
            "files_by_extension": dict(self.files_by_extension),
            "scanner_times_ms": dict(self.scanner_times_ms),
        }
        if self.target_url:
            d["target_url"] = self.target_url
        if self.scan_all:
            d["scan_all"] = True
        if self.no_gitignore:
            d["no_gitignore"] = True
        return d
