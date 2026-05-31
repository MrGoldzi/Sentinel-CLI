"""Human-readable output formatter for CLI display."""

from __future__ import annotations

from typing import Dict, List

from ..models import Finding, ScanResult, Severity, Verdict


# ANSI color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# Icons for finding types
TYPE_ICONS: Dict[str, str] = {
    "secret": "🔑",
    "static_analysis": "⚠️",
    "dependency": "📦",
}


def _severity_color(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return f"{Colors.RED}{Colors.BOLD}"
    elif severity == Severity.HIGH:
        return Colors.RED
    elif severity == Severity.MEDIUM:
        return Colors.YELLOW
    else:
        return Colors.BLUE


def _severity_badge(severity: Severity) -> str:
    color = _severity_color(severity)
    return f"{color}{Colors.BOLD}[{severity.value}]{Colors.RESET}"


def _verdict_color(verdict: Verdict) -> str:
    if verdict == Verdict.PASS:
        return Colors.GREEN
    elif verdict == Verdict.WARN:
        return Colors.YELLOW
    else:
        return Colors.RED


def _rule_label(rule_id: str) -> str:
    return f"{Colors.DIM}{rule_id}{Colors.RESET}"


def _issue_type_icon(issue_type: str) -> str:
    return TYPE_ICONS.get(issue_type, "🔍")


def _format_file_extensions(files_by_ext: Dict[str, int]) -> str:
    """Format file extension breakdown as a compact string."""
    if not files_by_ext:
        return ""
    parts: List[str] = []
    sorted_exts = sorted(files_by_ext.items(), key=lambda x: -x[1])
    for ext_key, count in sorted_exts:
        ext_display = ext_key if ext_key != "(no ext)" else "(none)"
        parts.append(f"{Colors.DIM}{ext_display}: {count}{Colors.RESET}")
    return ", ".join(parts)


def format_scan_result(result: ScanResult, show_stats: bool = False) -> str:
    """Format scan results as a human-readable string.

    Args:
        result: The scan result to format.
        show_stats: If True, include detailed scan statistics.

    Returns:
        A formatted string suitable for CLI display.
    """
    verdict = result.get_verdict()
    lines: List[str] = []

    # Header
    lines.append("")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════{Colors.RESET}")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}  Sentinel Security Scan Report{Colors.RESET}")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════{Colors.RESET}")
    lines.append("")

    # Summary
    threshold_label = _severity_badge(result.severity_threshold)
    lines.append(f"{Colors.BOLD}Summary:{Colors.RESET}")
    if result.scanned_endpoints:
        lines.append(f"  Endpoints scanned: {result.scanned_endpoints}")
    else:
        lines.append(f"  Files scanned:     {result.scanned_files}")
    lines.append(f"  Findings found:    {len(result.findings)}")
    lines.append(f"  Severity threshold: {threshold_label}")
    lines.append(f"  Scan time:         {result.scan_time_ms:.0f}ms")
    if result.target_url:
        lines.append(f"  Target URL:        {result.target_url}")
    if result.scan_all:
        lines.append(f"  Scan mode:         {Colors.RED}FULL SCAN (all files){Colors.RESET}")
    elif result.no_gitignore:
        lines.append(f"  Scan mode:         {Colors.YELLOW}including .gitignored{Colors.RESET}")

    # Show file type breakdown in summary
    if result.files_by_extension and not result.scanned_endpoints:
        ext_line = _format_file_extensions(result.files_by_extension)
        if ext_line:
            lines.append(f"  File types:        {ext_line}")

    lines.append("")

    if not result.findings:
        lines.append(f"  {Colors.GREEN}{Colors.BOLD}✓ No security issues found.{Colors.RESET}")
        lines.append("")

    # Breakdown by severity
    if result.findings:
        lines.append(f"{Colors.BOLD}Findings by severity:{Colors.RESET}")
        critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in result.findings if f.severity == Severity.LOW)

        if critical_count:
            lines.append(f"  {Colors.RED}{Colors.BOLD}{critical_count} CRITICAL{Colors.RESET}")
        if high_count:
            lines.append(f"  {Colors.RED}{Colors.BOLD}{high_count} HIGH{Colors.RESET}")
        if med_count:
            lines.append(f"  {Colors.YELLOW}{Colors.BOLD}{med_count} MEDIUM{Colors.RESET}")
        if low_count:
            lines.append(f"  {Colors.BLUE}{low_count} LOW{Colors.RESET}")
        lines.append("")

        # ─── Findings by type ─────────────────────────────────────────
        by_type = result.findings_by_type
        if by_type:
            lines.append(f"{Colors.BOLD}Findings by type:{Colors.RESET}")
            for issue_type in sorted(by_type.keys()):
                icon = _issue_type_icon(issue_type)
                type_label = issue_type.replace("_", " ").title()
                lines.append(f"  {icon} {type_label}: {by_type[issue_type]}")
            lines.append("")

    # Detailed findings
    if result.findings:
        lines.append(f"{Colors.BOLD}Detailed findings:{Colors.RESET}")
        lines.append("")

        # Group findings by file
        findings_by_file: dict = {}
        for finding in result.findings:
            key = finding.file_path
            if key not in findings_by_file:
                findings_by_file[key] = []
            findings_by_file[key].append(finding)

        for file_path in sorted(findings_by_file.keys()):
            file_findings = findings_by_file[file_path]
            lines.append(f"  {Colors.MAGENTA}{Colors.BOLD}📄 {file_path}{Colors.RESET}")

            for finding in file_findings:
                badge = _severity_badge(finding.severity)
                rule = _rule_label(finding.rule_id)
                icon = _issue_type_icon(finding.issue_type)

                # File:Line reference
                line_ref = f"{Colors.DIM}line {finding.line_number}{Colors.RESET}"

                lines.append(
                    f"    {badge} {icon} {finding.message} {line_ref} {rule}"
                )

                # Show snippet if available
                if finding.snippet:
                    snippet = finding.snippet[:80]
                    lines.append(f"           {Colors.DIM}\u2514\u2500\u2192 {snippet}{Colors.RESET}")

                # Show detection method
                method = finding.detection_method
                method_str = f"{Colors.DIM}method: {method}{Colors.RESET}"
                lines.append(f"           {method_str}")

                # Show confidence
                conf_pct = int(finding.confidence * 100)
                conf_str = f"{Colors.DIM}confidence: {conf_pct}%{Colors.RESET}"
                lines.append(f"           {conf_str}")

                # Show remediation hint if available
                if finding.remediation_hint:
                    rem_str = f"{Colors.DIM}fix: {finding.remediation_hint[:120]}{Colors.RESET}"
                    lines.append(f"           {rem_str}")

                # Show CWE/OWASP if available (for DAST findings)
                dast_info_parts = []
                if finding.cwe_id:
                    dast_info_parts.append(f"{finding.cwe_id}")
                if finding.owasp_category:
                    dast_info_parts.append(f"{finding.owasp_category}")
                if dast_info_parts:
                    dast_str = f"{Colors.DIM}{' | '.join(dast_info_parts)}{Colors.RESET}"
                    lines.append(f"           {dast_str}")

                # Show endpoint if available (for DAST findings)
                if finding.endpoint and finding.endpoint != finding.file_path:
                    ep_str = f"{Colors.DIM}endpoint: {finding.endpoint}{Colors.RESET}"
                    lines.append(f"           {ep_str}")

                lines.append("")

    # ─── Detailed statistics (--stats flag) ───────────────────────────
    if show_stats:
        lines.append(f"{Colors.BOLD}── Scan Statistics ──{Colors.RESET}")
        lines.append("")

        # Scanner times
        if result.scanner_times_ms:
            lines.append(f"{Colors.BOLD}Scanner timing:{Colors.RESET}")
            total_time = result.scan_time_ms
            for scanner_name, scanner_time in sorted(
                result.scanner_times_ms.items(), key=lambda x: -x[1]
            ):
                pct = (scanner_time / total_time * 100) if total_time > 0 else 0
                label = scanner_name.replace("_", " ").title()
                lines.append(f"  {Colors.DIM}{label}: {scanner_time:.0f}ms ({pct:.0f}%){Colors.RESET}")
            lines.append(f"  {Colors.DIM}Total: {total_time:.0f}ms{Colors.RESET}")
            lines.append("")

        # File extension breakdown
        if result.files_by_extension:
            lines.append(f"{Colors.BOLD}File extension breakdown:{Colors.RESET}")
            sorted_exts = sorted(
                result.files_by_extension.items(), key=lambda x: -x[1]
            )
            total_files = sum(c for _, c in sorted_exts)
            for ext_key, count in sorted_exts:
                ext_display = ext_key if ext_key != "(no ext)" else "(no extension)"
                pct = (count / total_files * 100) if total_files > 0 else 0
                bar_len = max(1, int(pct / 5))
                bar = "▓" * min(bar_len, 20) + "░" * max(0, 20 - bar_len)
                lines.append(f"  {Colors.DIM}{ext_display:15} {count:5} ({pct:5.1f}%) {bar}{Colors.RESET}")
            lines.append("")

    # Verdict
    lines.append("")
    lines.append(f"{Colors.BOLD}────────────────────────────────────────{Colors.RESET}")
    verdict_colored = f"{_verdict_color(verdict)}{Colors.BOLD}{verdict.value}{Colors.RESET}"
    lines.append(f"  Verdict: {verdict_colored}")

    exit_code = verdict.exit_code
    lines.append(f"  Exit code: {exit_code}")
    lines.append(f"{Colors.BOLD}────────────────────────────────────────{Colors.RESET}")
    lines.append("")

    return "\n".join(lines)
