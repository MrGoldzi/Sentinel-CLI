"""JSON output formatter for machine-readable scan results."""

from __future__ import annotations

import json
from typing import Dict, TextIO

from ..models import ScanResult


def format_scan_result(result: ScanResult, indent: int = 2) -> str:
    """Format scan results as a JSON string.

    Args:
        result: The scan result to format.
        indent: JSON indentation level (use None for compact output).

    Returns:
        A JSON-formatted string of the scan results.
    """
    data = result.to_dict()
    # The Finding.to_dict() already includes detection_method and remediation_hint
    # No changes needed here since models.py handles the serialization
    return json.dumps(data, indent=indent, ensure_ascii=False)


def write_json_report(result: ScanResult, file_path: str, indent: int = 2) -> None:
    """Write scan results to a JSON file.

    Args:
        result: The scan result to write.
        file_path: Path to write the JSON report to.
        indent: JSON indentation level.
    """
    data = result.to_dict()
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def format_compact(result: ScanResult) -> str:
    """Format scan results as a compact (single-line) JSON string."""
    return format_scan_result(result, indent=None)
