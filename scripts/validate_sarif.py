#!/usr/bin/env python3
"""
Validate Sentinel SARIF output against the official SARIF v2.1.0 JSON Schema.

Usage:
    python scripts/validate_sarif.py <sarif_file>
    python scripts/validate_sarif.py /tmp/sentinel_sarif_output.sarif

Downloads the official schema from OASIS if not cached locally.
Returns exit code 0 if valid, 1 if invalid.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)
CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", ".cache", "schemas")
CACHE_PATH = os.path.join(CACHE_DIR, "sarif-schema-2.1.0.json")


def download_schema() -> dict:
    """Download the official SARIF v2.1.0 schema, caching it locally."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return json.load(f)

    print(f"Downloading SARIF schema from {SCHEMA_URL}...")
    req = urllib.request.Request(
        SCHEMA_URL,
        headers={"User-Agent": "Sentinel/1.0"},
    )
    with urllib.request.urlopen(req) as response:
        schema = json.loads(response.read().decode("utf-8"))

    with open(CACHE_PATH, "w") as f:
        json.dump(schema, f, indent=2)
    print(f"Cached schema to {CACHE_PATH}")
    return schema


def validate_sarif(sarif_path: str, schema: dict) -> list[str]:
    """Validate a SARIF file against the schema. Returns list of error messages."""
    from jsonschema import Draft4Validator

    with open(sarif_path) as f:
        instance = json.load(f)

    validator = Draft4Validator(schema)

    errors: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=str):
        path = " → ".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
        errors.append(f"  • [{path}] {error.message}")

    return errors


def pretty_validate(sarif_path: str) -> bool:
    """Run validation and print formatted results."""
    print(f"\n{'='*60}")
    print("  SARIF v2.1.0 Schema Validation")
    print(f"{'='*60}")
    print(f"  File:   {sarif_path}")

    try:
        schema = download_schema()
    except Exception as e:
        print(f"\n  ❌ Failed to download schema: {e}")
        return False

    print(f"  Schema: {SCHEMA_URL}")
    print(f"  Draft:  {schema.get('$schema', 'unknown')}")
    print()

    try:
        errors = validate_sarif(sarif_path, schema)
    except json.JSONDecodeError as e:
        print(f"  ❌ Invalid JSON in SARIF file: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Validation error: {e}")
        return False

    if errors:
        print(f"  ❌ VALIDATION FAILED — {len(errors)} error(s):\n")
        for err in errors:
            print(err)
        print()
        return False
    else:
        file_size = os.path.getsize(sarif_path)
        print(f"  ✅ VALID — SARIF output conforms to the official v2.1.0 schema!")
        print(f"     File size: {file_size:,} bytes")
        print()
        return True


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sarif_file>")
        return 1

    sarif_path = sys.argv[1]
    if not os.path.exists(sarif_path):
        print(f"Error: File not found: {sarif_path}")
        return 1

    success = pretty_validate(sarif_path)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
