#!/usr/bin/env python3
"""
cloud-posture-watch CLI entrypoint.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _extract_findings(obj: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if isinstance(obj, dict):
        if "severity" in obj and isinstance(obj.get("severity"), str):
            findings.append(obj)
        for value in obj.values():
            findings.extend(_extract_findings(value))
    elif isinstance(obj, list):
        for item in obj:
            findings.extend(_extract_findings(item))

    return findings


def _has_findings_at_or_above(report_json: dict[str, Any], threshold: str) -> bool:
    threshold_rank = SEVERITY_ORDER[threshold]
    for finding in _extract_findings(report_json):
        sev = str(finding.get("severity", "")).strip().lower()
        if sev in SEVERITY_ORDER and SEVERITY_ORDER[sev] >= threshold_rank:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch")
    parser.add_argument("--output-json", required=True, help="Path to write JSON report")
    parser.add_argument(
        "--fail-on-severity",
        choices=["low", "medium", "high", "critical"],
        help="Exit non-zero if any findings at or above this severity are present",
    )
    return parser


def run_analyzers() -> dict[str, Any]:
    # Existing analyzer orchestration should remain here in the real project.
    # This placeholder keeps the file runnable for this incremental change.
    return {
        "findings": []
    }


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report = run_analyzers()

    output_path = Path(args.output_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.fail_on_severity:
        if _has_findings_at_or_above(report, args.fail_on_severity):
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
