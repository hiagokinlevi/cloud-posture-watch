#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List, Optional


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return text if text in SEVERITY_ORDER else None


def _iter_finding_severities(payload: Any) -> Iterable[str]:
    """Yield normalized severities from common report structures."""
    if isinstance(payload, dict):
        sev = _normalize_severity(payload.get("severity"))
        if sev:
            yield sev

        # Common list containers in report payloads
        for key in ("findings", "issues", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    yield from _iter_finding_severities(item)

        # Recurse remaining nested values to be resilient to schema variants
        for value in payload.values():
            if isinstance(value, (dict, list)):
                yield from _iter_finding_severities(value)

    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_finding_severities(item)


def _should_fail_exit(policy: str, report_payload: Any) -> bool:
    if policy == "never":
        return False

    threshold = {
        "any": 1,
        "medium": 2,
        "high": 3,
    }[policy]

    for sev in _iter_finding_severities(report_payload):
        if SEVERITY_ORDER.get(sev, 0) >= threshold:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--input", help="Path to JSON findings/report input", required=False)
    parser.add_argument(
        "--exit-code-policy",
        choices=["never", "high", "medium", "any"],
        default="never",
        help=(
            "Control non-zero exit behavior based on finding severity: "
            "never|high|medium|any (default: never)."
        ),
    )
    return parser


def _load_report(input_path: Optional[str]) -> Dict[str, Any]:
    if not input_path:
        return {}
    with open(input_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report_payload = _load_report(args.input)

    # Existing report generation/output flow would run before this policy check.
    if _should_fail_exit(args.exit_code_policy, report_payload):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
