#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, Iterable, Optional


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    norm = str(value).strip().lower()
    return norm if norm in SEVERITY_ORDER else None


def _iter_findings(report_obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(report_obj, dict):
        findings = report_obj.get("findings")
        if isinstance(findings, list):
            for item in findings:
                if isinstance(item, dict):
                    yield item
        for section in report_obj.values():
            if isinstance(section, dict):
                nested_findings = section.get("findings")
                if isinstance(nested_findings, list):
                    for item in nested_findings:
                        if isinstance(item, dict):
                            yield item
            elif isinstance(section, list):
                for row in section:
                    if isinstance(row, dict) and "severity" in row:
                        yield row


def _max_report_severity(report_obj: Any) -> Optional[str]:
    best_rank = 0
    best = None
    for finding in _iter_findings(report_obj):
        sev = _normalize_severity(finding.get("severity"))
        if not sev:
            continue
        rank = SEVERITY_ORDER[sev]
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


def _should_fail_for_threshold(report_obj: Any, threshold: Optional[str]) -> bool:
    threshold_norm = _normalize_severity(threshold)
    if not threshold_norm:
        return False
    max_sev = _max_report_severity(report_obj)
    if not max_sev:
        return False
    return SEVERITY_ORDER[max_sev] >= SEVERITY_ORDER[threshold_norm]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument(
        "--exit-code-threshold",
        choices=["low", "medium", "high", "critical"],
        help="Exit non-zero if any finding is at or above this severity (for CI gating).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # NOTE: existing scan/report pipeline should populate this object.
    # This placeholder keeps the change bounded to CLI wiring for threshold gating.
    report: Any = {}

    # Existing implementation would run and emit normal reports before this gate.
    if _should_fail_for_threshold(report, args.exit_code_threshold):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
