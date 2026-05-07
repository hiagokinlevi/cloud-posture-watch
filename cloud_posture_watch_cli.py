#!/usr/bin/env python3
"""
cloud-posture-watch CLI entrypoint.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable


# NOTE: Existing imports and project wiring are intentionally left minimal here.
# This file adds deterministic findings sorting with --sort-findings.


def _finding_sort_key_severity(finding: dict[str, Any]) -> tuple[int, str, str]:
    sev = str(finding.get("severity", "")).lower()
    sev_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "informational": 4,
    }.get(sev, 5)
    resource = str(
        finding.get("resource")
        or finding.get("resource_id")
        or finding.get("id")
        or ""
    )
    title = str(finding.get("title") or finding.get("check_id") or "")
    return (sev_rank, resource, title)


def _finding_sort_key_resource(finding: dict[str, Any]) -> tuple[str, int, str]:
    resource = str(
        finding.get("resource")
        or finding.get("resource_id")
        or finding.get("id")
        or ""
    )
    sev = str(finding.get("severity", "")).lower()
    sev_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "informational": 4,
    }.get(sev, 5)
    title = str(finding.get("title") or finding.get("check_id") or "")
    return (resource, sev_rank, title)


def sort_findings(findings: Iterable[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    items = list(findings)
    if mode == "severity":
        return sorted(items, key=_finding_sort_key_severity)
    if mode == "resource":
        return sorted(items, key=_finding_sort_key_resource)
    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")

    # ... existing args ...
    parser.add_argument(
        "--sort-findings",
        choices=["none", "severity", "resource"],
        default="none",
        help=(
            "Sort findings before report emission for deterministic diffs. "
            "Accepted values: none (default), severity, resource"
        ),
    )

    return parser


def _emit_reports(result: dict[str, Any], sort_mode: str) -> dict[str, Any]:
    """Apply deterministic sorting before markdown/json/sarif generation."""
    findings = result.get("findings", [])
    result["findings"] = sort_findings(findings, sort_mode)

    # Keep SARIF result ordering deterministic when present.
    sarif = result.get("sarif")
    if isinstance(sarif, dict):
        runs = sarif.get("runs")
        if isinstance(runs, list):
            for run in runs:
                if isinstance(run, dict) and isinstance(run.get("results"), list):
                    run["results"] = sort_findings(run["results"], sort_mode)

    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Existing execution/analyzer flow placeholder.
    result: dict[str, Any] = {"findings": []}

    result = _emit_reports(result, args.sort_findings)

    # Existing writers/emitters would consume `result`.
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
