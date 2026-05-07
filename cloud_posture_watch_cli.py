#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    provider: str = ""
    resource: str = ""


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "").strip().lower(), -1)


def _finding_sort_key(f: Dict[str, Any]) -> Any:
    sev = str(f.get("severity", "")).lower()
    return (
        -_severity_rank(sev),
        str(f.get("id", "")),
        str(f.get("provider", "")),
        str(f.get("resource", "")),
        str(f.get("title", "")),
    )


def _apply_max_findings(report: Dict[str, Any], max_findings: Optional[int]) -> Dict[str, Any]:
    findings = list(report.get("findings", []) or [])
    findings_sorted = sorted(findings, key=_finding_sort_key)
    total = len(findings_sorted)

    if max_findings is None:
        displayed = total
        truncated = False
        limited = findings_sorted
    else:
        cap = max(0, int(max_findings))
        limited = findings_sorted[:cap]
        displayed = len(limited)
        truncated = displayed < total

    report["findings"] = limited

    summary = dict(report.get("summary", {}) or {})
    summary["findings_total"] = total
    summary["findings_displayed"] = displayed
    summary["findings_truncated"] = truncated
    summary["findings_display"] = f"displayed {displayed} of {total} findings"
    report["summary"] = summary

    # Markdown/SARIF generators commonly consume top-level helper text if present.
    report["truncation_notice"] = summary["findings_display"]

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Cap emitted findings after severity sorting (highest first); summary includes displayed X of Y.",
    )
    return parser


def _emit(report: Dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True)
    if fmt == "markdown":
        summary = report.get("summary", {})
        lines = [
            "# cloud-posture-watch report",
            "",
            f"- {summary.get('findings_display', '')}",
            "",
            "## Findings",
        ]
        for f in report.get("findings", []):
            lines.append(f"- [{f.get('severity','')}] {f.get('id','')}: {f.get('title','')}")
        return "\n".join(lines)
    # sarif (minimal wrapper)
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "cloud-posture-watch"}},
                    "properties": {"summary": report.get("summary", {})},
                    "results": report.get("findings", []),
                }
            ],
        },
        indent=2,
        sort_keys=True,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Placeholder report assembly (real collectors/analyzers populate this in project runtime)
    report: Dict[str, Any] = {"summary": {}, "findings": []}

    report = _apply_max_findings(report, args.max_findings)
    print(_emit(report, args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
