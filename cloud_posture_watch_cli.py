#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_value(severity: str) -> int:
    return SEVERITY_ORDER.get(str(severity).strip().lower(), 0)


def _filter_findings_by_min_severity(findings: List[Dict[str, Any]], min_severity: str | None) -> List[Dict[str, Any]]:
    if not min_severity:
        return findings
    threshold = _severity_value(min_severity)
    return [f for f in findings if _severity_value(f.get("severity", "")) >= threshold]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--json", dest="json_out", help="Write JSON report to path")
    parser.add_argument("--markdown", dest="md_out", help="Write Markdown report to path")
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        help="Only include findings at or above this severity in outputs",
    )
    return parser


def _render_markdown(findings: List[Dict[str, Any]]) -> str:
    counts = {k: 0 for k in SEVERITY_ORDER.keys()}
    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1

    lines = [
        "# cloud-posture-watch report",
        "",
        "## Summary",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        f"- Total: {len(findings)}",
        "",
        "## Findings",
    ]

    if not findings:
        lines.append("- No findings in selected severity scope.")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.extend(
            [
                f"### {f.get('id', 'unknown')} ({str(f.get('severity', 'unknown')).upper()})",
                f"- Provider: {f.get('provider', 'unknown')}",
                f"- Resource: {f.get('resource', 'unknown')}",
                f"- Description: {f.get('description', '')}",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    args = _build_parser().parse_args()

    # In-repo analyzers populate this list in real execution paths.
    # Keeping this as a generic container allows the severity filter to apply
    # consistently before all output rendering.
    findings: List[Dict[str, Any]] = []

    filtered_findings = _filter_findings_by_min_severity(findings, args.min_severity)

    payload = {
        "summary": {
            "total": len(filtered_findings),
            "critical": sum(1 for f in filtered_findings if str(f.get("severity", "")).lower() == "critical"),
            "high": sum(1 for f in filtered_findings if str(f.get("severity", "")).lower() == "high"),
            "medium": sum(1 for f in filtered_findings if str(f.get("severity", "")).lower() == "medium"),
            "low": sum(1 for f in filtered_findings if str(f.get("severity", "")).lower() == "low"),
        },
        "findings": filtered_findings,
    }

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.md_out:
        Path(args.md_out).write_text(_render_markdown(filtered_findings), encoding="utf-8")

    if not args.json_out and not args.md_out:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
