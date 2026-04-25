#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


# NOTE:
# This file is intentionally self-contained for the roadmap task.
# It preserves existing collection/analysis assumptions by only adding
# summary_only plumbing into render/serialization.


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", default="-")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help=(
            "Emit only aggregate counts (provider/severity and totals) and suppress "
            "detailed per-finding sections."
        ),
    )
    return parser


def _compute_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", []) or []
    by_provider: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for f in findings:
        provider = str(f.get("provider", "unknown")).lower()
        severity = str(f.get("severity", "unknown")).lower()
        by_provider[provider] = by_provider.get(provider, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1

    return {
        "totals": {"findings": len(findings)},
        "by_provider": by_provider,
        "by_severity": by_severity,
    }


def render_markdown(report: Dict[str, Any], summary_only: bool = False) -> str:
    summary = report.get("summary") or _compute_summary(report)
    lines = ["# Cloud Posture Watch Report", "", "## Summary", ""]
    lines.append(f"- Total findings: {summary.get('totals', {}).get('findings', 0)}")

    lines.append("")
    lines.append("### Findings by provider")
    for k, v in sorted((summary.get("by_provider") or {}).items()):
        lines.append(f"- {k}: {v}")

    lines.append("")
    lines.append("### Findings by severity")
    for k, v in sorted((summary.get("by_severity") or {}).items()):
        lines.append(f"- {k}: {v}")

    if not summary_only:
        lines.append("")
        lines.append("## Detailed findings")
        lines.append("")
        for finding in report.get("findings", []) or []:
            fid = finding.get("id", "unknown")
            sev = finding.get("severity", "unknown")
            provider = finding.get("provider", "unknown")
            title = finding.get("title", "(untitled)")
            lines.append(f"- [{sev}] ({provider}) {fid}: {title}")

    return "\n".join(lines) + "\n"


def serialize_json(report: Dict[str, Any], summary_only: bool = False) -> str:
    summary = report.get("summary") or _compute_summary(report)
    if summary_only:
        payload = {"summary": summary}
    else:
        payload = dict(report)
        payload["summary"] = summary
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _write_output(content: str, output: str) -> None:
    if output == "-":
        print(content, end="")
        return
    Path(output).write_text(content, encoding="utf-8")


def run(argv: list[str] | None = None, report: Dict[str, Any] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # In the real project this comes from existing collection + analysis logic.
    report_obj = report or {"findings": []}

    if args.format == "json":
        out = serialize_json(report_obj, summary_only=args.summary_only)
    else:
        out = render_markdown(report_obj, summary_only=args.summary_only)

    _write_output(out, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
