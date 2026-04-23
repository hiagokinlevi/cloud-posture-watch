#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SAFE_BASENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _normalize_output_name(raw: str) -> str:
    """Normalize a user-provided output name into a safe filename stem.

    - strips directory components
    - removes extension if present
    - replaces unsupported characters with '-'
    - trims leading/trailing separators
    - falls back to 'posture-report' when empty
    """
    candidate = (raw or "").strip()
    candidate = Path(candidate).name
    if "." in candidate:
        candidate = candidate.rsplit(".", 1)[0]
    candidate = SAFE_BASENAME_RE.sub("-", candidate)
    candidate = candidate.strip("-._ ")
    return candidate or "posture-report"


def _build_report_basename(output_name: str | None, timestamped: bool) -> str:
    base = _normalize_output_name(output_name or "posture-report")
    if not timestamped:
        return base
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{base}-{stamp}"


def write_report_artifacts(
    report_data: dict[str, Any],
    output_dir: str | Path = "reports",
    output_name: str | None = None,
    timestamped_output: bool = False,
) -> tuple[Path, Path]:
    """Write markdown and JSON report artifacts with controlled naming."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    basename = _build_report_basename(output_name, timestamped_output)
    md_path = out_dir / f"{basename}.md"
    json_path = out_dir / f"{basename}.json"

    summary = report_data.get("summary", {})
    findings = report_data.get("findings", [])

    md_lines = [
        "# Cloud Posture Watch Report",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
        "",
        "## Summary",
        "",
        f"- Total findings: {summary.get('total_findings', len(findings))}",
        f"- Critical: {summary.get('critical', 0)}",
        f"- High: {summary.get('high', 0)}",
        f"- Medium: {summary.get('medium', 0)}",
        f"- Low: {summary.get('low', 0)}",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        md_lines.append("No findings detected.")
    else:
        for idx, finding in enumerate(findings, start=1):
            md_lines.extend(
                [
                    f"### {idx}. {finding.get('title', 'Untitled finding')}",
                    f"- Severity: {finding.get('severity', 'unknown')}",
                    f"- Provider: {finding.get('provider', 'unknown')}",
                    f"- Resource: {finding.get('resource', 'n/a')}",
                    f"- Description: {finding.get('description', '')}",
                    "",
                ]
            )

    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    json_path.write_text(json.dumps(report_data, indent=2, sort_keys=True), encoding="utf-8")

    return md_path, json_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch")
    parser.add_argument("--output-dir", default="reports", help="Directory for report artifacts")
    parser.add_argument(
        "--output-name",
        default=None,
        help="Base filename for report artifacts (deterministic for pipelines)",
    )
    parser.add_argument(
        "--timestamped-output",
        action="store_true",
        help="Append UTC timestamp suffix to output filename for archival",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Analyzer/collector execution remains unchanged and is represented here
    # by a placeholder report payload for artifact writing.
    report_payload: dict[str, Any] = {
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
    }

    md_path, json_path = write_report_artifacts(
        report_data=report_payload,
        output_dir=args.output_dir,
        output_name=args.output_name,
        timestamped_output=args.timestamped_output,
    )

    print(f"Wrote Markdown report: {md_path}")
    print(f"Wrote JSON report: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
