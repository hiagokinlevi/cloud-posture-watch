#!/usr/bin/env python3
"""Main CLI entrypoint for cloud-posture-watch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Existing project imports (kept as-is in this file's context)
# NOTE: These imports are intentionally broad to match existing CLI behavior.
from reports.markdown import generate_markdown_report
from reports.json_report import generate_json_report
from analyzers.runner import run_analysis


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_value(value: str | None) -> int:
    if not value:
        return 0
    return SEVERITY_ORDER.get(str(value).strip().lower(), 0)


def _filter_findings_by_min_severity(findings: list[dict[str, Any]], min_severity: str | None) -> list[dict[str, Any]]:
    if not min_severity:
        return findings
    threshold = _severity_value(min_severity)
    if threshold <= 0:
        return findings
    return [f for f in findings if _severity_value(f.get("severity")) >= threshold]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cloud posture assessment CLI")

    # Existing options should remain; only additive change for this task.
    parser.add_argument("--output", choices=["markdown", "json", "both"], default="markdown")
    parser.add_argument("--output-path", default="posture-report")
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Only emit findings at or above this severity in Markdown/JSON output.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    analysis_result = run_analysis(args)

    # Keep collector/analyzer logic unchanged; filter only at output time.
    if isinstance(analysis_result, dict) and "findings" in analysis_result:
        analysis_result = dict(analysis_result)
        analysis_result["findings"] = _filter_findings_by_min_severity(
            list(analysis_result.get("findings", [])),
            args.min_severity,
        )

    output_base = Path(args.output_path)

    if args.output in ("markdown", "both"):
        markdown = generate_markdown_report(analysis_result)
        md_path = output_base.with_suffix(".md")
        md_path.write_text(markdown, encoding="utf-8")

    if args.output in ("json", "both"):
        json_obj = generate_json_report(analysis_result)
        json_path = output_base.with_suffix(".json")
        json_path.write_text(json.dumps(json_obj, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
