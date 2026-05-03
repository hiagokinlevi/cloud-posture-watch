#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", required=True, help="Output report path")
    parser.add_argument(
        "--json-indent",
        type=int,
        default=None,
        help="Optional JSON indentation size for report output (e.g. 2 for pretty-print).",
    )
    return parser


def generate_report(provider: str) -> Dict[str, Any]:
    # Existing report generation flow lives in project modules.
    # Kept intentionally minimal here.
    return {
        "provider": provider,
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }


def write_report(report: Dict[str, Any], output: Path, fmt: str, json_indent: int | None = None) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        output.write_text(json.dumps(report, indent=json_indent) + "\n", encoding="utf-8")
    else:
        # Markdown path unchanged for this task.
        output.write_text("# cloud-posture-watch report\n", encoding="utf-8")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report = generate_report(args.provider)
    write_report(report, Path(args.output), args.format, json_indent=args.json_indent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
