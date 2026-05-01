#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--output-format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--fail-on-parser-warnings", action="store_true", help="Exit non-zero if parser/schema warnings are present in offline evidence analysis.")
    return parser


def _extract_parser_warnings(result: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    summary = result.get("summary") if isinstance(result, dict) else None
    if isinstance(summary, dict):
        for key in (
            "parser_warnings",
            "schema_warnings",
            "decode_warnings",
            "partial_decode_errors",
            "unsupported_versions",
            "skipped_records",
        ):
            value = summary.get(key)
            if isinstance(value, int) and value > 0:
                warnings.append(f"{key.replace('_', ' ')}: {value}")

    raw_warnings = result.get("warnings") if isinstance(result, dict) else None
    if isinstance(raw_warnings, list):
        for item in raw_warnings:
            if isinstance(item, str) and item.strip():
                warnings.append(item.strip())
            elif isinstance(item, dict):
                msg = item.get("message") or item.get("warning") or item.get("detail")
                if isinstance(msg, str) and msg.strip():
                    warnings.append(msg.strip())

    deduped: List[str] = []
    seen = set()
    for w in warnings:
        if w not in seen:
            seen.add(w)
            deduped.append(w)
    return deduped


def _emit_warning_summary_console(warnings: Iterable[str]) -> None:
    items = list(warnings)
    if not items:
        return
    print("\nParser/Schema Warning Summary:", file=sys.stderr)
    for line in items:
        print(f"- {line}", file=sys.stderr)


def _emit_output(result: Dict[str, Any], output_format: str, warnings: List[str]) -> None:
    if output_format == "json":
        payload = dict(result)
        payload["parser_warning_summary"] = {
            "count": len(warnings),
            "items": warnings,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(result.get("report_markdown", ""))
        if warnings:
            print("\n## Parser/Schema Warning Summary")
            for w in warnings:
                print(f"- {w}")


def run_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """Placeholder integration point for existing analyzer pipeline."""
    return {
        "summary": {},
        "warnings": [],
        "report_markdown": "",
        "exit_code": 0,
    }


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    result = run_analysis(args)
    warnings = _extract_parser_warnings(result)

    _emit_output(result, args.output_format, warnings)
    _emit_warning_summary_console(warnings)

    exit_code = int(result.get("exit_code", 0) or 0)
    if args.fail_on_parser_warnings and warnings:
        exit_code = 2 if exit_code == 0 else exit_code

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
