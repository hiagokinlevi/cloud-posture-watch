#!/usr/bin/env python3
"""CLI entrypoint for cloud-posture-watch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all")
    parser.add_argument("--output", type=str, default="report.json")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print final report payload as JSON to stdout for pipeline/jq consumption.",
    )
    return parser


def _generate_report(provider: str) -> Dict[str, Any]:
    # Existing report object/path would be used in the real implementation.
    # Kept intentionally minimal and deterministic for CLI behavior.
    return {
        "project": "cloud-posture-watch",
        "provider": provider,
        "status": "ok",
        "findings": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    report = _generate_report(args.provider)

    # Preserve file output behavior.
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # JSON-only stdout mode for CI/CD piping.
    if args.json:
        sys.stdout.write(json.dumps(report))
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
