#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_json_report(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _finding_identity(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(f.get("provider", "")),
        str(f.get("service", "")),
        str(f.get("resource_id", "")),
        str(f.get("rule_id", f.get("check_id", ""))),
    )


def _extract_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = report.get("findings")
    if isinstance(findings, list):
        return [x for x in findings if isinstance(x, dict)]
    return []


def _resolve_latest_snapshot(artifacts_dir: Path) -> Optional[Path]:
    if not artifacts_dir.exists() or not artifacts_dir.is_dir():
        return None
    candidates = sorted(
        [p for p in artifacts_dir.glob("*.json") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _classify_new_findings(current_report: Dict[str, Any], previous_report: Dict[str, Any]) -> Tuple[int, int]:
    current = _extract_findings(current_report)
    previous = _extract_findings(previous_report)

    prev_ids = {_finding_identity(f) for f in previous}
    new_count = sum(1 for f in current if _finding_identity(f) not in prev_ids)
    existing_count = len(current) - new_count
    return new_count, existing_count


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloud-posture-watch")
    p.add_argument("--report-json", help="Path to current JSON report", required=False)
    p.add_argument("--exit-on-findings", action="store_true", help="Exit non-zero when any findings exist")
    p.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit non-zero only when newly introduced findings exist compared to --prior-report-json or latest watch snapshot",
    )
    p.add_argument(
        "--prior-report-json",
        help="Path to prior JSON report used for drift/new-finding comparison",
        required=False,
    )
    p.add_argument(
        "--watch-artifacts-dir",
        default="watch-artifacts",
        help="Directory containing watch mode JSON snapshots (used when --prior-report-json is not supplied)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if not args.report_json:
        print("error: --report-json is required for this command", file=sys.stderr)
        return 2

    report_path = Path(args.report_json)
    if not report_path.exists():
        print(f"error: report file not found: {report_path}", file=sys.stderr)
        return 2

    current_report = _load_json_report(report_path)
    findings = _extract_findings(current_report)

    # Standard behavior: fail on any findings.
    exit_code = 0
    if args.exit_on_findings and findings:
        exit_code = 1

    # Drift-aware CI behavior: fail only on newly introduced findings.
    if args.fail_on_new:
        prior_path: Optional[Path] = None
        if args.prior_report_json:
            prior_path = Path(args.prior_report_json)
        else:
            prior_path = _resolve_latest_snapshot(Path(args.watch_artifacts_dir))

        if prior_path is None or not prior_path.exists():
            print(
                "warning: --fail-on-new enabled but no prior report found; treating all findings as existing and passing",
                file=sys.stderr,
            )
            return 0

        prior_report = _load_json_report(prior_path)
        new_count, existing_count = _classify_new_findings(current_report, prior_report)

        print(
            f"drift comparison: new_findings={new_count} existing_findings={existing_count} prior={prior_path}",
            file=sys.stderr,
        )
        if new_count > 0:
            return 1
        return 0

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
