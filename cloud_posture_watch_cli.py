#!/usr/bin/env python3

import argparse
import json
from typing import Any, Dict, List


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Any) -> str:
    if value is None:
        return "low"
    return str(value).strip().lower()


def _passes_severity_threshold(finding: Dict[str, Any], threshold: str) -> bool:
    finding_rank = SEVERITY_RANK.get(_normalize_severity(finding.get("severity")), 1)
    threshold_rank = SEVERITY_RANK[threshold]
    return finding_rank >= threshold_rank


def filter_findings_by_severity_threshold(findings: List[Dict[str, Any]], threshold: str | None) -> List[Dict[str, Any]]:
    if not threshold:
        return findings
    return [f for f in findings if _passes_severity_threshold(f, threshold)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        help="Only include findings at or above this severity in rendered JSON/Markdown output",
    )
    return parser


def render_report(findings: List[Dict[str, Any]], severity_threshold: str | None = None) -> Dict[str, Any]:
    filtered = filter_findings_by_severity_threshold(findings, severity_threshold)
    return {"findings": filtered}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Placeholder findings pipeline input; in real runs findings come from collectors/analyzers.
    findings: List[Dict[str, Any]] = []
    report = render_report(findings, args.severity_threshold)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
