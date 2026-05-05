#!/usr/bin/env python3
"""
cloud_posture_watch_cli.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _safe_get(d: Dict[str, Any], key: str, default: Any):
    v = d.get(key, default)
    return default if v is None else v


def build_summary(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    by_severity: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    by_provider: Dict[str, int] = {}
    by_analyzer: Dict[str, int] = {}

    for f in findings:
        sev = str(_safe_get(f, "severity", "info")).lower()
        if sev not in by_severity:
            by_severity[sev] = 0
        by_severity[sev] += 1

        provider = str(_safe_get(f, "provider", "unknown")).lower()
        by_provider[provider] = by_provider.get(provider, 0) + 1

        analyzer = str(_safe_get(f, "analyzer", "unknown"))
        by_analyzer[analyzer] = by_analyzer.get(analyzer, 0) + 1

    return {
        "by_severity": by_severity,
        "by_provider": dict(sorted(by_provider.items(), key=lambda kv: kv[0])),
        "by_analyzer": dict(sorted(by_analyzer.items(), key=lambda kv: kv[0])),
    }


def render_markdown_report(findings: List[Dict[str, Any]], summary_only: bool = False) -> str:
    summary = build_summary(findings)

    lines: List[str] = []
    lines.append("# Cloud Posture Watch Report")
    lines.append("")
    lines.append(f"Total findings: **{len(findings)}**")
    lines.append("")

    lines.append("## Findings by Severity")
    for sev in SEVERITY_ORDER:
        if sev in summary["by_severity"]:
            lines.append(f"- {sev}: {summary['by_severity'][sev]}")
    for sev, count in summary["by_severity"].items():
        if sev not in SEVERITY_ORDER:
            lines.append(f"- {sev}: {count}")
    lines.append("")

    lines.append("## Findings by Provider")
    if summary["by_provider"]:
        for provider, count in summary["by_provider"].items():
            lines.append(f"- {provider}: {count}")
    else:
        lines.append("- none: 0")
    lines.append("")

    lines.append("## Findings by Analyzer")
    if summary["by_analyzer"]:
        for analyzer, count in summary["by_analyzer"].items():
            lines.append(f"- {analyzer}: {count}")
    else:
        lines.append("- none: 0")
    lines.append("")

    if not summary_only:
        lines.append("## Detailed Findings")
        if not findings:
            lines.append("No findings.")
        else:
            for idx, f in enumerate(findings, start=1):
                sev = _safe_get(f, "severity", "info")
                title = _safe_get(f, "title", "Untitled finding")
                provider = _safe_get(f, "provider", "unknown")
                resource = _safe_get(f, "resource", "unknown")
                analyzer = _safe_get(f, "analyzer", "unknown")
                lines.append(f"### {idx}. [{sev}] {title}")
                lines.append(f"- Provider: {provider}")
                lines.append(f"- Analyzer: {analyzer}")
                lines.append(f"- Resource: {resource}")
                description = f.get("description")
                if description:
                    lines.append(f"- Description: {description}")
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json_report(findings: List[Dict[str, Any]], summary_only: bool = False) -> Dict[str, Any]:
    summary = build_summary(findings)
    payload: Dict[str, Any] = {
        "total_findings": len(findings),
        "summary": summary,
    }
    if not summary_only:
        payload["findings"] = findings
    return payload


def load_findings_from_file(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        return data["findings"]
    raise ValueError("Input JSON must be a findings array or an object containing a 'findings' array")


def compute_exit_code(findings: List[Dict[str, Any]], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold_index = SEVERITY_ORDER.index(fail_on)
    severities = {str(_safe_get(f, "severity", "info")).lower() for f in findings}
    for sev in severities:
        if sev in SEVERITY_ORDER and SEVERITY_ORDER.index(sev) <= threshold_index:
            return 2
    return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument("--input", required=True, help="Path to findings JSON input")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", help="Output file path; defaults to stdout")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "none"],
        default="high",
        help="Exit non-zero if findings at/above severity exist",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Output only high-level totals (severity/provider/analyzer) and omit detailed findings",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    findings = load_findings_from_file(Path(args.input))

    if args.format == "markdown":
        out = render_markdown_report(findings, summary_only=args.summary_only)
    else:
        out = json.dumps(render_json_report(findings, summary_only=args.summary_only), indent=2) + "\n"

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)

    return compute_exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
