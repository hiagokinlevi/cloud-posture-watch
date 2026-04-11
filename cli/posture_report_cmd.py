"""
posture-report CLI Command
===========================
A `posture-report` sub-command for the k1n-posture CLI that generates
JSON, HTML, and/or SARIF reports from a PostureReport object built from
local findings data (no live cloud API calls required).

This command is designed for two use cases:
  1. Re-rendering a report from a previously saved JSON findings file
  2. Running a synthetic / offline multi-cloud scan using fixture data
     (useful in CI pipelines where cloud credentials are not available)

The command is registered in cli/main.py as `posture-report`.

Usage:
    k1n-posture posture-report --input findings.json --format html
    k1n-posture posture-report --input findings.json --format json
    k1n-posture posture-report --input findings.json --format all

Input JSON schema (produced by posture_report_json.py or the assess command):
  {
    "run_id": "...",
    "provider": "aws",
    "assessed_at": "2026-04-06T12:00:00Z",
    "baseline_name": "standard",
    "total_resources": 12,
    "findings": [ { "provider":"aws", "resource_type":"...", ... } ],
    "drift_items": []
  }
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from reports.posture_report_html import generate_html_report, save_html_report
from reports.posture_report_json import generate_json_report, save_json_report
from reports.posture_report_sarif import generate_sarif_report, save_sarif_report
from schemas.posture import (
    DriftItem,
    Importance,
    PostureFinding,
    PostureReport,
    Provider,
    Severity,
)


# ---------------------------------------------------------------------------
# Deserialization helpers
# ---------------------------------------------------------------------------

def _parse_finding(raw: dict) -> PostureFinding:
    """Deserialize a finding dict to a PostureFinding."""
    return PostureFinding(
        provider=Provider(raw["provider"]),
        resource_type=raw["resource_type"],
        resource_name=raw["resource_name"],
        severity=Severity(raw["severity"]),
        flag=raw["flag"],
        title=raw["title"],
        recommendation=raw["recommendation"],
        baseline_name=raw.get("baseline_name"),
        baseline_control=raw.get("baseline_control"),
    )


def _parse_drift(raw: dict) -> DriftItem:
    """Deserialize a drift dict to a DriftItem."""
    return DriftItem(
        provider=Provider(raw["provider"]),
        resource_type=raw["resource_type"],
        resource_name=raw["resource_name"],
        baseline_name=raw["baseline_name"],
        control=raw["control"],
        expected=raw["expected"],
        actual=raw["actual"],
        importance=Importance(raw["importance"]),
        severity=Severity(raw["severity"]),
    )


def _load_report_from_json(path: Path) -> PostureReport:
    """
    Load a PostureReport from a saved JSON findings file.

    Raises:
        click.ClickException: If the file is missing, invalid JSON, or missing
                              required fields.
    """
    if not path.exists():
        raise click.ClickException(f"Input file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON in {path}: {exc}") from exc

    try:
        # Parse the assessed_at timestamp — accept Z suffix
        assessed_at_str: str = raw.get("assessed_at", "")
        if assessed_at_str.endswith("Z"):
            assessed_at_str = assessed_at_str[:-1] + "+00:00"
        assessed_at = (
            datetime.fromisoformat(assessed_at_str)
            if assessed_at_str
            else datetime.now(tz=timezone.utc)
        )

        findings = [_parse_finding(f) for f in raw.get("findings", [])]
        drift    = [_parse_drift(d)   for d in raw.get("drift_items", [])]

        return PostureReport(
            run_id=raw.get("run_id", "unknown"),
            provider=Provider(raw["provider"]),
            baseline_name=raw.get("baseline_name"),
            total_resources=int(raw.get("total_resources", len(findings))),
            findings=findings,
            drift_items=drift,
            assessed_at=assessed_at,
        )
    except (KeyError, ValueError) as exc:
        raise click.ClickException(f"Failed to parse findings file: {exc}") from exc


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@click.command("posture-report")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(dir_okay=False),
    help="Path to a JSON findings file (produced by 'k1n-posture assess' or posture_report_json.py).",
)
@click.option(
    "--format",
    "output_format",
    default="both",
    type=click.Choice(["json", "html", "sarif", "both", "all"], case_sensitive=False),
    show_default=True,
    help="Output format(s) to generate.",
)
@click.option(
    "--output-dir",
    "output_dir",
    default="./output",
    show_default=True,
    type=click.Path(),
    help="Directory where report files will be written.",
)
@click.option(
    "--stdout",
    is_flag=True,
    default=False,
    help="Print the report to stdout instead of (or in addition to) saving to a file.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Exit with code 1 if findings at this severity or above are present.",
)
@click.pass_context
def posture_report_cmd(
    ctx: click.Context,
    input_file: str,
    output_format: str,
    output_dir: str,
    stdout: bool,
    fail_on: Optional[str],
) -> None:
    """
    Generate a JSON, HTML, and/or SARIF posture report from a saved findings file.

    The input file must be a JSON file produced by 'k1n-posture assess'
    or by the posture_report_json.py serializer.

    Examples:

    \b
      k1n-posture posture-report --input findings.json --format html
      k1n-posture posture-report --input findings.json --format sarif --output-dir ./reports
      k1n-posture posture-report --input findings.json --format all --stdout --fail-on high
    """
    report = _load_report_from_json(Path(input_file))

    resolved_output_dir = output_dir
    if (
        output_dir == "./output"
        and ctx.obj
        and isinstance(ctx.obj, dict)
        and ctx.obj.get("output_dir")
    ):
        resolved_output_dir = str(ctx.obj["output_dir"])

    output_path = Path(resolved_output_dir)
    written: list[Path] = []

    # Generate requested formats
    if output_format in ("json", "both", "all"):
        if stdout and output_format == "json":
            click.echo(generate_json_report(report))
        else:
            p = save_json_report(report, output_path)
            written.append(p)
            click.echo(f"JSON report: {p}")

    if output_format in ("html", "both", "all"):
        if stdout and output_format == "html":
            click.echo(generate_html_report(report))
        else:
            p = save_html_report(report, output_path)
            written.append(p)
            click.echo(f"HTML report: {p}")

    if output_format in ("sarif", "all"):
        if stdout and output_format == "sarif":
            click.echo(generate_sarif_report(report))
        else:
            p = save_sarif_report(report, output_path)
            written.append(p)
            click.echo(f"SARIF report: {p}")

    if output_format == "both" and stdout:
        # Both formats requested with --stdout: print JSON (more useful for piping)
        click.echo(generate_json_report(report))

    if output_format == "all" and stdout:
        # Multi-format stdout still prints the JSON representation for piping.
        click.echo(generate_json_report(report))

    # Summary line
    counts = report.finding_counts
    click.echo(
        f"\nSummary: {report.provider.value.upper()} | "
        f"CRITICAL={counts.get('critical',0)} "
        f"HIGH={counts.get('high',0)} "
        f"MEDIUM={counts.get('medium',0)} "
        f"LOW={counts.get('low',0)}"
    )

    # Exit gate
    if fail_on:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_rank[fail_on]
        if any(severity_rank.get(f.severity.value, 0) >= threshold for f in report.findings):
            click.echo(
                f"\nGate FAILED: findings at or above '{fail_on}' severity detected.",
                err=True,
            )
            sys.exit(1)
