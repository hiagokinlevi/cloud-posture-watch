"""
`scan` CLI Command
===================
Runs a unified multi-cloud posture scan across all configured providers
(AWS, Azure, GCP) in a single pass and generates combined reports.

The command reads cloud credentials from environment variables:
  AWS:   AWS_REGION (default us-east-1), AWS_PROFILE
  Azure: AZURE_SUBSCRIPTION_ID
  GCP:   GCP_PROJECT_ID

Collectors that lack credentials are skipped gracefully — a missing
AZURE_SUBSCRIPTION_ID does not abort the AWS or GCP portions of the scan.

Usage:
    k1n-posture scan
    k1n-posture scan --providers aws,gcp
    k1n-posture scan --format html --output-dir ./reports
    k1n-posture scan --fail-on high
    k1n-posture scan --dry-run
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from providers.multi_cloud_scanner import (
    MultiCloudScanReport,
    ProviderScanConfig,
    ProviderScanResult,
    run_multi_cloud_scan,
)
from reports.posture_report_html import generate_html_report, save_html_report
from reports.posture_report_json import generate_json_report, save_json_report
from schemas.posture import DriftItem, PostureReport, Provider, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider_report(
    pr: ProviderScanResult,
    scan_id: str,
    scanned_at,
) -> PostureReport:
    """Wrap a ProviderScanResult in a single-provider PostureReport for serialisation."""
    return PostureReport(
        run_id=scan_id,
        provider=Provider(pr.provider),
        baseline_name="multi-cloud-scan",
        total_resources=pr.total_resources,
        findings=pr.findings,
        drift_items=[],
        assessed_at=scanned_at,
    )


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@click.command("scan")
@click.option(
    "--providers",
    default="aws,azure,gcp",
    show_default=True,
    help="Comma-separated list of cloud providers to scan (aws, azure, gcp).",
)
@click.option(
    "--format",
    "output_format",
    default="both",
    type=click.Choice(["json", "html", "both"], case_sensitive=False),
    show_default=True,
    help="Output format(s) for the generated report.",
)
@click.option(
    "--output-dir",
    "output_dir",
    default="./output",
    show_default=True,
    type=click.Path(),
    help="Directory to write report files into.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit code 1 if any finding at this severity or above is present.",
)
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    default=False,
    help="Skip all live API calls — validates CLI wiring without cloud credentials.",
)
def scan_cmd(
    providers: str,
    output_format: str,
    output_dir: str,
    fail_on: Optional[str],
    dry_run: bool,
) -> None:
    """
    Run a unified multi-cloud posture scan across all configured providers.

    Cloud credentials are read from environment variables:

    \b
      AWS:   AWS_REGION, AWS_PROFILE
      Azure: AZURE_SUBSCRIPTION_ID
      GCP:   GCP_PROJECT_ID

    Providers with missing credentials are skipped without aborting the scan.
    Use --dry-run to validate CLI wiring without live API calls.

    Examples:

    \b
      k1n-posture scan
      k1n-posture scan --providers aws,gcp --format html
      k1n-posture scan --fail-on high --output-dir ./reports
      k1n-posture scan --dry-run
    """
    provider_list = [p.strip().lower() for p in providers.split(",") if p.strip()]

    if dry_run:
        click.echo("[DRY RUN] Multi-cloud scan — no live API calls will be made.")

    click.echo(f"Scanning providers: {', '.join(p.upper() for p in provider_list)}")

    # Execute scan
    scan_report = run_multi_cloud_scan(providers=provider_list, dry_run=dry_run)
    click.echo(f"Scan ID: {scan_report.scan_id}")
    click.echo("")

    if dry_run:
        click.echo("Dry run complete. 0 resources scanned, 0 findings collected.")
        return

    # ------------------------------------------------------------------
    # Per-provider summary
    # ------------------------------------------------------------------
    for pr in scan_report.provider_results:
        ok = sum(1 for c in pr.collector_results if c.succeeded)
        total = len(pr.collector_results)
        status = "OK" if not pr.scan_errors and not pr.failed_collectors else "PARTIAL"
        click.echo(
            f"  [{status}] {pr.provider.upper()}: "
            f"{pr.total_resources} resources | "
            f"{len(pr.findings)} findings | "
            f"{ok}/{total} collectors succeeded"
        )
        for err in pr.scan_errors:
            click.echo(f"    WARNING: {err}", err=True)

    # ------------------------------------------------------------------
    # Totals
    # ------------------------------------------------------------------
    counts = scan_report.finding_counts
    click.echo(
        f"\nTotals: {scan_report.total_resources} resources | "
        f"Risk score: {scan_report.risk_score}/100 | "
        f"CRITICAL={counts['critical']} "
        f"HIGH={counts['high']} "
        f"MEDIUM={counts['medium']} "
        f"LOW={counts['low']}"
    )

    # ------------------------------------------------------------------
    # Report generation — one file per provider that has findings
    # ------------------------------------------------------------------
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for pr in scan_report.provider_results:
        if not pr.findings:
            continue
        pr_report = _provider_report(pr, scan_report.scan_id, scan_report.scanned_at)

        if output_format in ("json", "both"):
            p = save_json_report(pr_report, output_path)
            written.append(p)
            click.echo(f"JSON → {p}")

        if output_format in ("html", "both"):
            p = save_html_report(pr_report, output_path)
            written.append(p)
            click.echo(f"HTML → {p}")

    if not written:
        click.echo("No findings — report files not generated.")

    # ------------------------------------------------------------------
    # Severity gate
    # ------------------------------------------------------------------
    if fail_on and scan_report.meets_severity_gate(fail_on):
        click.echo(
            f"\nGate FAILED: findings at or above '{fail_on}' severity detected.",
            err=True,
        )
        sys.exit(1)
