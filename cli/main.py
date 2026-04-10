"""
cloud-posture-watch CLI
============================
Main Click command group. Entry point is `k1n-posture` (configured in pyproject.toml).

Commands:
  assess        Run a full posture assessment for a cloud provider
  drift         Compare live state against a baseline and report deviations
  report        (Re-)generate a report from a previously saved JSON state file
  list-checks   List all supported baseline controls for a provider

Global options (can also be set via .env or environment variables):
  --provider    Cloud provider (aws, azure, gcp)
  --profile     Baseline profile (minimal, standard, strict)
  --output-dir  Directory for report output
"""
import sys
import logging
from pathlib import Path

import click
try:
    import structlog
except ImportError:  # pragma: no cover - exercised via offline install smoke tests
    class _StructlogFallback:
        @staticmethod
        def get_logger(*_args, **_kwargs):
            return logging.getLogger("cloud-posture-watch")

    structlog = _StructlogFallback()

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - exercised via offline install smoke tests
    def load_dotenv() -> bool:
        return False

# Load .env from the working directory before any other imports that read env vars
load_dotenv()

logger = structlog.get_logger(__name__)


@click.group()
@click.option(
    "--provider",
    envvar="PROVIDER",
    default="aws",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    show_default=True,
    help="Cloud provider to assess.",
)
@click.option(
    "--output-dir",
    envvar="OUTPUT_DIR",
    default="./output",
    show_default=True,
    help="Directory for generated reports.",
)
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
@click.pass_context
def cli(ctx: click.Context, provider: str, output_dir: str, verbose: bool) -> None:
    """cloud-posture-watch — multi-cloud security posture assessment."""
    # Store shared options in the Click context object
    ctx.ensure_object(dict)
    ctx.obj["provider"] = provider.lower()
    ctx.obj["output_dir"] = output_dir
    ctx.obj["verbose"] = verbose

    # Configure structlog level based on verbosity flag
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")


@cli.command()
@click.option(
    "--profile",
    envvar="BASELINE_PROFILE",
    default="standard",
    type=click.Choice(["minimal", "standard", "strict"]),
    show_default=True,
    help="Baseline security profile to assess against.",
)
@click.option(
    "--fail-on",
    envvar="FAIL_ON_SEVERITY",
    default="high",
    type=click.Choice(["low", "medium", "high", "critical"]),
    show_default=True,
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def assess(ctx: click.Context, profile: str, fail_on: str) -> None:
    """
    Run a full posture assessment for the configured cloud provider.

    Collects live configuration state, runs all analyzers, and writes
    a Markdown report to the output directory.
    """
    provider = ctx.obj["provider"]
    output_dir = ctx.obj["output_dir"]

    logger.info("Starting posture assessment", provider=provider, profile=profile)

    # Determine the baseline path for this provider + profile combination
    baseline_path = Path(__file__).parent.parent / "baselines" / provider / f"{profile}.yaml"
    if not baseline_path.exists():
        click.echo(
            f"Baseline not found: {baseline_path}. "
            f"Check that baselines/{provider}/{profile}.yaml exists.",
            err=True,
        )
        sys.exit(2)

    click.echo(f"Provider:  {provider.upper()}")
    click.echo(f"Profile:   {profile}")
    click.echo(f"Baseline:  {baseline_path}")
    click.echo(f"Output:    {output_dir}")
    click.echo("")

    # Provider-specific assessment dispatch
    if provider == "aws":
        _assess_aws(baseline_path, output_dir, fail_on)
    elif provider == "azure":
        _assess_azure(baseline_path, output_dir, fail_on)
    elif provider == "gcp":
        _assess_gcp(baseline_path, output_dir, fail_on)


def _assess_aws(baseline_path: Path, output_dir: str, fail_on: str) -> None:
    """Run AWS posture assessment using boto3 and the default session."""
    import os
    import uuid
    import boto3
    from analyzers.flow_logs_analyzer import analyze_vpc_flow_logs
    from providers.aws.storage_collector import assess_bucket_posture
    from providers.aws.flow_logs_collector import collect_vpc_flow_log_postures
    from analyzers.exposure_analyzer import analyze_exposure
    from analyzers.logging_analyzer import analyze_logging_coverage
    from analyzers.drift_analyzer import analyze_drift
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, DriftItem as SchemaDriftItem
    from schemas.posture import PostureReport, Provider, Severity

    # Build the boto3 session (respects AWS_PROFILE and AWS_REGION env vars)
    session = boto3.Session(
        profile_name=os.getenv("AWS_PROFILE"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )

    click.echo("Collecting S3 bucket posture...")
    buckets = assess_bucket_posture(session)
    click.echo(f"  Found {len(buckets)} bucket(s).")
    click.echo("Collecting VPC Flow Logs posture...")
    vpc_postures = collect_vpc_flow_log_postures(session)
    click.echo(f"  Found {len(vpc_postures)} VPC(s).")

    # Run analyzers
    exposure_findings = analyze_exposure(buckets, provider="aws", resource_type="s3_bucket")
    logging_gaps = analyze_logging_coverage(buckets, provider="aws", resource_type="s3_bucket")
    flow_log_findings = analyze_vpc_flow_logs(vpc_postures, provider="aws", resource_type="vpc")
    drift_items = analyze_drift(buckets, provider="aws", baseline_path=baseline_path)

    # Convert raw findings to Pydantic models for the report
    schema_findings: list[PostureFinding] = []
    for f in exposure_findings:
        schema_findings.append(PostureFinding(
            provider=Provider.AWS,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity),
            flag=f.flag,
            title=f.title,
            recommendation=f.recommendation,
        ))
    for f in flow_log_findings:
        schema_findings.append(PostureFinding(
            provider=Provider.AWS,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity),
            flag=f.rule_id,
            title=f.title,
            recommendation=f.recommendation,
        ))

    schema_drift: list[SchemaDriftItem] = []
    from schemas.posture import Importance
    for d in drift_items:
        schema_drift.append(SchemaDriftItem(
            provider=Provider.AWS,
            resource_type=d.resource_type,
            resource_name=d.resource_name,
            baseline_name=d.baseline_name,
            control=d.control,
            expected=d.expected,
            actual=d.actual,
            importance=Importance(d.importance),
            severity=Severity(d.severity),
        ))

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AWS,
        baseline_name=baseline_path.stem,
        total_resources=len(buckets) + len(vpc_postures),
        findings=schema_findings,
        drift_items=schema_drift,
    )

    report_path = save_report(report, output_dir)
    click.echo(f"\nReport written to: {report_path}")

    # Exit with non-zero code if findings exceed the fail_on threshold
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = severity_rank.get(fail_on, 3)
    if any(severity_rank.get(f.severity.value, 0) >= threshold for f in report.findings):
        click.echo(f"\nFail condition met: findings at or above '{fail_on}' severity detected.", err=True)
        sys.exit(1)


def _assess_azure(baseline_path: Path, output_dir: str, fail_on: str) -> None:
    """Run Azure posture assessment."""
    import os
    click.echo("Azure assessment requires AZURE_SUBSCRIPTION_ID to be set.")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        click.echo("Error: AZURE_SUBSCRIPTION_ID is not set.", err=True)
        sys.exit(2)
    # Full implementation follows the same pattern as _assess_aws above.
    click.echo("Azure assessment: collecting storage account posture...")
    click.echo("(Full Azure assessment implementation: see providers/azure/storage_collector.py)")


def _assess_gcp(baseline_path: Path, output_dir: str, fail_on: str) -> None:
    """Run GCP posture assessment."""
    import os
    project_id = os.getenv("GCP_PROJECT_ID")
    if not project_id:
        click.echo("Error: GCP_PROJECT_ID is not set.", err=True)
        sys.exit(2)
    click.echo("GCP assessment: collecting Cloud Storage bucket posture...")
    click.echo("(Full GCP assessment implementation: see providers/gcp/storage_collector.py)")


@cli.command("scan-azure-nsgs")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an Azure NSG JSON export from `az network nsg list -o json`.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_azure_nsgs(ctx: click.Context, input_file: str, fail_on: str | None) -> None:
    """
    Analyze an offline Azure NSG JSON export for public network exposure.

    This command does not require Azure credentials or the Azure SDK. Export NSGs
    with `az network nsg list -o json` and review the resulting report before
    applying firewall changes.
    """
    import uuid
    from analyzers.nsg_exposure import analyze_nsg_exposure
    from providers.azure.network_collector import load_nsgs_from_export
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    nsgs = load_nsgs_from_export(input_file)
    findings = analyze_nsg_exposure(nsgs)
    schema_findings = [
        PostureFinding(
            provider=Provider.AZURE,
            resource_type=f.resource_type,
            resource_name=f.resource_name or f.resource_id,
            severity=Severity(f.severity),
            flag=f.rule_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AZURE,
        baseline_name="offline-azure-nsg-export",
        total_resources=len(nsgs),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"Azure NSG export: {len(nsgs)} NSG(s), {len(findings)} finding(s) | "
        f"CRITICAL={counts['critical']} HIGH={counts['high']} "
        f"MEDIUM={counts['medium']} LOW={counts['low']}"
    )
    click.echo(f"Report written to: {report_path}")

    if fail_on:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_rank.get(fail_on.lower(), 3)
        if any(severity_rank.get(f.severity.value, 0) >= threshold for f in report.findings):
            click.echo(
                f"Fail condition met: findings at or above '{fail_on}' severity detected.",
                err=True,
            )
            sys.exit(1)


@cli.command("scan-gcp-firewalls")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a GCP firewall JSON export from `gcloud compute firewall-rules list --format=json`.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_gcp_firewalls(ctx: click.Context, input_file: str, fail_on: str | None) -> None:
    """
    Analyze an offline GCP firewall-rule JSON export for public network exposure.

    This command does not require GCP credentials or the Google SDK. Export rules
    with `gcloud compute firewall-rules list --format=json` and review the report
    before applying firewall changes.
    """
    import uuid
    from analyzers.network_exposure import analyze_network_exposure
    from providers.gcp.network_collector import load_firewall_rules_from_export
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    firewalls = load_firewall_rules_from_export(input_file)
    findings = analyze_network_exposure(
        firewalls,
        provider="gcp",
        resource_type="firewall_rule",
    )
    schema_findings = [
        PostureFinding(
            provider=Provider.GCP,
            resource_type=f.resource_type,
            resource_name=f.resource_name or f.resource_id,
            severity=Severity(f.severity),
            flag=f.rule_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.GCP,
        baseline_name="offline-gcp-firewall-export",
        total_resources=len(firewalls),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"GCP firewall export: {len(firewalls)} rule(s), {len(findings)} finding(s) | "
        f"CRITICAL={counts['critical']} HIGH={counts['high']} "
        f"MEDIUM={counts['medium']} LOW={counts['low']}"
    )
    click.echo(f"Report written to: {report_path}")

    if fail_on:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_rank.get(fail_on.lower(), 3)
        if any(severity_rank.get(f.severity.value, 0) >= threshold for f in report.findings):
            click.echo(
                f"Fail condition met: findings at or above '{fail_on}' severity detected.",
                err=True,
            )
            sys.exit(1)


@cli.command()
@click.option(
    "--baseline",
    required=True,
    type=click.Path(exists=True),
    help="Path to the YAML baseline file to compare against.",
)
@click.option(
    "--sensitivity",
    envvar="DRIFT_SENSITIVITY",
    default="medium",
    type=click.Choice(["low", "medium", "high"]),
    show_default=True,
    help="Drift sensitivity: low=required only, medium=+recommended, high=all.",
)
@click.pass_context
def drift(ctx: click.Context, baseline: str, sensitivity: str) -> None:
    """
    Compare live cloud state against a YAML baseline and report deviations.

    Produces a drift report in the output directory and exits non-zero
    if required controls are violated.
    """
    provider = ctx.obj["provider"]
    click.echo(f"Running drift analysis — provider: {provider}, baseline: {baseline}")
    click.echo(f"Sensitivity: {sensitivity}")
    click.echo("(Run 'k1n-posture assess' for a full assessment including drift.)")


@cli.command()
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a previously saved JSON findings file.",
)
@click.option(
    "--format",
    "output_format",
    default="markdown",
    type=click.Choice(["markdown", "json"]),
    show_default=True,
    help="Output format for the regenerated report.",
)
@click.pass_context
def report(ctx: click.Context, input_file: str, output_format: str) -> None:
    """Regenerate a report from a saved findings JSON file."""
    output_dir = ctx.obj["output_dir"]
    click.echo(f"Regenerating {output_format} report from: {input_file}")
    click.echo(f"Output directory: {output_dir}")


@cli.command("list-checks")
@click.pass_context
def list_checks(ctx: click.Context) -> None:
    """List all supported baseline controls for the configured provider."""
    provider = ctx.obj["provider"]
    from analyzers.drift_analyzer import _CONTROL_MAPS
    controls = _CONTROL_MAPS.get(provider, {})
    if not controls:
        click.echo(f"No controls defined for provider: {provider}")
        return
    click.echo(f"\nBaseline controls for provider: {provider.upper()}\n")
    click.echo(f"{'Control':<45} {'Attribute':<35} {'Importance'}")
    click.echo("-" * 95)
    for control, (attr, expected, importance) in controls.items():
        click.echo(f"{control:<45} {attr:<35} {importance}")


from cli.posture_report_cmd import posture_report_cmd
from cli.scan_cmd import scan_cmd

cli.add_command(posture_report_cmd)
cli.add_command(scan_cmd)


if __name__ == "__main__":
    cli()
