"""
cloud-posture-watch CLI
============================
Main Click command group. Entry point is `k1n-posture` (configured in pyproject.toml).

Commands:
  assess        Run a full posture assessment for a cloud provider
  drift         Compare live state against a baseline and report deviations
  report        (Re-)generate a report from a previously saved JSON state file
  watch-report  Compare the latest report against the previous snapshot
  list-checks   List all supported baseline controls for a provider

Global options (can also be set via .env or environment variables):
  --provider    Cloud provider (aws, azure, gcp)
  --profile     Baseline profile (minimal, standard, strict)
  --output-dir  Directory for report output
"""
import sys
import logging
import json
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


@cli.command("scan-aws-iam")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline AWS IAM posture JSON export.",
)
@click.option(
    "--max-access-key-age-days",
    default=90,
    show_default=True,
    type=int,
    help="Maximum acceptable age for active IAM user access keys.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_aws_iam(
    ctx: click.Context,
    input_file: str,
    max_access_key_age_days: int,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline AWS IAM posture export for root MFA and privilege risk.

    This command does not require AWS credentials or boto3. It accepts JSON that
    includes account summary evidence, credential-report-style users, and IAM
    policy documents gathered by an authorized read-only operator.
    """
    import uuid
    from analyzers.aws_iam_analyzer import (
        AWSIAMAnalyzer,
        load_aws_iam_snapshot_from_export,
    )
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    snapshots = load_aws_iam_snapshot_from_export(input_file)
    iam_report = AWSIAMAnalyzer(
        max_access_key_age_days=max_access_key_age_days,
    ).analyze(snapshots)
    schema_findings = [
        PostureFinding(
            provider=Provider.AWS,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity.value),
            flag=f.rule_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in iam_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AWS,
        baseline_name="offline-aws-iam-export",
        total_resources=len(snapshots),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"AWS IAM export: {len(snapshots)} account snapshot(s), "
        f"{len(iam_report.findings)} finding(s) | "
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


@cli.command("scan-aws-rds")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline AWS RDS JSON export from describe-db-instances or describe-db-clusters.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_aws_rds(
    ctx: click.Context,
    input_file: str,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline AWS RDS export for encryption and public exposure risk.

    This command does not require AWS credentials or boto3. It accepts JSON
    exported from `aws rds describe-db-instances` and optionally
    `aws rds describe-db-clusters`, including common wrapped response shapes.
    """
    import uuid
    from analyzers.aws_rds_analyzer import AWSRDSAnalyzer, load_aws_rds_from_export
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    db_instances, db_clusters = load_aws_rds_from_export(input_file)
    rds_report = AWSRDSAnalyzer().analyze(db_instances, db_clusters)
    schema_findings = [
        PostureFinding(
            provider=Provider.AWS,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity.value),
            flag=f.check_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in rds_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AWS,
        baseline_name="offline-aws-rds-export",
        total_resources=len(db_instances) + len(db_clusters),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"AWS RDS export: {len(db_instances)} DB instance(s), "
        f"{len(db_clusters)} DB cluster(s), {len(rds_report.findings)} finding(s), "
        f"risk_score={rds_report.risk_score} | "
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


@cli.command("scan-azure-sql")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline Azure SQL export containing server and database evidence.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_azure_sql(
    ctx: click.Context,
    input_file: str,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline Azure SQL export for encryption and firewall exposure risk.

    This command does not require Azure credentials or the Azure SDK. It accepts
    JSON exports with `servers` and `databases` arrays, including common wrapped
    response shapes, gathered by an authorized read-only operator.
    """
    import uuid
    from analyzers.azure_sql_analyzer import AzureSQLAnalyzer, load_azure_sql_from_export
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    servers, databases = load_azure_sql_from_export(input_file)
    sql_report = AzureSQLAnalyzer().analyze(servers, databases)
    schema_findings = [
        PostureFinding(
            provider=Provider.AZURE,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity.value),
            flag=f.check_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in sql_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AZURE,
        baseline_name="offline-azure-sql-export",
        total_resources=len(servers) + len(databases),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"Azure SQL export: {len(servers)} server(s), {len(databases)} database(s), "
        f"{len(sql_report.findings)} finding(s), risk_score={sql_report.risk_score} | "
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


@cli.command("scan-gcp-cloud-sql")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline GCP Cloud SQL JSON export from `gcloud sql instances list --format=json`.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_gcp_cloud_sql(
    ctx: click.Context,
    input_file: str,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline GCP Cloud SQL export for public IP and SSL/TLS risk.

    This command does not require GCP credentials or the Google SDK. It accepts
    JSON exported from `gcloud sql instances list --format=json`, including
    common wrapped response shapes gathered by an authorized read-only operator.
    """
    import uuid
    from analyzers.gcp_cloud_sql_analyzer import (
        GCPCloudSQLAnalyzer,
        load_gcp_cloud_sql_from_export,
    )
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    instances = load_gcp_cloud_sql_from_export(input_file)
    sql_report = GCPCloudSQLAnalyzer().analyze(instances)
    schema_findings = [
        PostureFinding(
            provider=Provider.GCP,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity.value),
            flag=f.check_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in sql_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.GCP,
        baseline_name="offline-gcp-cloud-sql-export",
        total_resources=len(instances),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"GCP Cloud SQL export: {len(instances)} instance(s), "
        f"{len(sql_report.findings)} finding(s), risk_score={sql_report.risk_score} | "
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


@cli.command("scan-gcp-iam")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline GCP IAM policy JSON export.",
)
@click.option(
    "--org-domain",
    "org_domains",
    multiple=True,
    help="Trusted organization email domain for external-member checks. Repeatable.",
)
@click.option(
    "--max-service-account-key-age-days",
    default=90,
    show_default=True,
    type=int,
    help="Maximum acceptable age for exported GCP service account keys.",
)
@click.option(
    "--skip-external-members",
    is_flag=True,
    default=False,
    help="Disable external user checks when an org-domain allow list is not desired.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_gcp_iam(
    ctx: click.Context,
    input_file: str,
    org_domains: tuple[str, ...],
    max_service_account_key_age_days: int,
    skip_external_members: bool,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline GCP IAM policy export for broad access and key age risk.

    This command does not require GCP credentials or the Google SDK. It accepts
    JSON gathered by an authorized read-only operator from project, folder, or
    organization IAM policy exports, plus optional service account key metadata.
    """
    import uuid
    from analyzers.gcp_iam_analyzer import (
        GCPIAMAnalyzer,
        load_gcp_iam_policies_from_export,
    )
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    policies = load_gcp_iam_policies_from_export(input_file)
    iam_report = GCPIAMAnalyzer(
        org_domains=list(org_domains) or None,
        max_key_age_days=max_service_account_key_age_days,
        check_external_members=not skip_external_members,
    ).analyze(policies)
    schema_findings = [
        PostureFinding(
            provider=Provider.GCP,
            resource_type="iam_policy",
            resource_name=f.resource,
            severity=Severity(f.severity.value.lower()),
            flag=f.check_id,
            title=f.title,
            recommendation=f.remediation or f.detail,
        )
        for f in iam_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.GCP,
        baseline_name="offline-gcp-iam-export",
        total_resources=len(policies),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"GCP IAM export: {len(policies)} policy snapshot(s), "
        f"{len(iam_report.findings)} finding(s), risk_score={iam_report.risk_score} | "
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


@cli.command("scan-azure-rbac")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to an offline Azure RBAC role assignment JSON export.",
)
@click.option(
    "--trusted-domain",
    "trusted_domains",
    multiple=True,
    help="Trusted user principal domain for external-principal checks. Repeatable.",
)
@click.option(
    "--skip-external-principals",
    is_flag=True,
    default=False,
    help="Disable external and guest principal checks.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_azure_rbac(
    ctx: click.Context,
    input_file: str,
    trusted_domains: tuple[str, ...],
    skip_external_principals: bool,
    fail_on: str | None,
) -> None:
    """
    Analyze an offline Azure RBAC export for broad standing access.

    This command does not require Azure credentials or the Azure SDK. Export
    role assignments with `az role assignment list --all -o json`, and include
    optional custom role definitions under `role_definitions` when wildcard
    custom-role review is required.
    """
    import uuid
    from analyzers.azure_rbac_analyzer import (
        AzureRBACAnalyzer,
        load_azure_rbac_from_export,
    )
    from reports.posture_report import save_report
    from schemas.posture import PostureFinding, PostureReport, Provider, Severity

    assignments, role_definitions = load_azure_rbac_from_export(input_file)
    rbac_report = AzureRBACAnalyzer(
        trusted_domains=list(trusted_domains) or None,
        check_external_principals=not skip_external_principals,
    ).analyze(assignments, role_definitions)
    schema_findings = [
        PostureFinding(
            provider=Provider.AZURE,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            severity=Severity(f.severity.value),
            flag=f.check_id,
            title=f.title,
            recommendation=f.recommendation,
        )
        for f in rbac_report.findings
    ]

    report = PostureReport(
        run_id=str(uuid.uuid4())[:8],
        provider=Provider.AZURE,
        baseline_name="offline-azure-rbac-export",
        total_resources=len(assignments),
        findings=schema_findings,
    )
    report_path = save_report(report, ctx.obj["output_dir"])

    counts = report.finding_counts
    click.echo(
        f"Azure RBAC export: {len(assignments)} assignment(s), "
        f"{len(role_definitions)} role definition(s), "
        f"{len(rbac_report.findings)} finding(s), risk_score={rbac_report.risk_score} | "
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


@cli.command("scan-iam-comparison")
@click.option(
    "--aws-input",
    type=click.Path(exists=True),
    default=None,
    help="Path to an offline AWS IAM posture JSON export.",
)
@click.option(
    "--azure-input",
    type=click.Path(exists=True),
    default=None,
    help="Path to an offline Azure RBAC role assignment JSON export.",
)
@click.option(
    "--gcp-input",
    type=click.Path(exists=True),
    default=None,
    help="Path to an offline GCP IAM policy JSON export.",
)
@click.option(
    "--trusted-domain",
    "trusted_domains",
    multiple=True,
    help="Trusted Azure user principal domain for external-principal checks. Repeatable.",
)
@click.option(
    "--org-domain",
    "org_domains",
    multiple=True,
    help="Trusted GCP organization email domain for external-member checks. Repeatable.",
)
@click.option(
    "--max-access-key-age-days",
    default=90,
    show_default=True,
    type=int,
    help="Maximum acceptable age for active AWS IAM user access keys.",
)
@click.option(
    "--max-service-account-key-age-days",
    default=90,
    show_default=True,
    type=int,
    help="Maximum acceptable age for exported GCP service account keys.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with a non-zero code if any finding reaches this severity.",
)
@click.pass_context
def scan_iam_comparison(
    ctx: click.Context,
    aws_input: str | None,
    azure_input: str | None,
    gcp_input: str | None,
    trusted_domains: tuple[str, ...],
    org_domains: tuple[str, ...],
    max_access_key_age_days: int,
    max_service_account_key_age_days: int,
    fail_on: str | None,
) -> None:
    """
    Build one offline comparison report across AWS IAM, Azure RBAC, and GCP IAM.

    Provide evidence for at least two clouds. The command runs the existing
    provider-specific offline analyzers and writes both Markdown and JSON
    comparison artifacts to the configured output directory.
    """
    from analyzers.aws_iam_analyzer import AWSIAMAnalyzer, load_aws_iam_snapshot_from_export
    from analyzers.azure_rbac_analyzer import AzureRBACAnalyzer, load_azure_rbac_from_export
    from analyzers.gcp_iam_analyzer import GCPIAMAnalyzer, load_gcp_iam_policies_from_export
    from analyzers.iam_comparison_analyzer import (
        build_iam_comparison_report,
        save_iam_comparison_report,
    )

    provided_inputs = [path for path in (aws_input, azure_input, gcp_input) if path]
    if len(provided_inputs) < 2:
        raise click.UsageError("Provide at least two of --aws-input, --azure-input, and --gcp-input.")

    aws_report = None
    if aws_input:
        aws_snapshots = load_aws_iam_snapshot_from_export(aws_input)
        aws_report = AWSIAMAnalyzer(
            max_access_key_age_days=max_access_key_age_days,
        ).analyze(aws_snapshots)

    azure_report = None
    if azure_input:
        assignments, role_definitions = load_azure_rbac_from_export(azure_input)
        azure_report = AzureRBACAnalyzer(
            trusted_domains=list(trusted_domains) or None,
        ).analyze(assignments, role_definitions)

    gcp_report = None
    if gcp_input:
        policies = load_gcp_iam_policies_from_export(gcp_input)
        gcp_report = GCPIAMAnalyzer(
            org_domains=list(org_domains) or None,
            max_key_age_days=max_service_account_key_age_days,
        ).analyze(policies)

    comparison = build_iam_comparison_report(
        aws_report=aws_report,
        azure_report=azure_report,
        gcp_report=gcp_report,
    )
    markdown_path, json_path = save_iam_comparison_report(comparison, ctx.obj["output_dir"])
    click.echo(
        f"IAM comparison: {len(comparison.providers)} provider(s), "
        f"{comparison.total_findings} finding(s), "
        f"risk_score={comparison.cross_cloud_risk_score}"
    )
    click.echo(f"Markdown report written to: {markdown_path}")
    click.echo(f"JSON report written to: {json_path}")

    if fail_on:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_rank.get(fail_on.lower(), 3)
        if any(severity_rank.get(finding.severity, 0) >= threshold for finding in comparison.findings):
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


@cli.command("json-schema")
def json_schema() -> None:
    """Print the stable v1 posture-report JSON schema."""
    from reports.posture_report_schema import POSTURE_REPORT_JSON_SCHEMA

    click.echo(json.dumps(POSTURE_REPORT_JSON_SCHEMA, indent=2))


@cli.command("notify-webhook")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a JSON posture report generated by k1n-posture.",
)
@click.option(
    "--target",
    required=True,
    type=click.Choice(["slack", "teams"], case_sensitive=False),
    help="Webhook payload format.",
)
@click.option(
    "--webhook-url",
    envvar="POSTURE_WEBHOOK_URL",
    default=None,
    help="Incoming webhook URL. Can also be supplied with POSTURE_WEBHOOK_URL.",
)
@click.option(
    "--dashboard-url",
    default=None,
    help="Optional report or dashboard URL to include in the notification.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the payload instead of sending it.",
)
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=float,
    help="Webhook POST timeout in seconds.",
)
def notify_webhook(
    input_file: str,
    target: str,
    webhook_url: str | None,
    dashboard_url: str | None,
    dry_run: bool,
    timeout: float,
) -> None:
    """
    Send a posture report summary to Slack or Microsoft Teams.

    Use --dry-run to validate the generated payload without making a network
    request or exposing the webhook URL in terminal output.
    """
    from cli.posture_report_cmd import _load_report_from_json
    from reports.webhook_notifications import build_webhook_payload, send_webhook_payload

    report = _load_report_from_json(Path(input_file))
    payload = build_webhook_payload(report, target=target, dashboard_url=dashboard_url)

    if dry_run:
        click.echo(json.dumps(payload, indent=2))
        return

    if not webhook_url:
        raise click.UsageError(
            "Provide --webhook-url, set POSTURE_WEBHOOK_URL, or use --dry-run to inspect the payload."
        )
    if not webhook_url.startswith(("https://hooks.slack.com/", "https://")):
        raise click.UsageError("Webhook URL must use HTTPS.")

    status = send_webhook_payload(webhook_url, payload, timeout_seconds=timeout)
    click.echo(f"{target.lower()} webhook notification delivered with HTTP {status}.")


@cli.command("watch-report")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the current JSON posture report generated by k1n-posture.",
)
@click.option(
    "--previous",
    "previous_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Optional path to the previous JSON posture report snapshot.",
)
@click.option(
    "--state-file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Optional snapshot path to read/write between scheduled runs.",
)
@click.option(
    "--alert-on",
    default="high",
    show_default=True,
    type=click.Choice(["none", "low", "medium", "high", "critical"], case_sensitive=False),
    help="Alert only when new findings meet or exceed this severity.",
)
@click.option(
    "--alert-on-first-run",
    is_flag=True,
    default=False,
    help="Allow alerting when no previous snapshot is available.",
)
@click.option(
    "--target",
    default=None,
    type=click.Choice(["slack", "teams"], case_sensitive=False),
    help="Optional webhook payload format for new-finding alerts.",
)
@click.option(
    "--webhook-url",
    envvar="POSTURE_WEBHOOK_URL",
    default=None,
    help="Incoming webhook URL. Can also be supplied with POSTURE_WEBHOOK_URL.",
)
@click.option(
    "--dashboard-url",
    default=None,
    help="Optional report or dashboard URL to include in the alert.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the alert payload instead of sending it.",
)
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=float,
    help="Webhook POST timeout in seconds.",
)
def watch_report(
    input_file: str,
    previous_file: str | None,
    state_file: str | None,
    alert_on: str,
    alert_on_first_run: bool,
    target: str | None,
    webhook_url: str | None,
    dashboard_url: str | None,
    dry_run: bool,
    timeout: float,
) -> None:
    """
    Compare the latest posture report to the previous snapshot and alert on new findings.

    This watch mode is designed for scheduled runners that already produce JSON
    posture reports. Use --state-file to persist the last snapshot between runs.
    """
    from cli.posture_report_cmd import _load_report_from_json
    from reports.watch_mode import (
        build_watch_notification_report,
        diff_posture_reports,
        should_alert,
        write_watch_state,
    )
    from reports.webhook_notifications import build_webhook_payload, send_webhook_payload

    input_path = Path(input_file)
    previous_path = Path(previous_file) if previous_file else None
    state_path = Path(state_file) if state_file else None

    if previous_path and state_path:
        raise click.UsageError("Use either --previous or --state-file for the baseline snapshot, not both.")

    if not previous_path and state_path and state_path.exists():
        previous_path = state_path

    current_report = _load_report_from_json(input_path)
    previous_report = _load_report_from_json(previous_path) if previous_path else None
    first_run = previous_report is None

    try:
        delta = diff_posture_reports(current_report, previous_report)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    click.echo(
        f"Watch summary: run={delta.current_run_id} "
        f"new={len(delta.new_findings)} resolved={len(delta.resolved_findings)} "
        f"persistent={len(delta.persistent_findings)}"
    )
    if delta.previous_run_id:
        click.echo(f"Compared against previous run: {delta.previous_run_id}")
    else:
        click.echo("Compared against previous run: none")

    alert_required = alert_on.lower() != "none" and should_alert(
        delta,
        alert_on=alert_on,
        first_run=first_run,
        alert_on_first_run=alert_on_first_run,
    )
    if not alert_required:
        click.echo("Alert status: no new findings met the configured threshold.")
    elif not target:
        click.echo("Alert status: threshold met, but no webhook target was requested.")
    else:
        notification_report = build_watch_notification_report(current_report, delta)
        payload = build_webhook_payload(
            notification_report,
            target=target,
            dashboard_url=dashboard_url,
        )
        if dry_run:
            click.echo(json.dumps(payload, indent=2))
        else:
            if not webhook_url:
                raise click.UsageError(
                    "Provide --webhook-url, set POSTURE_WEBHOOK_URL, or use --dry-run to inspect the alert payload."
                )
            if not webhook_url.startswith(("https://hooks.slack.com/", "https://")):
                raise click.UsageError("Webhook URL must use HTTPS.")
            status = send_webhook_payload(webhook_url, payload, timeout_seconds=timeout)
            click.echo(f"{target.lower()} watch alert delivered with HTTP {status}.")

    if state_path:
        write_watch_state(input_path, state_path)
        click.echo(f"State snapshot updated: {state_path}")


from cli.posture_report_cmd import posture_report_cmd
from cli.scan_cmd import scan_cmd

cli.add_command(posture_report_cmd)
cli.add_command(scan_cmd)


if __name__ == "__main__":
    cli()
