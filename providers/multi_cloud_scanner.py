"""
Multi-Cloud Unified Scanner
=============================
Orchestrates all available collectors and analyzers across AWS, Azure, and GCP
in a single pass, producing a unified MultiCloudScanReport.

Each provider is scanned independently — a failure in one provider does not
prevent the others from running.  Collectors that require missing credentials
are skipped gracefully with a clear reason message.

Usage:
    from providers.multi_cloud_scanner import run_multi_cloud_scan, ProviderScanConfig

    # Auto-detect providers from environment variables
    report = run_multi_cloud_scan()
    print(report.summary())

    # Explicit config
    configs = [
        ProviderScanConfig(provider="aws", aws_region="eu-west-1"),
        ProviderScanConfig(provider="azure", azure_subscription_id="sub-123"),
    ]
    report = run_multi_cloud_scan(configs=configs)

    # Dry run (no live API calls)
    report = run_multi_cloud_scan(dry_run=True)
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from schemas.posture import PostureFinding, Provider, Severity
from schemas.risk import (
    SEVERITY_RANK as _SEVERITY_RANK,
    SEVERITY_WEIGHTS as _SEVERITY_SCORE,
    calculate_risk_score,
    classify_risk_score,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ProviderScanConfig:
    """
    Configuration for a single cloud provider scan.

    All credential fields are optional — the scanner falls back to environment
    variables when they are not supplied.
    """

    provider: str                           # "aws", "azure", or "gcp"
    enabled: bool = True

    # AWS
    aws_region: str = "us-east-1"
    aws_profile: Optional[str] = None

    # Azure
    azure_subscription_id: Optional[str] = None

    # GCP
    gcp_project_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.provider not in ("aws", "azure", "gcp"):
            raise ValueError(
                f"Unknown provider '{self.provider}'. Must be 'aws', 'azure', or 'gcp'."
            )


# ---------------------------------------------------------------------------
# Collector result
# ---------------------------------------------------------------------------

@dataclass
class CollectorResult:
    """
    Result of running a single collector (e.g. storage or network).

    Either postures contains the collected resources (succeeded), or error /
    skipped explains why no data is available.
    """

    collector_name: str                         # "storage" or "network"
    resource_count: int = 0
    postures: list[Any] = field(default_factory=list)
    error: Optional[str] = None
    skipped: bool = False
    skip_reason: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        """True when the collector ran without errors and was not skipped."""
        return not self.skipped and self.error is None


# ---------------------------------------------------------------------------
# Provider scan result
# ---------------------------------------------------------------------------

@dataclass
class ProviderScanResult:
    """
    Aggregated result of all collectors + analyzers for one cloud provider.

    findings is a flat list of normalised PostureFinding objects ready for
    ingestion by the reporting layer.
    """

    provider: str
    collector_results: list[CollectorResult] = field(default_factory=list)
    findings: list[PostureFinding] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)

    @property
    def total_resources(self) -> int:
        """Total count of resources collected across all successful collectors."""
        return sum(r.resource_count for r in self.collector_results if r.succeeded)

    @property
    def failed_collectors(self) -> list[CollectorResult]:
        """Collectors that raised an exception during execution."""
        return [r for r in self.collector_results if r.error is not None]

    @property
    def skipped_collectors(self) -> list[CollectorResult]:
        """Collectors skipped due to missing credentials or unavailable SDK."""
        return [r for r in self.collector_results if r.skipped]


# ---------------------------------------------------------------------------
# Multi-cloud scan report
# ---------------------------------------------------------------------------

@dataclass
class MultiCloudScanReport:
    """
    Unified multi-cloud posture scan report.

    Aggregates findings from all provider scans into a single structure
    with cross-cloud risk metrics.
    """

    scan_id: str
    scanned_at: datetime
    provider_results: list[ProviderScanResult] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Aggregated properties
    # ------------------------------------------------------------------

    @property
    def all_findings(self) -> list[PostureFinding]:
        """Flat list of all findings across every provider."""
        return [f for pr in self.provider_results for f in pr.findings]

    @property
    def total_resources(self) -> int:
        """Total number of cloud resources scanned across all providers."""
        return sum(pr.total_resources for pr in self.provider_results)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def finding_counts(self) -> dict[str, int]:
        """Per-severity finding counts across all providers."""
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in self.all_findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def risk_score(self) -> int:
        """
        Weighted risk score 0–100.

        Each finding contributes its severity weight. Score is capped at 100
        so the gauge stays interpretable regardless of finding volume.
        """
        return calculate_risk_score(self.all_findings)

    @property
    def providers_scanned(self) -> list[str]:
        """List of provider names that were included in this scan."""
        return [pr.provider for pr in self.provider_results]

    @property
    def has_errors(self) -> bool:
        """True if any provider reported a scan error or collector failure."""
        return any(
            pr.scan_errors or pr.failed_collectors
            for pr in self.provider_results
        )

    @property
    def highest_severity(self) -> Optional[str]:
        """Highest severity level present in findings, or None if no findings."""
        if not self.all_findings:
            return None
        return max(
            self.all_findings,
            key=lambda f: severity_rank(f.severity),
        ).severity.value

    # ------------------------------------------------------------------
    # Report helpers
    # ------------------------------------------------------------------

    def findings_by_provider(self) -> dict[str, list[PostureFinding]]:
        """Findings grouped by provider name."""
        return {pr.provider: list(pr.findings) for pr in self.provider_results}

    def findings_for_provider(self, provider: str) -> list[PostureFinding]:
        """Return findings for a single named provider."""
        for pr in self.provider_results:
            if pr.provider == provider:
                return list(pr.findings)
        return []

    def meets_severity_gate(self, threshold: str) -> bool:
        """
        Return True if any finding is at or above the given severity threshold.

        Used by the CLI to trigger a non-zero exit code.
        """
        rank = _SEVERITY_RANK.get(threshold.lower(), 0)
        return any(
            _SEVERITY_RANK.get(f.severity.value, 0) >= rank
            for f in self.all_findings
        )

    def summary(self) -> str:
        providers = ", ".join(p.upper() for p in self.providers_scanned) or "none"
        counts = self.finding_counts
        risk_band = classify_risk_score(self.risk_score).name
        return (
            f"Multi-cloud scan [{self.scan_id}] — {providers} | "
            f"Resources: {self.total_resources} | "
            f"Risk: {self.risk_score}/100 ({risk_band}) | "
            f"CRITICAL={counts['critical']} "
            f"HIGH={counts['high']} "
            f"MEDIUM={counts['medium']} "
            f"LOW={counts['low']}"
        )


# ---------------------------------------------------------------------------
# Finding normalisation
# ---------------------------------------------------------------------------

def _normalize_finding(f: Any, provider: str) -> PostureFinding:
    """
    Convert any analyser finding object to a canonical PostureFinding.

    Handles NetworkFinding, NSGFinding, and StoragePublicAccessFinding — all of
    which share the fields provider/resource_type/resource_name/severity/title/
    recommendation but may use different attribute names for the rule identifier.
    """
    # NSGFinding uses resource_id as the primary identifier, others use resource_name
    resource_name = getattr(f, "resource_name", None) or getattr(f, "resource_id", "unknown")
    flag = (
        getattr(f, "rule_id", None)
        or getattr(f, "flag", None)
        or "UNKNOWN"
    )
    return PostureFinding(
        provider=Provider(provider),
        resource_type=getattr(f, "resource_type", "cloud_resource"),
        resource_name=resource_name,
        severity=Severity(f.severity),
        flag=flag,
        title=f.title,
        recommendation=f.recommendation,
    )


# ---------------------------------------------------------------------------
# Provider scan functions
# ---------------------------------------------------------------------------

def _scan_aws(config: ProviderScanConfig) -> ProviderScanResult:
    """
    Run AWS storage and network collectors, then run all available analyzers.

    Requires boto3 to be installed and valid AWS credentials in the environment.
    """
    result = ProviderScanResult(provider="aws")

    # Check boto3 availability
    try:
        import boto3  # noqa: F401
    except ImportError:
        msg = "boto3 not installed — AWS scan skipped"
        result.scan_errors.append(msg)
        for name in ("storage", "network"):
            result.collector_results.append(
                CollectorResult(collector_name=name, skipped=True, skip_reason=msg)
            )
        return result

    # Build boto3 session
    try:
        import boto3
        session = boto3.Session(
            profile_name=config.aws_profile,
            region_name=config.aws_region,
        )
    except Exception as exc:
        result.scan_errors.append(f"Failed to create AWS session: {exc}")
        return result

    # --- S3 storage ---
    try:
        from providers.aws.storage_collector import assess_bucket_posture
        from analyzers.storage_public_access import analyze_storage_public_access

        postures = assess_bucket_posture(session)
        result.collector_results.append(
            CollectorResult(
                collector_name="storage",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_storage_public_access(postures, provider="aws"):
            result.findings.append(_normalize_finding(f, "aws"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="storage", error=str(exc))
        )
        result.scan_errors.append(f"AWS storage collector failed: {exc}")

    # --- EC2 Security Groups ---
    try:
        from providers.aws.network_collector import collect_security_groups
        from analyzers.network_exposure import analyze_network_exposure

        postures = collect_security_groups(session, region=config.aws_region)
        result.collector_results.append(
            CollectorResult(
                collector_name="network",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_network_exposure(postures, provider="aws"):
            result.findings.append(_normalize_finding(f, "aws"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="network", error=str(exc))
        )
        result.scan_errors.append(f"AWS network collector failed: {exc}")

    return result


def _scan_azure(config: ProviderScanConfig) -> ProviderScanResult:
    """
    Run Azure storage and NSG collectors, then run all available analyzers.

    Requires azure-identity and azure-mgmt-network to be installed, and
    AZURE_SUBSCRIPTION_ID to be set (or passed via config).
    """
    result = ProviderScanResult(provider="azure")

    # Resolve subscription ID
    sub_id = config.azure_subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        msg = "AZURE_SUBSCRIPTION_ID not configured — Azure scan skipped"
        result.scan_errors.append(msg)
        for name in ("storage", "network"):
            result.collector_results.append(
                CollectorResult(collector_name=name, skipped=True, skip_reason=msg)
            )
        return result

    # --- Azure Blob Storage ---
    try:
        from providers.azure.storage_collector import assess_storage_account_posture
        from analyzers.storage_public_access import analyze_storage_public_access

        postures = assess_storage_account_posture(sub_id)
        result.collector_results.append(
            CollectorResult(
                collector_name="storage",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_storage_public_access(postures, provider="azure"):
            result.findings.append(_normalize_finding(f, "azure"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="storage", error=str(exc))
        )
        result.scan_errors.append(f"Azure storage collector failed: {exc}")

    # --- NSG (Network Security Groups) ---
    try:
        from providers.azure.network_collector import collect_nsgs
        from analyzers.nsg_exposure import analyze_nsg_exposure

        postures = collect_nsgs(sub_id)
        result.collector_results.append(
            CollectorResult(
                collector_name="network",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_nsg_exposure(postures):
            result.findings.append(_normalize_finding(f, "azure"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="network", error=str(exc))
        )
        result.scan_errors.append(f"Azure network collector failed: {exc}")

    return result


def _scan_gcp(config: ProviderScanConfig) -> ProviderScanResult:
    """
    Run GCP storage and firewall collectors, then run available analyzers.

    Requires GCP_PROJECT_ID to be set (or passed via config). Storage and
    firewall collectors each skip or fail independently based on installed SDKs
    and available read-only permissions.
    """
    result = ProviderScanResult(provider="gcp")

    # Resolve project ID
    project_id = config.gcp_project_id or os.getenv("GCP_PROJECT_ID")
    if not project_id:
        msg = "GCP_PROJECT_ID not configured — GCP scan skipped"
        result.scan_errors.append(msg)
        for name in ("storage", "network"):
            result.collector_results.append(
                CollectorResult(
                    collector_name=name, skipped=True, skip_reason=msg
                )
            )
        return result

    # --- GCS Cloud Storage ---
    try:
        from providers.gcp.storage_collector import assess_gcs_bucket_posture
        from analyzers.storage_public_access import analyze_storage_public_access

        postures = assess_gcs_bucket_posture(project_id)
        result.collector_results.append(
            CollectorResult(
                collector_name="storage",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_storage_public_access(postures, provider="gcp"):
            result.findings.append(_normalize_finding(f, "gcp"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="storage", error=str(exc))
        )
        result.scan_errors.append(f"GCP storage collector failed: {exc}")

    # --- VPC firewall rules ---
    try:
        from providers.gcp.network_collector import collect_firewall_rules
        from analyzers.network_exposure import analyze_network_exposure

        postures = collect_firewall_rules(project_id)
        result.collector_results.append(
            CollectorResult(
                collector_name="network",
                resource_count=len(postures),
                postures=postures,
            )
        )
        for f in analyze_network_exposure(
            postures,
            provider="gcp",
            resource_type="firewall_rule",
        ):
            result.findings.append(_normalize_finding(f, "gcp"))
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(collector_name="network", error=str(exc))
        )
        result.scan_errors.append(f"GCP network collector failed: {exc}")

    return result


# ---------------------------------------------------------------------------
# Default config builder
# ---------------------------------------------------------------------------

def _default_configs() -> list[ProviderScanConfig]:
    """Build default scan configs for all three providers from environment."""
    return [
        ProviderScanConfig(
            provider="aws",
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            aws_profile=os.getenv("AWS_PROFILE"),
        ),
        ProviderScanConfig(
            provider="azure",
            azure_subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        ),
        ProviderScanConfig(
            provider="gcp",
            gcp_project_id=os.getenv("GCP_PROJECT_ID"),
        ),
    ]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_multi_cloud_scan(
    configs: Optional[list[ProviderScanConfig]] = None,
    providers: Optional[list[str]] = None,
    dry_run: bool = False,
) -> MultiCloudScanReport:
    """
    Run a unified multi-cloud posture scan.

    Args:
        configs:   Explicit list of ProviderScanConfig objects. When None, the
                   scanner builds configs automatically from environment variables.
        providers: Optional allow-list of provider names (e.g. ["aws", "gcp"]).
                   When given, only these providers are scanned.
        dry_run:   When True, skip all live API calls and return an empty report.
                   Useful for CI pipeline wiring validation.

    Returns:
        MultiCloudScanReport aggregating findings from all configured providers.
    """
    scan_id = str(uuid.uuid4())[:8]
    scanned_at = datetime.now(tz=timezone.utc)

    if dry_run:
        return MultiCloudScanReport(
            scan_id=scan_id,
            scanned_at=scanned_at,
            provider_results=[],
        )

    if configs is None:
        configs = _default_configs()

    # Apply provider filter
    if providers:
        allowed = {p.lower() for p in providers}
        configs = [c for c in configs if c.provider in allowed]

    # Apply enabled filter
    configs = [c for c in configs if c.enabled]

    # Dispatch to per-provider scan functions
    _dispatch = {
        "aws": _scan_aws,
        "azure": _scan_azure,
        "gcp": _scan_gcp,
    }

    provider_results: list[ProviderScanResult] = []
    for cfg in configs:
        fn = _dispatch.get(cfg.provider)
        if fn:
            provider_results.append(fn(cfg))

    return MultiCloudScanReport(
        scan_id=scan_id,
        scanned_at=scanned_at,
        provider_results=provider_results,
    )
