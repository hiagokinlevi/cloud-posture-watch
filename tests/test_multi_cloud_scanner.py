"""
Tests for providers/multi_cloud_scanner.py

Validates:
  - ProviderScanConfig defaults and validation
  - ProviderScanConfig rejects unknown provider
  - CollectorResult.succeeded logic
  - ProviderScanResult.total_resources sums only successful collectors
  - ProviderScanResult.failed_collectors and skipped_collectors filtering
  - MultiCloudScanReport.all_findings aggregates across all provider results
  - MultiCloudScanReport.total_resources
  - MultiCloudScanReport.total_findings
  - MultiCloudScanReport.finding_counts per-severity breakdown
  - MultiCloudScanReport.risk_score weighted sum capped at 100
  - MultiCloudScanReport.providers_scanned
  - MultiCloudScanReport.has_errors True when errors present
  - MultiCloudScanReport.has_errors False when no errors
  - MultiCloudScanReport.highest_severity
  - MultiCloudScanReport.findings_by_provider
  - MultiCloudScanReport.findings_for_provider returns correct subset
  - MultiCloudScanReport.meets_severity_gate True/False
  - MultiCloudScanReport.summary() contains scan_id and providers
  - run_multi_cloud_scan with dry_run=True returns empty report with scan_id
  - run_multi_cloud_scan with providers filter includes only requested providers
  - run_multi_cloud_scan with disabled config skips that provider
  - run_multi_cloud_scan with empty configs produces empty report
  - _normalize_finding maps rule_id, title, recommendation, provider, severity
  - _normalize_finding falls back to resource_id when resource_name absent
  - _default_configs returns three providers
  - _default_configs reads aws_region from AWS_REGION env var
  - _SEVERITY_SCORE weights: critical > high > medium > low
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from providers.multi_cloud_scanner import (
    CollectorResult,
    MultiCloudScanReport,
    ProviderScanConfig,
    ProviderScanResult,
    _default_configs,
    _normalize_finding,
    _SEVERITY_SCORE,
    run_multi_cloud_scan,
)
from schemas.posture import PostureFinding, Provider, Severity


# ---------------------------------------------------------------------------
# Stub finding objects (mimic NetworkFinding / StoragePublicAccessFinding)
# ---------------------------------------------------------------------------

@dataclass
class _StubFinding:
    provider: str
    resource_type: str
    resource_name: str
    severity: str
    rule_id: str
    title: str
    recommendation: str


def _pf(
    provider: str = "aws",
    severity: str = "high",
    resource_name: str = "my-bucket",
    flag: str = "STG-PUB-001",
) -> PostureFinding:
    return PostureFinding(
        provider=Provider(provider),
        resource_type="s3_bucket",
        resource_name=resource_name,
        severity=Severity(severity),
        flag=flag,
        title=f"Test finding ({severity})",
        recommendation="Fix it.",
    )


# ---------------------------------------------------------------------------
# ProviderScanConfig
# ---------------------------------------------------------------------------

class TestProviderScanConfig:

    def test_default_provider_aws(self):
        cfg = ProviderScanConfig(provider="aws")
        assert cfg.provider == "aws"
        assert cfg.enabled is True

    def test_default_aws_region(self):
        cfg = ProviderScanConfig(provider="aws")
        assert cfg.aws_region == "us-east-1"

    def test_aws_profile_defaults_none(self):
        cfg = ProviderScanConfig(provider="aws")
        assert cfg.aws_profile is None

    def test_azure_subscription_id_defaults_none(self):
        cfg = ProviderScanConfig(provider="azure")
        assert cfg.azure_subscription_id is None

    def test_gcp_project_id_defaults_none(self):
        cfg = ProviderScanConfig(provider="gcp")
        assert cfg.gcp_project_id is None

    def test_unknown_provider_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            ProviderScanConfig(provider="digitalocean")

    def test_custom_aws_region(self):
        cfg = ProviderScanConfig(provider="aws", aws_region="eu-west-1")
        assert cfg.aws_region == "eu-west-1"

    def test_disabled_config(self):
        cfg = ProviderScanConfig(provider="aws", enabled=False)
        assert cfg.enabled is False


# ---------------------------------------------------------------------------
# CollectorResult
# ---------------------------------------------------------------------------

class TestCollectorResult:

    def test_succeeded_true_when_no_error_not_skipped(self):
        cr = CollectorResult(collector_name="storage", resource_count=3)
        assert cr.succeeded is True

    def test_succeeded_false_when_error_set(self):
        cr = CollectorResult(collector_name="storage", error="connection refused")
        assert cr.succeeded is False

    def test_succeeded_false_when_skipped(self):
        cr = CollectorResult(collector_name="network", skipped=True)
        assert cr.succeeded is False

    def test_resource_count_default_zero(self):
        cr = CollectorResult(collector_name="storage")
        assert cr.resource_count == 0

    def test_postures_default_empty(self):
        cr = CollectorResult(collector_name="storage")
        assert cr.postures == []


# ---------------------------------------------------------------------------
# ProviderScanResult
# ---------------------------------------------------------------------------

class TestProviderScanResult:

    def _make(self) -> ProviderScanResult:
        pr = ProviderScanResult(provider="aws")
        pr.collector_results = [
            CollectorResult("storage", resource_count=5),
            CollectorResult("network", resource_count=3),
            CollectorResult("extra", skipped=True),
        ]
        return pr

    def test_total_resources_sums_succeeded_only(self):
        pr = self._make()
        assert pr.total_resources == 8   # 5 + 3, skipped excluded

    def test_skipped_not_counted_in_total_resources(self):
        pr = ProviderScanResult(provider="aws")
        pr.collector_results = [
            CollectorResult("storage", resource_count=10, skipped=True)
        ]
        assert pr.total_resources == 0

    def test_failed_collectors_returns_error_ones(self):
        pr = ProviderScanResult(provider="aws")
        pr.collector_results = [
            CollectorResult("storage", error="timeout"),
            CollectorResult("network", resource_count=2),
        ]
        assert len(pr.failed_collectors) == 1
        assert pr.failed_collectors[0].collector_name == "storage"

    def test_skipped_collectors_returns_skipped_ones(self):
        pr = ProviderScanResult(provider="azure")
        pr.collector_results = [
            CollectorResult("storage", skipped=True, skip_reason="no creds"),
            CollectorResult("network", resource_count=1),
        ]
        assert len(pr.skipped_collectors) == 1

    def test_findings_defaults_empty(self):
        pr = ProviderScanResult(provider="gcp")
        assert pr.findings == []


# ---------------------------------------------------------------------------
# MultiCloudScanReport — aggregation
# ---------------------------------------------------------------------------

class TestMultiCloudScanReportAggregation:

    def _report(self) -> MultiCloudScanReport:
        aws = ProviderScanResult(provider="aws")
        aws.findings = [_pf("aws", "critical"), _pf("aws", "high")]

        azure = ProviderScanResult(provider="azure")
        azure.findings = [_pf("azure", "medium")]

        gcp = ProviderScanResult(provider="gcp")
        # no findings

        return MultiCloudScanReport(
            scan_id="abc12345",
            scanned_at=datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc),
            provider_results=[aws, azure, gcp],
        )

    def test_all_findings_aggregates(self):
        r = self._report()
        assert len(r.all_findings) == 3

    def test_total_findings(self):
        r = self._report()
        assert r.total_findings == 3

    def test_finding_counts_per_severity(self):
        r = self._report()
        counts = r.finding_counts
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0

    def test_providers_scanned(self):
        r = self._report()
        assert set(r.providers_scanned) == {"aws", "azure", "gcp"}

    def test_empty_report_all_findings_empty(self):
        r = MultiCloudScanReport(
            scan_id="x",
            scanned_at=datetime.now(tz=timezone.utc),
        )
        assert r.all_findings == []

    def test_total_resources_sums_all_providers(self):
        aws = ProviderScanResult(provider="aws")
        aws.collector_results = [CollectorResult("storage", resource_count=5)]
        gcp = ProviderScanResult(provider="gcp")
        gcp.collector_results = [CollectorResult("storage", resource_count=3)]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[aws, gcp],
        )
        assert r.total_resources == 8


# ---------------------------------------------------------------------------
# MultiCloudScanReport — risk score
# ---------------------------------------------------------------------------

class TestRiskScore:

    def test_risk_score_zero_with_no_findings(self):
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc)
        )
        assert r.risk_score == 0

    def test_risk_score_critical_weighs_10(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="critical")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.risk_score == 10

    def test_risk_score_high_weighs_5(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="high")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.risk_score == 5

    def test_risk_score_capped_at_100(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="critical")] * 20   # 20 × 10 = 200 → capped
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.risk_score == 100

    def test_severity_score_ordering(self):
        assert _SEVERITY_SCORE["critical"] > _SEVERITY_SCORE["high"]
        assert _SEVERITY_SCORE["high"] > _SEVERITY_SCORE["medium"]
        assert _SEVERITY_SCORE["medium"] > _SEVERITY_SCORE["low"]
        assert _SEVERITY_SCORE["low"] > _SEVERITY_SCORE["info"]


# ---------------------------------------------------------------------------
# MultiCloudScanReport — properties
# ---------------------------------------------------------------------------

class TestMultiCloudScanReportProperties:

    def test_has_errors_false_when_clean(self):
        pr = ProviderScanResult(provider="aws")
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.has_errors is False

    def test_has_errors_true_when_scan_error(self):
        pr = ProviderScanResult(provider="aws")
        pr.scan_errors.append("connection refused")
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.has_errors is True

    def test_has_errors_true_when_failed_collector(self):
        pr = ProviderScanResult(provider="aws")
        pr.collector_results.append(CollectorResult("storage", error="timeout"))
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.has_errors is True

    def test_highest_severity_none_when_no_findings(self):
        r = MultiCloudScanReport(scan_id="x", scanned_at=datetime.now(tz=timezone.utc))
        assert r.highest_severity is None

    def test_highest_severity_critical(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="medium"), _pf(severity="critical"), _pf(severity="high")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.highest_severity == "critical"

    def test_findings_by_provider_groups_correctly(self):
        aws = ProviderScanResult(provider="aws")
        aws.findings = [_pf("aws")]
        azure = ProviderScanResult(provider="azure")
        azure.findings = [_pf("azure")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[aws, azure],
        )
        by_prov = r.findings_by_provider()
        assert len(by_prov["aws"]) == 1
        assert len(by_prov["azure"]) == 1

    def test_findings_for_provider_returns_correct_subset(self):
        aws = ProviderScanResult(provider="aws")
        aws.findings = [_pf("aws", severity="critical")]
        gcp = ProviderScanResult(provider="gcp")
        gcp.findings = [_pf("gcp", severity="low")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[aws, gcp],
        )
        aws_f = r.findings_for_provider("aws")
        assert len(aws_f) == 1
        assert aws_f[0].severity.value == "critical"

    def test_findings_for_provider_unknown_returns_empty(self):
        r = MultiCloudScanReport(scan_id="x", scanned_at=datetime.now(tz=timezone.utc))
        assert r.findings_for_provider("digitalocean") == []

    def test_meets_severity_gate_true(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="high")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.meets_severity_gate("high") is True
        assert r.meets_severity_gate("medium") is True

    def test_meets_severity_gate_false(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="medium")]
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert r.meets_severity_gate("high") is False
        assert r.meets_severity_gate("critical") is False

    def test_summary_contains_scan_id(self):
        r = MultiCloudScanReport(
            scan_id="deadbeef", scanned_at=datetime.now(tz=timezone.utc)
        )
        assert "deadbeef" in r.summary()

    def test_summary_contains_provider_names(self):
        aws = ProviderScanResult(provider="aws")
        gcp = ProviderScanResult(provider="gcp")
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[aws, gcp],
        )
        s = r.summary()
        assert "AWS" in s
        assert "GCP" in s

    def test_summary_contains_risk_score(self):
        r = MultiCloudScanReport(scan_id="x", scanned_at=datetime.now(tz=timezone.utc))
        assert "/100" in r.summary()

    def test_summary_contains_risk_band(self):
        pr = ProviderScanResult(provider="aws")
        pr.findings = [_pf(severity="critical")] * 6
        r = MultiCloudScanReport(
            scan_id="x", scanned_at=datetime.now(tz=timezone.utc),
            provider_results=[pr],
        )
        assert "(high)" in r.summary()


# ---------------------------------------------------------------------------
# _normalize_finding
# ---------------------------------------------------------------------------

class TestNormalizeFinding:

    def test_rule_id_mapped_to_flag(self):
        stub = _StubFinding(
            provider="aws",
            resource_type="s3_bucket",
            resource_name="my-bucket",
            severity="high",
            rule_id="STG-PUB-001",
            title="Public bucket",
            recommendation="Enable block.",
        )
        pf = _normalize_finding(stub, "aws")
        assert pf.flag == "STG-PUB-001"

    def test_provider_set_correctly(self):
        stub = _StubFinding("azure", "nsg", "nsg-1", "critical", "NET-AZ-001", "Open SSH", "Block it.")
        pf = _normalize_finding(stub, "azure")
        assert pf.provider == Provider.AZURE

    def test_severity_mapped_correctly(self):
        stub = _StubFinding("gcp", "storage_bucket", "bucket-x", "medium", "STG-PUB-006", "Public IAM", "Fix.")
        pf = _normalize_finding(stub, "gcp")
        assert pf.severity == Severity.MEDIUM

    def test_resource_name_used(self):
        stub = _StubFinding("aws", "s3_bucket", "important-bucket", "low", "STG-001", "T", "R.")
        pf = _normalize_finding(stub, "aws")
        assert pf.resource_name == "important-bucket"

    def test_fallback_to_resource_id_when_no_name(self):
        """NSGFinding uses resource_id; resource_name defaults to empty string."""
        class _NSGLike:
            resource_type = "network_security_group"
            resource_name = ""   # empty — should fall back to resource_id
            resource_id = "nsg-prod"
            severity = "high"
            rule_id = "NET-AZ-001"
            title = "Admin port exposed"
            recommendation = "Block it."

        pf = _normalize_finding(_NSGLike(), "azure")
        assert pf.resource_name == "nsg-prod"

    def test_title_and_recommendation_copied(self):
        stub = _StubFinding("aws", "sg", "sg-001", "high", "NET001", "SSH open", "Block port 22.")
        pf = _normalize_finding(stub, "aws")
        assert pf.title == "SSH open"
        assert pf.recommendation == "Block port 22."


# ---------------------------------------------------------------------------
# run_multi_cloud_scan — dry run and filtering
# ---------------------------------------------------------------------------

class TestRunMultiCloudScan:

    def test_dry_run_returns_empty_provider_results(self):
        report = run_multi_cloud_scan(dry_run=True)
        assert report.provider_results == []

    def test_dry_run_scan_id_is_set(self):
        report = run_multi_cloud_scan(dry_run=True)
        assert report.scan_id  # non-empty string
        assert len(report.scan_id) == 8  # first 8 chars of UUID

    def test_dry_run_scanned_at_is_set(self):
        report = run_multi_cloud_scan(dry_run=True)
        assert isinstance(report.scanned_at, datetime)

    def test_providers_filter_limits_scan(self):
        """With providers=["aws"], only an aws ProviderScanResult should be present."""
        # The scan will fail to reach real AWS but should still produce one result
        report = run_multi_cloud_scan(providers=["aws"])
        provider_names = [pr.provider for pr in report.provider_results]
        assert "azure" not in provider_names
        assert "gcp" not in provider_names
        # aws entry may be skipped/errored but should be present
        assert "aws" in provider_names

    def test_disabled_config_not_scanned(self):
        configs = [
            ProviderScanConfig(provider="aws", enabled=False),
            ProviderScanConfig(provider="gcp", enabled=False),
        ]
        report = run_multi_cloud_scan(configs=configs)
        assert report.provider_results == []

    def test_empty_configs_returns_empty_report(self):
        report = run_multi_cloud_scan(configs=[])
        assert report.provider_results == []
        assert report.total_findings == 0

    def test_provider_filter_with_enabled_true_but_not_in_filter(self):
        configs = [
            ProviderScanConfig(provider="aws"),
            ProviderScanConfig(provider="gcp"),
        ]
        report = run_multi_cloud_scan(configs=configs, providers=["gcp"])
        provider_names = [pr.provider for pr in report.provider_results]
        assert "aws" not in provider_names


# ---------------------------------------------------------------------------
# _default_configs
# ---------------------------------------------------------------------------

class TestDefaultConfigs:

    def test_returns_three_providers(self):
        configs = _default_configs()
        providers = {c.provider for c in configs}
        assert providers == {"aws", "azure", "gcp"}

    def test_aws_region_from_env(self):
        with patch.dict("os.environ", {"AWS_REGION": "ap-southeast-1"}):
            configs = _default_configs()
            aws_cfg = next(c for c in configs if c.provider == "aws")
            assert aws_cfg.aws_region == "ap-southeast-1"

    def test_aws_region_default_when_not_set(self):
        env = {k: v for k, v in __import__("os").environ.items() if k != "AWS_REGION"}
        with patch.dict("os.environ", env, clear=True):
            configs = _default_configs()
            aws_cfg = next(c for c in configs if c.provider == "aws")
            assert aws_cfg.aws_region == "us-east-1"

    def test_azure_sub_id_from_env(self):
        with patch.dict("os.environ", {"AZURE_SUBSCRIPTION_ID": "sub-test-123"}):
            configs = _default_configs()
            az_cfg = next(c for c in configs if c.provider == "azure")
            assert az_cfg.azure_subscription_id == "sub-test-123"

    def test_gcp_project_id_from_env(self):
        with patch.dict("os.environ", {"GCP_PROJECT_ID": "my-project"}):
            configs = _default_configs()
            gcp_cfg = next(c for c in configs if c.provider == "gcp")
            assert gcp_cfg.gcp_project_id == "my-project"
