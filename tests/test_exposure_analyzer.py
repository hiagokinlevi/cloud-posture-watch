"""
Tests for analyzers/exposure_analyzer.py
==========================================
Validates that the exposure analyzer correctly maps risk flags to findings
and assigns accurate severity levels.
"""
from dataclasses import dataclass, field

import pytest

from analyzers.exposure_analyzer import ExposureFinding, analyze_exposure


@dataclass
class MockBucketPosture:
    """Minimal mock posture object for testing the exposure analyzer."""
    name: str
    risk_flags: list[str] = field(default_factory=list)


class TestAnalyzeExposure:
    """Tests for analyze_exposure()."""

    def test_returns_empty_list_when_no_flags(self):
        """Resources with no risk flags should produce no findings."""
        postures = [MockBucketPosture(name="clean-bucket")]
        findings = analyze_exposure(postures, provider="aws", resource_type="s3_bucket")
        assert findings == []

    def test_maps_known_flag_to_finding(self):
        """A known risk flag should produce exactly one ExposureFinding."""
        postures = [
            MockBucketPosture(name="exposed-bucket", risk_flags=["public_access_not_fully_blocked"])
        ]
        findings = analyze_exposure(postures, provider="aws", resource_type="s3_bucket")
        assert len(findings) == 1
        assert findings[0].resource_name == "exposed-bucket"
        assert findings[0].severity == "high"
        assert findings[0].flag == "public_access_not_fully_blocked"

    def test_multiple_flags_produce_multiple_findings(self):
        """Each flag on a resource should produce a separate finding."""
        postures = [
            MockBucketPosture(
                name="bad-bucket",
                risk_flags=["public_access_not_fully_blocked", "encryption_not_enabled"],
            )
        ]
        findings = analyze_exposure(postures, provider="aws", resource_type="s3_bucket")
        assert len(findings) == 2

    def test_gcp_public_iam_binding_is_critical(self):
        """Public IAM binding on GCS should be classified as critical."""
        postures = [
            MockBucketPosture(
                name="public-gcs-bucket",
                risk_flags=["public_iam_binding_detected"],
            )
        ]
        findings = analyze_exposure(postures, provider="gcp", resource_type="gcs_bucket")
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_unknown_flag_produces_low_severity_finding(self):
        """An unrecognised flag should not crash the analyzer; it should produce a LOW finding."""
        postures = [
            MockBucketPosture(name="odd-bucket", risk_flags=["some_unknown_flag"])
        ]
        findings = analyze_exposure(postures, provider="aws", resource_type="s3_bucket")
        assert len(findings) == 1
        assert findings[0].severity == "low"

    def test_findings_sorted_critical_first(self):
        """Findings should be sorted by severity, most critical first."""
        postures = [
            MockBucketPosture(
                name="multi-flag",
                risk_flags=["server_access_logging_disabled", "public_iam_binding_detected"],
            )
        ]
        findings = analyze_exposure(postures, provider="gcp", resource_type="gcs_bucket")
        severities = [f.severity for f in findings]
        # critical should precede medium
        assert severities[0] == "critical"

    def test_provider_is_propagated_to_finding(self):
        """The provider field should match the argument passed to analyze_exposure."""
        postures = [
            MockBucketPosture(name="bucket", risk_flags=["https_not_enforced"])
        ]
        findings = analyze_exposure(postures, provider="azure", resource_type="storage_account")
        assert findings[0].provider == "azure"

    def test_empty_posture_list_returns_empty_findings(self):
        """An empty input list should return an empty findings list."""
        findings = analyze_exposure([], provider="aws", resource_type="s3_bucket")
        assert findings == []

    def test_multiple_resources_each_produce_findings(self):
        """Flags from multiple resources should each generate separate findings."""
        postures = [
            MockBucketPosture(name="bucket-a", risk_flags=["encryption_not_enabled"]),
            MockBucketPosture(name="bucket-b", risk_flags=["encryption_not_enabled"]),
        ]
        findings = analyze_exposure(postures, provider="aws", resource_type="s3_bucket")
        assert len(findings) == 2
        names = {f.resource_name for f in findings}
        assert names == {"bucket-a", "bucket-b"}
