"""
Unit tests for analyzers/storage_public_access.py

Tests cover:
  - AWS S3 PublicAccessBlock (missing, all disabled, partially disabled)
  - Azure public blob access and HTTPS enforcement
  - GCP public IAM bindings and uniform bucket access
  - Cross-provider: findings sorted by severity
  - Empty inputs return empty lists
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.storage_public_access import (
    StoragePublicAccessFinding,
    analyze_storage_public_access,
)


# ---------------------------------------------------------------------------
# Mock posture objects
# ---------------------------------------------------------------------------


class _S3BucketPosture:
    """Minimal mock matching AWS S3BucketPosture attribute names."""

    def __init__(
        self,
        name: str = "my-bucket",
        public_access_block_configured: bool = True,
        block_public_acls: bool = True,
        block_public_policy: bool = True,
        ignore_public_acls: bool = True,
        restrict_public_buckets: bool = True,
    ):
        self.name = name
        self.public_access_block_configured = public_access_block_configured
        self.block_public_acls = block_public_acls
        self.block_public_policy = block_public_policy
        self.ignore_public_acls = ignore_public_acls
        self.restrict_public_buckets = restrict_public_buckets


class _AzureStoragePosture:
    """Minimal mock matching Azure StorageAccountPosture attribute names."""

    def __init__(
        self,
        name: str = "mystorage",
        public_blob_access_allowed: bool = False,
        https_only: bool = True,
    ):
        self.name = name
        self.public_blob_access_allowed = public_blob_access_allowed
        self.https_only = https_only


class _GCSBucketPosture:
    """Minimal mock matching GCP BucketPosture attribute names."""

    def __init__(
        self,
        name: str = "my-gcs-bucket",
        public_iam_bindings: list = None,
        uniform_bucket_level_access: bool = True,
    ):
        self.name = name
        self.public_iam_bindings = public_iam_bindings or []
        self.uniform_bucket_level_access = uniform_bucket_level_access


def _findings_by_rule(
    findings: list[StoragePublicAccessFinding], rule_id: str
) -> list[StoragePublicAccessFinding]:
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# AWS S3 — STG-PUB-001: No PublicAccessBlock configured
# ---------------------------------------------------------------------------


class TestS3NoPublicAccessBlock(unittest.TestCase):

    def test_no_public_access_block_is_critical(self):
        posture = _S3BucketPosture(public_access_block_configured=False)
        findings = analyze_storage_public_access([posture], provider="aws")
        stg001 = _findings_by_rule(findings, "STG-PUB-001")
        self.assertTrue(stg001)
        self.assertEqual(stg001[0].severity, "critical")

    def test_no_public_access_block_returns_single_finding(self):
        """When block is not configured, only STG-PUB-001 should fire (not 002/003)."""
        posture = _S3BucketPosture(public_access_block_configured=False)
        findings = analyze_storage_public_access([posture], provider="aws")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "STG-PUB-001")

    def test_public_access_block_configured_no_stg001(self):
        posture = _S3BucketPosture(public_access_block_configured=True)
        findings = analyze_storage_public_access([posture], provider="aws")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-001"))


# ---------------------------------------------------------------------------
# AWS S3 — STG-PUB-002: All controls disabled
# ---------------------------------------------------------------------------


class TestS3AllControlsDisabled(unittest.TestCase):

    def test_all_controls_disabled_is_critical(self):
        posture = _S3BucketPosture(
            public_access_block_configured=True,
            block_public_acls=False,
            block_public_policy=False,
            ignore_public_acls=False,
            restrict_public_buckets=False,
        )
        findings = analyze_storage_public_access([posture], provider="aws")
        stg002 = _findings_by_rule(findings, "STG-PUB-002")
        self.assertTrue(stg002)
        self.assertEqual(stg002[0].severity, "critical")

    def test_all_controls_enabled_no_stg002(self):
        posture = _S3BucketPosture()
        findings = analyze_storage_public_access([posture], provider="aws")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-002"))


# ---------------------------------------------------------------------------
# AWS S3 — STG-PUB-003: Partial controls disabled
# ---------------------------------------------------------------------------


class TestS3PartialControlsDisabled(unittest.TestCase):

    def test_one_control_disabled_is_high(self):
        posture = _S3BucketPosture(
            public_access_block_configured=True,
            block_public_acls=False,  # Only this one disabled
        )
        findings = analyze_storage_public_access([posture], provider="aws")
        stg003 = _findings_by_rule(findings, "STG-PUB-003")
        self.assertTrue(stg003)
        self.assertEqual(stg003[0].severity, "high")

    def test_two_controls_disabled_is_high(self):
        posture = _S3BucketPosture(
            public_access_block_configured=True,
            block_public_acls=False,
            block_public_policy=False,
        )
        findings = analyze_storage_public_access([posture], provider="aws")
        self.assertTrue(_findings_by_rule(findings, "STG-PUB-003"))

    def test_all_controls_enabled_no_stg003(self):
        posture = _S3BucketPosture()
        findings = analyze_storage_public_access([posture], provider="aws")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-003"))


# ---------------------------------------------------------------------------
# Azure — STG-PUB-004: Public blob access
# ---------------------------------------------------------------------------


class TestAzurePublicBlobAccess(unittest.TestCase):

    def test_public_blob_access_allowed_is_critical(self):
        posture = _AzureStoragePosture(public_blob_access_allowed=True)
        findings = analyze_storage_public_access([posture], provider="azure")
        stg004 = _findings_by_rule(findings, "STG-PUB-004")
        self.assertTrue(stg004)
        self.assertEqual(stg004[0].severity, "critical")

    def test_public_blob_access_disabled_no_stg004(self):
        posture = _AzureStoragePosture(public_blob_access_allowed=False)
        findings = analyze_storage_public_access([posture], provider="azure")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-004"))


# ---------------------------------------------------------------------------
# Azure — STG-PUB-005: HTTPS not enforced
# ---------------------------------------------------------------------------


class TestAzureHTTPSEnforcement(unittest.TestCase):

    def test_http_allowed_is_high(self):
        posture = _AzureStoragePosture(https_only=False)
        findings = analyze_storage_public_access([posture], provider="azure")
        stg005 = _findings_by_rule(findings, "STG-PUB-005")
        self.assertTrue(stg005)
        self.assertEqual(stg005[0].severity, "high")

    def test_https_only_no_stg005(self):
        posture = _AzureStoragePosture(https_only=True)
        findings = analyze_storage_public_access([posture], provider="azure")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-005"))

    def test_secure_storage_account_no_findings(self):
        """A storage account with no public access and HTTPS-only should have no findings."""
        posture = _AzureStoragePosture(public_blob_access_allowed=False, https_only=True)
        findings = analyze_storage_public_access([posture], provider="azure")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# GCP — STG-PUB-006: Public IAM bindings
# ---------------------------------------------------------------------------


class TestGCPPublicIAMBindings(unittest.TestCase):

    def test_all_users_binding_is_critical(self):
        posture = _GCSBucketPosture(public_iam_bindings=["roles/storage.objectViewer"])
        findings = analyze_storage_public_access([posture], provider="gcp")
        stg006 = _findings_by_rule(findings, "STG-PUB-006")
        self.assertTrue(stg006)
        self.assertEqual(stg006[0].severity, "critical")

    def test_no_public_bindings_no_stg006(self):
        posture = _GCSBucketPosture(public_iam_bindings=[])
        findings = analyze_storage_public_access([posture], provider="gcp")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-006"))


# ---------------------------------------------------------------------------
# GCP — STG-PUB-007: Non-uniform bucket access
# ---------------------------------------------------------------------------


class TestGCPUniformBucketAccess(unittest.TestCase):

    def test_non_uniform_access_is_high(self):
        posture = _GCSBucketPosture(uniform_bucket_level_access=False)
        findings = analyze_storage_public_access([posture], provider="gcp")
        stg007 = _findings_by_rule(findings, "STG-PUB-007")
        self.assertTrue(stg007)
        self.assertEqual(stg007[0].severity, "high")

    def test_uniform_access_enabled_no_stg007(self):
        posture = _GCSBucketPosture(uniform_bucket_level_access=True)
        findings = analyze_storage_public_access([posture], provider="gcp")
        self.assertFalse(_findings_by_rule(findings, "STG-PUB-007"))

    def test_secure_gcs_bucket_no_findings(self):
        posture = _GCSBucketPosture(
            public_iam_bindings=[],
            uniform_bucket_level_access=True,
        )
        findings = analyze_storage_public_access([posture], provider="gcp")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Severity sorting
# ---------------------------------------------------------------------------


class TestSeveritySorting(unittest.TestCase):

    def test_critical_before_high(self):
        postures = [
            _AzureStoragePosture(public_blob_access_allowed=True, https_only=False),
        ]
        findings = analyze_storage_public_access(postures, provider="azure")
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [severity_rank[f.severity] for f in findings]
        self.assertEqual(ranks, sorted(ranks))


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


class TestEmptyInput(unittest.TestCase):

    def test_aws_empty_returns_empty(self):
        self.assertEqual(analyze_storage_public_access([], provider="aws"), [])

    def test_azure_empty_returns_empty(self):
        self.assertEqual(analyze_storage_public_access([], provider="azure"), [])

    def test_gcp_empty_returns_empty(self):
        self.assertEqual(analyze_storage_public_access([], provider="gcp"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
