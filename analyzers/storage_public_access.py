"""
Storage Public Access Analyzer
================================
Cross-cloud analyzer that detects publicly accessible storage resources.

Public storage is one of the most common causes of cloud data breaches.
This analyzer provides a unified view of public access risk across AWS S3,
Azure Blob Storage, and GCP Cloud Storage.

Checks performed:
  - STG-PUB-001 CRITICAL: S3 bucket has no PublicAccessBlock configured
  - STG-PUB-002 CRITICAL: S3 bucket has PublicAccessBlock disabled on all four controls
  - STG-PUB-003 HIGH:     S3 bucket has PublicAccessBlock partially disabled
  - STG-PUB-004 CRITICAL: Azure Storage Account allows public blob access
  - STG-PUB-005 HIGH:     Azure Storage Account uses HTTP (not HTTPS-only)
  - STG-PUB-006 CRITICAL: GCS bucket has allUsers or allAuthenticatedUsers IAM binding
  - STG-PUB-007 HIGH:     GCS bucket does not use uniform bucket-level access

Input objects are passed as generic dicts or typed posture objects — the
analyzer reads well-known attribute names that all three collectors set.

Usage:
    from providers.aws.storage_collector import assess_bucket_posture
    from analyzers.storage_public_access import analyze_storage_public_access

    # AWS
    s3_postures = assess_bucket_posture(boto3_session)
    findings = analyze_storage_public_access(s3_postures, provider="aws")

    # Azure (use StorageAccountPosture objects from azure/storage_collector)
    az_postures = assess_storage_account_posture(subscription_id)
    findings = analyze_storage_public_access(az_postures, provider="azure")
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class StoragePublicAccessFinding:
    """A single storage public access finding."""

    provider: str           # "aws", "azure", "gcp"
    resource_type: str
    resource_name: str
    severity: str           # "critical", "high", "medium", "low", "info"
    rule_id: str            # e.g. "STG-PUB-001"
    title: str
    detail: str
    recommendation: str


def analyze_storage_public_access(
    postures: list[Any],
    provider: str,
) -> list[StoragePublicAccessFinding]:
    """
    Analyze storage resource postures for public access risk.

    Dispatches to the provider-specific analyzer based on the 'provider' argument.
    Accepts posture objects from the respective collectors (AWS, Azure, GCP).

    Args:
        postures: List of posture objects from the provider's storage collector.
        provider: Cloud provider string: "aws", "azure", or "gcp".

    Returns:
        List of StoragePublicAccessFinding objects, sorted by severity.
    """
    findings: list[StoragePublicAccessFinding] = []

    for posture in postures:
        if provider == "aws":
            findings.extend(_analyze_s3(posture))
        elif provider == "azure":
            findings.extend(_analyze_azure_blob(posture))
        elif provider == "gcp":
            findings.extend(_analyze_gcs(posture))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings


# ---------------------------------------------------------------------------
# AWS S3
# ---------------------------------------------------------------------------

def _analyze_s3(posture: Any) -> list[StoragePublicAccessFinding]:
    """
    Analyze an AWS S3 bucket posture for public access risk.

    Reads attributes from S3BucketPosture:
      public_access_block_configured: bool
      block_public_acls: bool
      block_public_policy: bool
      ignore_public_acls: bool
      restrict_public_buckets: bool
    """
    findings: list[StoragePublicAccessFinding] = []
    name = getattr(posture, "name", "unknown")

    configured = getattr(posture, "public_access_block_configured", None)

    # STG-PUB-001: No PublicAccessBlock at all
    if configured is False:
        findings.append(StoragePublicAccessFinding(
            provider="aws",
            resource_type="s3_bucket",
            resource_name=name,
            severity="critical",
            rule_id="STG-PUB-001",
            title=f"S3 bucket '{name}' has no PublicAccessBlock configured",
            detail="PublicAccessBlock is not configured on this bucket.",
            recommendation=(
                f"Enable S3 PublicAccessBlock on bucket '{name}' with all four controls "
                "set to True: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, "
                "RestrictPublicBuckets. This is the strongest protection against accidental "
                "public exposure. Apply at the account level via S3 account-level settings "
                "to protect all current and future buckets."
            ),
        ))
        return findings  # Further checks require the block to be configured

    # Check each individual control if block is configured
    controls = {
        "block_public_acls":       "BlockPublicAcls",
        "block_public_policy":     "BlockPublicPolicy",
        "ignore_public_acls":      "IgnorePublicAcls",
        "restrict_public_buckets": "RestrictPublicBuckets",
    }
    disabled = [
        (attr, control_name)
        for attr, control_name in controls.items()
        if getattr(posture, attr, True) is False
    ]

    if len(disabled) == len(controls):
        # STG-PUB-002: All four controls disabled
        findings.append(StoragePublicAccessFinding(
            provider="aws",
            resource_type="s3_bucket",
            resource_name=name,
            severity="critical",
            rule_id="STG-PUB-002",
            title=f"S3 bucket '{name}' has all PublicAccessBlock controls disabled",
            detail="All four PublicAccessBlock controls are False.",
            recommendation=(
                f"Enable all four PublicAccessBlock controls for bucket '{name}'. "
                "Having all controls disabled is equivalent to having no block configured."
            ),
        ))
    elif disabled:
        # STG-PUB-003: Some controls disabled
        disabled_names = [n for _, n in disabled]
        findings.append(StoragePublicAccessFinding(
            provider="aws",
            resource_type="s3_bucket",
            resource_name=name,
            severity="high",
            rule_id="STG-PUB-003",
            title=(
                f"S3 bucket '{name}' has {len(disabled)} PublicAccessBlock "
                f"control(s) disabled: {disabled_names}"
            ),
            detail=f"Disabled controls: {disabled_names}",
            recommendation=(
                f"Enable the following PublicAccessBlock controls for bucket '{name}': "
                f"{disabled_names}. Partial protection leaves the bucket vulnerable to "
                "specific types of public access."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Azure Blob Storage
# ---------------------------------------------------------------------------

def _analyze_azure_blob(posture: Any) -> list[StoragePublicAccessFinding]:
    """
    Analyze an Azure StorageAccountPosture for public access risk.

    Reads:
      public_blob_access_allowed: bool
      https_only: bool
    """
    findings: list[StoragePublicAccessFinding] = []
    name = getattr(posture, "name", "unknown")

    # STG-PUB-004: Public blob access allowed
    if getattr(posture, "public_blob_access_allowed", False):
        findings.append(StoragePublicAccessFinding(
            provider="azure",
            resource_type="storage_account",
            resource_name=name,
            severity="critical",
            rule_id="STG-PUB-004",
            title=f"Azure Storage Account '{name}' allows public blob access",
            detail="allowBlobPublicAccess is True — any container can be set to public.",
            recommendation=(
                f"Set 'allowBlobPublicAccess: false' on storage account '{name}'. "
                "This property controls whether containers can be made public. "
                "Disabling it at the account level overrides any container-level "
                "public access settings. Use SAS tokens or Entra ID for controlled access."
            ),
        ))

    # STG-PUB-005: HTTP access allowed (not HTTPS-only)
    if not getattr(posture, "https_only", True):
        findings.append(StoragePublicAccessFinding(
            provider="azure",
            resource_type="storage_account",
            resource_name=name,
            severity="high",
            rule_id="STG-PUB-005",
            title=f"Azure Storage Account '{name}' does not enforce HTTPS",
            detail="supportsHttpsTrafficOnly is False — data can be transferred in plaintext.",
            recommendation=(
                f"Enable 'Secure transfer required' (httpsOnly: true) on storage account '{name}'. "
                "This forces all requests to use HTTPS, preventing man-in-the-middle attacks "
                "that could intercept unencrypted data transfers."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# GCP Cloud Storage
# ---------------------------------------------------------------------------

def _analyze_gcs(posture: Any) -> list[StoragePublicAccessFinding]:
    """
    Analyze a GCS BucketPosture for public access risk.

    Reads:
      public_iam_bindings: list[str]  — roles granted to allUsers/allAuthenticatedUsers
      uniform_bucket_level_access: bool
    """
    findings: list[StoragePublicAccessFinding] = []
    name = getattr(posture, "name", "unknown")

    # STG-PUB-006: allUsers or allAuthenticatedUsers in IAM bindings
    public_bindings = getattr(posture, "public_iam_bindings", []) or []
    if public_bindings:
        findings.append(StoragePublicAccessFinding(
            provider="gcp",
            resource_type="gcs_bucket",
            resource_name=name,
            severity="critical",
            rule_id="STG-PUB-006",
            title=(
                f"GCS bucket '{name}' has public IAM bindings: {public_bindings}"
            ),
            detail=(
                f"allUsers or allAuthenticatedUsers are granted roles: {public_bindings}"
            ),
            recommendation=(
                f"Remove all allUsers and allAuthenticatedUsers IAM bindings from "
                f"bucket '{name}'. Public IAM bindings make bucket objects accessible "
                "to anyone on the internet (allUsers) or any Google account "
                "(allAuthenticatedUsers). Use signed URLs for time-limited public access."
            ),
        ))

    # STG-PUB-007: Uniform bucket-level access not enabled
    if not getattr(posture, "uniform_bucket_level_access", True):
        findings.append(StoragePublicAccessFinding(
            provider="gcp",
            resource_type="gcs_bucket",
            resource_name=name,
            severity="high",
            rule_id="STG-PUB-007",
            title=f"GCS bucket '{name}' does not use uniform bucket-level access",
            detail="Uniform bucket-level access is disabled — legacy ACLs can grant public access.",
            recommendation=(
                f"Enable uniform bucket-level access on GCS bucket '{name}'. "
                "Without it, individual objects can have ACLs granting public access, "
                "which is harder to audit and manage. Uniform access disables object "
                "ACLs and enforces IAM-only access control."
            ),
        ))

    return findings
