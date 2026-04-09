"""
Cross-Cloud Exposure Analyzer
================================
Analyzes provider collector output and flags resources that are, or may be,
publicly accessible.

The analyzer is provider-agnostic at the interface level: it receives lists of
objects that implement the ExposureCheckable protocol (duck typing — any object
with a `risk_flags` list and a `name` string).

Severity levels
---------------
- critical  : Confirmed public exposure (e.g. S3 with public access block off + public ACL)
- high      : Strong indicator of exposure (public access block not fully enabled)
- medium    : Partial control missing (logging disabled alongside open access)
- low       : Informational / recommended improvement

Usage
-----
    from providers.aws.storage_collector import assess_bucket_posture
    from analyzers.exposure_analyzer import analyze_exposure

    postures = assess_bucket_posture(session)
    findings = analyze_exposure(postures, provider="aws")
"""
from dataclasses import dataclass
from typing import Any


@dataclass
class ExposureFinding:
    """A single exposure-related finding for a resource."""
    provider: str           # "aws", "azure", "gcp"
    resource_type: str      # e.g. "s3_bucket", "storage_account", "gcs_bucket"
    resource_name: str
    severity: str           # "critical", "high", "medium", "low"
    flag: str               # The specific risk flag that triggered this finding
    title: str              # Short human-readable description
    recommendation: str     # Actionable remediation step


# Mapping of risk flags to finding metadata
# Each entry is (severity, title, recommendation)
_FLAG_METADATA: dict[str, tuple[str, str, str]] = {
    # AWS S3 flags
    "no_public_access_block": (
        "high",
        "S3 bucket has no Public Access Block configuration",
        "Enable all four S3 Block Public Access settings at the bucket level, "
        "or preferably at the account level via S3 > Block Public Access (account settings).",
    ),
    "public_access_not_fully_blocked": (
        "high",
        "S3 bucket Public Access Block is not fully enabled",
        "Ensure all four settings are True: BlockPublicAcls, IgnorePublicAcls, "
        "BlockPublicPolicy, RestrictPublicBuckets.",
    ),
    "encryption_not_enabled": (
        "medium",
        "S3 bucket does not have default encryption enabled",
        "Enable default encryption using SSE-S3 (AES-256) or SSE-KMS. "
        "For sensitive data, prefer SSE-KMS with a customer-managed key.",
    ),
    "server_access_logging_disabled": (
        "medium",
        "S3 server access logging is disabled",
        "Enable S3 server access logging and direct logs to a dedicated, "
        "security-controlled logging bucket.",
    ),
    # Azure Storage Account flags
    "https_not_enforced": (
        "high",
        "Azure Storage Account does not require HTTPS",
        "Enable 'Secure transfer required' (enableHttpsTrafficOnly: true) "
        "on the storage account to reject unencrypted connections.",
    ),
    "public_blob_access_allowed": (
        "high",
        "Azure Storage Account allows public blob access",
        "Set allowBlobPublicAccess to false on the storage account. "
        "Review individual container access levels to ensure none are public.",
    ),
    "weak_tls_version": (
        "medium",
        "Azure Storage Account minimum TLS version is below 1.2",
        "Set minimumTlsVersion to TLS1_2 to reject connections from clients "
        "using deprecated TLS 1.0 or 1.1.",
    ),
    # GCP Cloud Storage flags
    "uniform_bucket_level_access_disabled": (
        "medium",
        "GCS bucket does not use uniform bucket-level access",
        "Enable uniform bucket-level access to disable legacy ACLs and manage "
        "permissions exclusively through IAM.",
    ),
    "public_iam_binding_detected": (
        "critical",
        "GCS bucket grants access to allUsers or allAuthenticatedUsers",
        "Remove IAM bindings for allUsers and allAuthenticatedUsers unless "
        "the bucket intentionally serves public content.",
    ),
    "access_logging_disabled": (
        "medium",
        "GCS bucket access logging is not enabled",
        "Configure a log bucket to receive GCS access logs for this bucket.",
    ),
}


def analyze_exposure(
    postures: list[Any],
    provider: str,
    resource_type: str = "storage",
) -> list[ExposureFinding]:
    """
    Analyze a list of resource posture objects for exposure indicators.

    Args:
        postures: List of posture dataclass instances (from any provider collector).
                  Each must have a `name` attribute and a `risk_flags` list.
        provider: Cloud provider identifier ("aws", "azure", "gcp").
        resource_type: Descriptive resource type string for the findings report.

    Returns:
        List of ExposureFinding objects, one per flag per resource.
        Sorted by severity (critical first).
    """
    findings: list[ExposureFinding] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for posture in postures:
        resource_name = getattr(posture, "name", "unknown")

        for flag in getattr(posture, "risk_flags", []):
            # Look up metadata for the flag (strip dynamic suffixes like "weak_tls_version:TLS1_0")
            base_flag = flag.split(":")[0]
            metadata = _FLAG_METADATA.get(base_flag)

            if metadata:
                severity, title, recommendation = metadata
            else:
                # Unknown flag — record at low severity for awareness
                severity, title, recommendation = (
                    "low",
                    f"Unclassified risk flag: {flag}",
                    "Review this flag and determine whether it represents a risk in your environment.",
                )

            findings.append(ExposureFinding(
                provider=provider,
                resource_type=resource_type,
                resource_name=resource_name,
                severity=severity,
                flag=flag,
                title=title,
                recommendation=recommendation,
            ))

    # Sort by severity so the most critical findings appear first
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings
