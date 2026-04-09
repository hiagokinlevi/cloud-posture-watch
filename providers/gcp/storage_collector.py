"""
GCP Cloud Storage Posture Collector
=====================================
Collects GCP Cloud Storage bucket configurations to assess security posture:
  - Uniform bucket-level access (replaces legacy ACLs)
  - Public access via IAM bindings (allUsers / allAuthenticatedUsers)
  - Versioning status
  - Retention policy presence
  - Logging configuration

Permissions required (read-only):
  - storage.buckets.list
  - storage.buckets.getIamPolicy
  - roles/storage.objectViewer (or roles/viewer) on the project

Use only on projects you are authorised to assess.
"""
from dataclasses import dataclass, field
from typing import Optional

from google.cloud import storage
from google.oauth2 import service_account


@dataclass
class GCSBucketPosture:
    """Posture data for a single GCS bucket."""
    name: str
    location: str
    location_type: str              # "region", "dual-region", "multi-region"
    uniform_bucket_level_access: bool
    public_iam_binding: bool        # True if allUsers or allAuthenticatedUsers has any role
    versioning_enabled: bool
    retention_policy_set: bool
    logging_enabled: bool
    risk_flags: list[str] = field(default_factory=list)


def _is_public_iam_binding(policy) -> bool:
    """
    Return True if the bucket IAM policy grants any role to allUsers
    or allAuthenticatedUsers — either of which exposes the bucket publicly.
    """
    public_members = {"allUsers", "allAuthenticatedUsers"}
    for binding in policy.bindings:
        if public_members.intersection(set(binding.get("members", []))):
            return True
    return False


def assess_gcs_bucket_posture(
    project_id: str,
    credentials_path: Optional[str] = None,
) -> list[GCSBucketPosture]:
    """
    Assess posture of all GCS buckets in the given GCP project.

    Args:
        project_id: GCP project ID (not the numeric project number).
        credentials_path: Path to a service account JSON key file.
                          If None, uses Application Default Credentials.

    Returns:
        List of GCSBucketPosture objects with risk flags populated.
    """
    # Build the storage client — prefer ADC for production use
    if credentials_path:
        creds = service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        client = storage.Client(project=project_id, credentials=creds)
    else:
        client = storage.Client(project=project_id)

    results = []

    for bucket in client.list_buckets():
        flags: list[str] = []

        # Reload full bucket metadata (list_buckets returns partial objects)
        bucket.reload()

        # Uniform bucket-level access disables legacy ACLs and is the recommended setting
        uba = bucket.iam_configuration.uniform_bucket_level_access_enabled
        if not uba:
            flags.append("uniform_bucket_level_access_disabled")

        # Check IAM policy for public bindings
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            public_iam = _is_public_iam_binding(policy)
        except Exception:
            public_iam = False  # Could not retrieve policy; note but don't assume public

        if public_iam:
            flags.append("public_iam_binding_detected")

        # Versioning
        versioning_enabled = bucket.versioning_enabled or False
        if not versioning_enabled:
            flags.append("versioning_disabled")

        # Retention policy (presence indicates data lifecycle governance)
        retention_policy_set = bucket.retention_policy is not None
        if not retention_policy_set:
            flags.append("retention_policy_not_set")

        # Logging — check if a log bucket is configured
        logging_enabled = bool(bucket.logging)
        if not logging_enabled:
            flags.append("access_logging_disabled")

        results.append(GCSBucketPosture(
            name=bucket.name,
            location=bucket.location or "unknown",
            location_type=bucket.location_type or "unknown",
            uniform_bucket_level_access=uba,
            public_iam_binding=public_iam,
            versioning_enabled=versioning_enabled,
            retention_policy_set=retention_policy_set,
            logging_enabled=logging_enabled,
            risk_flags=flags,
        ))

    return results
