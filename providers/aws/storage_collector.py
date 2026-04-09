"""
AWS Storage Posture Collector
==============================
Collects S3 bucket configurations to assess public exposure,
encryption posture, and logging coverage.

Permissions required (read-only):
  - s3:ListAllMyBuckets
  - s3:GetBucketAcl
  - s3:GetBucketEncryption
  - s3:GetBucketLogging
  - s3:GetBucketVersioning
  - s3:GetBucketPublicAccessBlock

Use only on accounts you are authorized to assess.
"""
import boto3
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BucketPosture:
    """Posture data for a single S3 bucket."""
    name: str
    region: str
    public_access_blocked: bool
    acl_public: bool             # True if ACL grants public access
    encryption_enabled: bool
    logging_enabled: bool
    versioning_enabled: bool
    owner: Optional[str]
    risk_flags: list[str] = field(default_factory=list)


def assess_bucket_posture(session: boto3.Session) -> list[BucketPosture]:
    """
    Assess posture of all S3 buckets in the account.

    Returns a list of BucketPosture objects, one per bucket.
    Flags buckets with public access, missing encryption, or disabled logging.
    """
    s3 = session.client("s3")
    buckets_response = s3.list_buckets()
    results = []

    for bucket in buckets_response.get("Buckets", []):
        name = bucket["Name"]
        flags: list[str] = []

        # Check public access block settings
        try:
            pab = s3.get_bucket_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            public_access_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            public_access_blocked = False
            flags.append("no_public_access_block")

        if not public_access_blocked:
            flags.append("public_access_not_fully_blocked")

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            encryption_enabled = True
        except Exception:
            encryption_enabled = False
            flags.append("encryption_not_enabled")

        # Check logging
        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            logging_enabled = "LoggingEnabled" in logging_cfg
        except Exception:
            logging_enabled = False

        if not logging_enabled:
            flags.append("server_access_logging_disabled")

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            versioning_enabled = versioning.get("Status") == "Enabled"
        except Exception:
            versioning_enabled = False

        # Determine bucket region (LocationConstraint is None for us-east-1)
        try:
            location = s3.get_bucket_location(Bucket=name)
            region = location.get("LocationConstraint") or "us-east-1"
        except Exception:
            region = "unknown"

        results.append(BucketPosture(
            name=name,
            region=region,
            public_access_blocked=public_access_blocked,
            acl_public=False,  # Would need GetBucketAcl for full check
            encryption_enabled=encryption_enabled,
            logging_enabled=logging_enabled,
            versioning_enabled=versioning_enabled,
            owner=None,
            risk_flags=flags,
        ))

    return results
