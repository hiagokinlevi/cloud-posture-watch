"""
S3 Bucket Policy Analyzer
===========================
Analyzes S3 bucket policies and ACL configurations for public exposure,
cross-account trust, missing encryption enforcement, and missing logging.

Operates on structured policy dicts — no live AWS credentials required for
testing. Feed it parsed bucket policy JSON + ACL metadata.

Check IDs
----------
S3-PUB-001   Public grants in bucket policy (AllUsers / AuthenticatedUsers)
S3-PUB-002   Bucket ACL grants public read or full-control
S3-XACCT-001 Cross-account principal with wide action scope
S3-ENC-001   Bucket policy does not enforce encryption (missing denyUnencrypted)
S3-LOG-001   No server access logging or CloudTrail S3 data events configured
S3-VERS-001  Versioning not enabled (data loss risk)
S3-TLS-001   Bucket policy does not deny non-TLS (http) requests

Usage::

    from analyzers.s3_policy_analyzer import S3PolicyAnalyzer, BucketConfig

    config = BucketConfig(
        name="my-bucket",
        policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }]
        },
        acl_grants=[{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}],
    )
    analyzer = S3PolicyAnalyzer()
    report = analyzer.analyze(config)
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class S3Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# BucketConfig — input model
# ---------------------------------------------------------------------------

@dataclass
class BucketConfig:
    """
    Configuration snapshot for one S3 bucket.

    Attributes:
        name:               Bucket name.
        policy:             Parsed bucket policy document (dict) or None.
        acl_grants:         List of ACL grant dicts (from GetBucketAcl).
        versioning_enabled: True if versioning is Enabled (not Suspended/None).
        logging_enabled:    True if access logging or CloudTrail data events configured.
        account_id:         Owner AWS account ID (12 digits). Used for cross-account checks.
    """
    name:               str
    policy:             Optional[Dict] = None
    acl_grants:         List[Dict]     = field(default_factory=list)
    versioning_enabled: bool           = False
    logging_enabled:    bool           = False
    account_id:         str            = ""


# ---------------------------------------------------------------------------
# S3Finding
# ---------------------------------------------------------------------------

@dataclass
class S3Finding:
    """
    A single S3 security finding.

    Attributes:
        check_id:   S3-* identifier.
        severity:   Severity level.
        bucket:     Bucket name.
        title:      Short description.
        detail:     Detailed explanation.
        evidence:   Specific value / statement that triggered the check.
        remediation: Recommended fix.
    """
    check_id:    str
    severity:    S3Severity
    bucket:      str
    title:       str
    detail:      str
    evidence:    str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "bucket":      self.bucket,
            "title":       self.title,
            "detail":      self.detail,
            "evidence":    self.evidence[:512],
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        return f"[{self.check_id}] {self.severity.value}: {self.title} ({self.bucket})"


# ---------------------------------------------------------------------------
# S3PolicyReport
# ---------------------------------------------------------------------------

@dataclass
class S3PolicyReport:
    """
    Aggregated S3 security analysis report.

    Attributes:
        findings:     All findings across analyzed buckets.
        risk_score:   0–100 aggregate risk score.
        generated_at: Unix timestamp.
    """
    findings:     List[S3Finding] = field(default_factory=list)
    risk_score:   int             = 0
    generated_at: float           = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> List[S3Finding]:
        return [f for f in self.findings if f.severity == S3Severity.CRITICAL]

    @property
    def high_findings(self) -> List[S3Finding]:
        return [f for f in self.findings if f.severity == S3Severity.HIGH]

    def findings_by_check(self, check_id: str) -> List[S3Finding]:
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_bucket(self, name: str) -> List[S3Finding]:
        return [f for f in self.findings if f.bucket == name]

    def summary(self) -> str:
        return (
            f"S3 Policy Report: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"critical={len(self.critical_findings)}, "
            f"high={len(self.high_findings)}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score":     self.risk_score,
            "critical":       len(self.critical_findings),
            "high":           len(self.high_findings),
            "generated_at":   self.generated_at,
            "findings":       [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AWS public group URIs
_PUBLIC_GROUPS = frozenset({
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
})

# Actions that are dangerous if granted publicly
_DANGEROUS_ACTIONS = frozenset({
    "s3:*",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutEncryptionConfiguration",
})

_BROAD_ACTIONS = frozenset({
    "s3:GetObject",
    "s3:ListBucket",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicy",
})

_CHECK_WEIGHTS = {
    "S3-PUB-001":   50,
    "S3-PUB-002":   45,
    "S3-XACCT-001": 30,
    "S3-ENC-001":   25,
    "S3-LOG-001":   15,
    "S3-VERS-001":  10,
    "S3-TLS-001":   20,
}

_ACCOUNT_ID_RE = re.compile(r"arn:aws:iam::(\d{12}):")


def _account_from_principal(principal_str: str) -> Optional[str]:
    """Extract account ID from an ARN principal string."""
    m = _ACCOUNT_ID_RE.search(principal_str)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# S3PolicyAnalyzer
# ---------------------------------------------------------------------------

class S3PolicyAnalyzer:
    """
    Analyze S3 bucket policy and configuration for security issues.

    Args:
        check_versioning: Include versioning check (default True).
        check_logging:    Include logging check (default True).
    """

    def __init__(
        self,
        check_versioning: bool = True,
        check_logging: bool = True,
    ) -> None:
        self._check_versioning = check_versioning
        self._check_logging    = check_logging

    def analyze(self, config: BucketConfig) -> S3PolicyReport:
        """
        Analyze a single bucket configuration.

        Returns:
            S3PolicyReport with all findings and risk score.
        """
        findings: List[S3Finding] = []

        if config.policy:
            findings.extend(self._check_public_policy(config))
            findings.extend(self._check_cross_account(config))
            findings.extend(self._check_encryption_enforcement(config))
            findings.extend(self._check_tls_enforcement(config))

        findings.extend(self._check_acl_public(config))

        if self._check_logging and not config.logging_enabled:
            findings.append(S3Finding(
                check_id="S3-LOG-001",
                severity=S3Severity.MEDIUM,
                bucket=config.name,
                title="No server access logging configured",
                detail=(
                    f"Bucket '{config.name}' has neither S3 server access "
                    f"logging nor CloudTrail S3 data events enabled."
                ),
                remediation="Enable S3 server access logging or CloudTrail S3 data events.",
            ))

        if self._check_versioning and not config.versioning_enabled:
            findings.append(S3Finding(
                check_id="S3-VERS-001",
                severity=S3Severity.LOW,
                bucket=config.name,
                title="Object versioning not enabled",
                detail=(
                    f"Bucket '{config.name}' has versioning disabled or suspended. "
                    f"Accidental deletes or overwrites cannot be recovered."
                ),
                remediation="Enable S3 versioning and configure lifecycle rules.",
            ))

        fired = {f.check_id for f in findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired))

        return S3PolicyReport(findings=findings, risk_score=score)

    def analyze_many(self, configs: List[BucketConfig]) -> S3PolicyReport:
        """Analyze multiple buckets and return combined report."""
        all_findings: List[S3Finding] = []
        for config in configs:
            r = self.analyze(config)
            all_findings.extend(r.findings)
        fired = {f.check_id for f in all_findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired))
        return S3PolicyReport(findings=all_findings, risk_score=score)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _get_statements(self, config: BucketConfig) -> List[Dict]:
        policy = config.policy or {}
        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        return stmts

    def _check_public_policy(self, config: BucketConfig) -> List[S3Finding]:
        """S3-PUB-001: Allow statement with Principal * or public groups."""
        findings: List[S3Finding] = []
        for stmt in self._get_statements(config):
            if stmt.get("Effect", "").upper() != "ALLOW":
                continue
            principal = stmt.get("Principal", "")
            if self._is_public_principal(principal):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                sev = (
                    S3Severity.CRITICAL
                    if any(a in _DANGEROUS_ACTIONS for a in actions)
                    else S3Severity.HIGH
                )
                findings.append(S3Finding(
                    check_id="S3-PUB-001",
                    severity=sev,
                    bucket=config.name,
                    title="Bucket policy allows public access",
                    detail=(
                        f"Statement in bucket '{config.name}' policy has "
                        f"Principal='{principal}' with Effect=Allow."
                    ),
                    evidence=str(stmt)[:256],
                    remediation=(
                        "Remove public principal from bucket policy. "
                        "Use resource-based policies with specific account/role ARNs."
                    ),
                ))
        return findings

    def _check_acl_public(self, config: BucketConfig) -> List[S3Finding]:
        """S3-PUB-002: ACL grants public read or full-control."""
        findings: List[S3Finding] = []
        for grant in config.acl_grants:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            permission = grant.get("Permission", "")
            if uri in _PUBLIC_GROUPS and permission in ("READ", "FULL_CONTROL", "WRITE"):
                sev = (
                    S3Severity.CRITICAL
                    if permission == "FULL_CONTROL"
                    else S3Severity.HIGH
                )
                findings.append(S3Finding(
                    check_id="S3-PUB-002",
                    severity=sev,
                    bucket=config.name,
                    title="Bucket ACL grants public access",
                    detail=(
                        f"Bucket '{config.name}' ACL grants {permission} to "
                        f"public group {uri}."
                    ),
                    evidence=f"Grantee={uri} Permission={permission}",
                    remediation=(
                        "Remove public ACL grants. Use bucket policies instead of ACLs."
                    ),
                ))
        return findings

    def _check_cross_account(self, config: BucketConfig) -> List[S3Finding]:
        """S3-XACCT-001: Cross-account principal with broad action scope."""
        findings: List[S3Finding] = []
        if not config.account_id:
            return findings

        for stmt in self._get_statements(config):
            if stmt.get("Effect", "").upper() != "ALLOW":
                continue
            principal = stmt.get("Principal", "")
            principals = _flatten_principal(principal)
            for p in principals:
                acct = _account_from_principal(p)
                if acct and acct != config.account_id:
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    # Wide = includes dangerous or wildcard actions
                    if "s3:*" in actions or any(a in _DANGEROUS_ACTIONS for a in actions):
                        findings.append(S3Finding(
                            check_id="S3-XACCT-001",
                            severity=S3Severity.HIGH,
                            bucket=config.name,
                            title="Cross-account access with wide permissions",
                            detail=(
                                f"Bucket '{config.name}' policy grants "
                                f"cross-account principal ({acct}) broad actions: "
                                f"{actions}."
                            ),
                            evidence=str(stmt)[:256],
                            remediation=(
                                "Scope cross-account grants to minimum required actions. "
                                "Add Condition blocks to restrict by source ARN or org."
                            ),
                        ))
        return findings

    def _check_encryption_enforcement(self, config: BucketConfig) -> List[S3Finding]:
        """S3-ENC-001: No Deny statement for PutObject without server-side encryption."""
        stmts = self._get_statements(config)
        for stmt in stmts:
            if stmt.get("Effect", "").upper() != "DENY":
                continue
            action = stmt.get("Action", "")
            if isinstance(action, list):
                action_list = action
            else:
                action_list = [action]
            if "s3:PutObject" in action_list or "s3:*" in action_list:
                condition = stmt.get("Condition", {})
                # AWS recommends: Condition: Null: { s3:x-amz-server-side-encryption: true }
                # or StringNotEquals: s3:x-amz-server-side-encryption: [AES256, aws:kms]
                if condition:
                    return []  # some encryption condition present
        return [S3Finding(
            check_id="S3-ENC-001",
            severity=S3Severity.MEDIUM,
            bucket=config.name,
            title="Bucket policy does not enforce server-side encryption",
            detail=(
                f"Bucket '{config.name}' policy has no Deny statement requiring "
                f"server-side encryption on PutObject requests."
            ),
            remediation=(
                "Add a Deny statement with Condition: "
                "Null: {'s3:x-amz-server-side-encryption': true} "
                "to enforce SSE on all uploads."
            ),
        )]

    def _check_tls_enforcement(self, config: BucketConfig) -> List[S3Finding]:
        """S3-TLS-001: No Deny statement for non-TLS (aws:SecureTransport: false)."""
        stmts = self._get_statements(config)
        for stmt in stmts:
            if stmt.get("Effect", "").upper() != "DENY":
                continue
            condition = stmt.get("Condition", {})
            # Look for: Condition: Bool: { aws:SecureTransport: false }
            bool_cond = condition.get("Bool", {})
            if bool_cond.get("aws:SecureTransport") in ("false", False):
                return []
        return [S3Finding(
            check_id="S3-TLS-001",
            severity=S3Severity.MEDIUM,
            bucket=config.name,
            title="Bucket policy does not deny non-TLS requests",
            detail=(
                f"Bucket '{config.name}' policy has no Deny statement requiring "
                f"TLS (aws:SecureTransport: false)."
            ),
            remediation=(
                "Add: Deny all principals where aws:SecureTransport is false, "
                "to prevent unencrypted HTTP access to this bucket."
            ),
        )]

    @staticmethod
    def _is_public_principal(principal: Any) -> bool:
        if principal == "*":
            return True
        if isinstance(principal, str) and principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", "")
            if aws == "*":
                return True
            if isinstance(aws, list) and "*" in aws:
                return True
            fed = principal.get("Federated", "")
            if fed in _PUBLIC_GROUPS or (isinstance(fed, list) and any(f in _PUBLIC_GROUPS for f in fed)):
                return True
        return False


def _flatten_principal(principal: Any) -> List[str]:
    """Flatten principal to a list of ARN/identifier strings."""
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        return principal
    if isinstance(principal, dict):
        result = []
        for v in principal.values():
            if isinstance(v, str):
                result.append(v)
            elif isinstance(v, list):
                result.extend(v)
        return result
    return []
