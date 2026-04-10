"""
AWS IAM posture analyzer.

This module reviews offline IAM evidence for three high-value account risks:
root MFA status, stale active access keys, and overly permissive IAM policies.
It accepts JSON exported from AWS CLI workflows instead of requiring live AWS
credentials, which keeps the analyzer deterministic and safe for restricted
review environments.
"""
from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AWSIAMSeverity(str, Enum):
    """Severity levels for AWS IAM findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AWSAccessKey:
    """IAM access key evidence for one user."""

    user: str
    key_id: str
    active: bool = True
    age_days: int | None = None
    last_used_days_ago: int | None = None


@dataclass
class AWSPolicyStatement:
    """Normalized IAM policy statement."""

    effect: str = ""
    action: list[str] = field(default_factory=list)
    resource: list[str] = field(default_factory=list)
    condition: dict[str, Any] = field(default_factory=dict)


@dataclass
class AWSPolicyDocument:
    """IAM policy evidence with a stable policy identifier."""

    name: str
    statements: list[AWSPolicyStatement] = field(default_factory=list)


@dataclass
class AWSIAMSnapshot:
    """Offline AWS IAM evidence for one account."""

    account_id: str = "unknown"
    root_mfa_enabled: bool | None = None
    access_keys: list[AWSAccessKey] = field(default_factory=list)
    policies: list[AWSPolicyDocument] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AWSIAMSnapshot":
        """Build a snapshot from JSON-friendly AWS CLI export data."""
        root_mfa = _extract_root_mfa(data)
        account_id = str(data.get("account_id") or data.get("accountId") or "unknown")

        return cls(
            account_id=account_id,
            root_mfa_enabled=root_mfa,
            access_keys=_extract_access_keys(data),
            policies=_extract_policies(data),
        )


@dataclass
class AWSIAMFinding:
    """A single AWS IAM posture finding."""

    check_id: str
    severity: AWSIAMSeverity
    resource: str
    title: str
    detail: str
    recommendation: str

    @property
    def resource_type(self) -> str:
        return "iam"

    @property
    def resource_name(self) -> str:
        return self.resource

    @property
    def rule_id(self) -> str:
        return self.check_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "resource": self.resource,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class AWSIAMReport:
    """Aggregated AWS IAM analyzer result."""

    findings: list[AWSIAMFinding] = field(default_factory=list)
    snapshots_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[AWSIAMFinding]:
        return [f for f in self.findings if f.severity == AWSIAMSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[AWSIAMFinding]:
        return [f for f in self.findings if f.severity == AWSIAMSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> list[AWSIAMFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "critical": len(self.critical_findings),
            "high": len(self.high_findings),
            "snapshots_analyzed": self.snapshots_analyzed,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


_ADMIN_ACTION_PATTERNS = {
    "*",
    "iam:*",
    "iam:Create*",
    "iam:Delete*",
    "iam:Put*",
    "iam:Attach*",
    "iam:Update*",
    "sts:AssumeRole",
}

_SENSITIVE_SERVICE_WILDCARDS = {
    "iam:*",
    "kms:*",
    "organizations:*",
    "s3:*",
    "secretsmanager:*",
    "ssm:*",
    "sts:*",
}

_CHECK_WEIGHTS = {
    "AWS-IAM-001": 40,
    "AWS-IAM-002": 50,
    "AWS-IAM-003": 25,
    "AWS-IAM-004": 50,
    "AWS-IAM-005": 35,
    "AWS-IAM-006": 30,
}


class AWSIAMAnalyzer:
    """Analyze offline AWS IAM snapshots."""

    def __init__(self, max_access_key_age_days: int = 90) -> None:
        self._max_access_key_age_days = max_access_key_age_days

    def analyze(self, snapshots: list[AWSIAMSnapshot]) -> AWSIAMReport:
        findings: list[AWSIAMFinding] = []
        for snapshot in snapshots:
            findings.extend(self._check_root_mfa(snapshot))
            findings.extend(self._check_access_key_age(snapshot))
            findings.extend(self._check_broad_policies(snapshot))
        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return AWSIAMReport(findings=findings, snapshots_analyzed=len(snapshots), risk_score=risk_score)

    def _check_root_mfa(self, snapshot: AWSIAMSnapshot) -> list[AWSIAMFinding]:
        if snapshot.root_mfa_enabled is True:
            return []
        severity = (
            AWSIAMSeverity.CRITICAL
            if snapshot.root_mfa_enabled is False
            else AWSIAMSeverity.MEDIUM
        )
        title = (
            "Root account MFA is not enabled"
            if snapshot.root_mfa_enabled is False
            else "Root account MFA is not confirmed"
        )
        detail = (
            "The IAM account summary indicates the root account has no MFA device."
            if snapshot.root_mfa_enabled is False
            else "The snapshot did not include root MFA evidence from AccountMFAEnabled."
        )
        return [
            AWSIAMFinding(
                check_id="AWS-IAM-001",
                severity=severity,
                resource=f"account/{snapshot.account_id}/root",
                title=title,
                detail=detail,
                recommendation=(
                    "Enable hardware or virtual MFA on the AWS root user and include "
                    "AccountMFAEnabled from `aws iam get-account-summary` in evidence exports."
                ),
            )
        ]

    def _check_access_key_age(self, snapshot: AWSIAMSnapshot) -> list[AWSIAMFinding]:
        findings: list[AWSIAMFinding] = []
        for key in snapshot.access_keys:
            if not key.active:
                continue
            if key.user.lower() in {"<root>", "root"}:
                findings.append(
                    AWSIAMFinding(
                        check_id="AWS-IAM-002",
                        severity=AWSIAMSeverity.CRITICAL,
                        resource=f"account/{snapshot.account_id}/root/access-key/{key.key_id}",
                        title="Active root access key detected",
                        detail=(
                            f"Root access key {key.key_id} is active in account "
                            f"{snapshot.account_id}. Root access keys bypass normal "
                            "least-privilege controls and should not be used by workloads."
                        ),
                        recommendation=(
                            "Delete root access keys and migrate automation to scoped IAM "
                            "roles or least-privilege IAM users."
                        ),
                    )
                )
                continue
            if key.age_days is None:
                continue
            if key.age_days <= self._max_access_key_age_days:
                continue
            findings.append(
                AWSIAMFinding(
                    check_id="AWS-IAM-003",
                    severity=AWSIAMSeverity.HIGH,
                    resource=f"user/{key.user}/access-key/{key.key_id}",
                    title="Active IAM access key exceeds age threshold",
                    detail=(
                        f"Access key {key.key_id} for user {key.user} is active and "
                        f"{key.age_days} days old, exceeding the "
                        f"{self._max_access_key_age_days}-day threshold."
                    ),
                    recommendation=(
                        "Rotate or delete stale IAM user access keys. Prefer short-lived "
                        "role credentials through AWS IAM Identity Center or STS."
                    ),
                )
            )
        return findings

    def _check_broad_policies(self, snapshot: AWSIAMSnapshot) -> list[AWSIAMFinding]:
        findings: list[AWSIAMFinding] = []
        for policy in snapshot.policies:
            for statement in policy.statements:
                if not _is_allow(statement.effect):
                    continue
                if not _is_global_resource(statement.resource):
                    continue
                if _has_passrole_wildcard(statement.action):
                    findings.append(
                        AWSIAMFinding(
                            check_id="AWS-IAM-006",
                            severity=AWSIAMSeverity.HIGH,
                            resource=f"policy/{policy.name}",
                            title="IAM policy allows PassRole on all resources",
                            detail=(
                                f"Policy {policy.name} allows iam:PassRole on "
                                f"{statement.resource}. PassRole should be constrained "
                                "to approved role ARNs and paired services."
                            ),
                            recommendation=(
                                "Scope iam:PassRole to specific role ARNs and add "
                                "iam:PassedToService conditions."
                            ),
                        )
                    )
                has_broad_action = _has_broad_action(statement.action)
                has_sensitive_wildcard = _has_sensitive_service_wildcard(statement.action)
                if not (has_broad_action or has_sensitive_wildcard) or statement.condition:
                    continue
                check_id = "AWS-IAM-004"
                severity = AWSIAMSeverity.CRITICAL
                title = "IAM policy grants broad privileges on all resources"
                recommendation = (
                    "Replace wildcard or IAM-administration actions with scoped "
                    "least-privilege actions, resource ARNs, and conditions."
                )
                if has_sensitive_wildcard and "*" not in statement.action:
                    check_id = "AWS-IAM-005"
                    severity = AWSIAMSeverity.HIGH
                    title = "IAM policy grants sensitive service wildcard permissions"
                    recommendation = (
                        "Limit sensitive service wildcards to required API calls and "
                        "resource ARNs."
                    )
                findings.append(
                    AWSIAMFinding(
                        check_id=check_id,
                        severity=severity,
                        resource=f"policy/{policy.name}",
                        title=title,
                        detail=(
                            f"Policy {policy.name} allows {statement.action} on "
                            f"{statement.resource} without a limiting condition."
                        ),
                        recommendation=recommendation,
                    )
                )
                break
        return findings


def load_aws_iam_snapshot_from_export(path: str) -> list[AWSIAMSnapshot]:
    """Load one or more AWS IAM snapshots from an offline JSON export."""
    import json
    from pathlib import Path

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [AWSIAMSnapshot.from_dict(item) for item in raw]
    if isinstance(raw, dict) and isinstance(raw.get("accounts"), list):
        return [AWSIAMSnapshot.from_dict(item) for item in raw["accounts"]]
    if isinstance(raw, dict):
        return [AWSIAMSnapshot.from_dict(raw)]
    raise ValueError("AWS IAM export must be a JSON object, list, or {\"accounts\": [...]} object.")


def _extract_root_mfa(data: dict[str, Any]) -> bool | None:
    explicit = data.get("root_mfa_enabled")
    if isinstance(explicit, bool):
        return explicit
    summary = data.get("account_summary") or data.get("summary") or {}
    summary_map = summary.get("SummaryMap", summary) if isinstance(summary, dict) else {}
    value = summary_map.get("AccountMFAEnabled") if isinstance(summary_map, dict) else None
    if value is None:
        return None
    return str(value).lower() in {"1", "true", "yes"}


def _extract_access_keys(data: dict[str, Any]) -> list[AWSAccessKey]:
    raw_users = data.get("users") or data.get("credential_report") or []
    keys: list[AWSAccessKey] = []
    root = data.get("root_account") or data.get("root") or {}
    if isinstance(root, dict):
        for key in root.get("access_keys", []) or []:
            if not isinstance(key, dict):
                continue
            keys.append(
                AWSAccessKey(
                    user="<root>",
                    key_id=str(key.get("key_id") or key.get("access_key_id") or key.get("AccessKeyId") or "unknown"),
                    active=_truthy(key.get("active", key.get("status", key.get("Status", "Active")))) is not False,
                    age_days=_optional_int(key.get("age_days") or key.get("created_at_days_ago") or key.get("AgeDays")),
                    last_used_days_ago=_optional_int(key.get("last_used_days_ago")),
                )
            )
    for user in raw_users:
        if not isinstance(user, dict):
            continue
        user_name = str(user.get("user") or user.get("user_name") or user.get("UserName") or "unknown")
        for key_name in ("access_key_1", "access_key_2"):
            active = _truthy(user.get(f"{key_name}_active"))
            if active is None:
                continue
            keys.append(
                AWSAccessKey(
                    user=user_name,
                    key_id=str(user.get(f"{key_name}_id") or key_name),
                    active=active,
                    age_days=_optional_int(user.get(f"{key_name}_age_days")),
                    last_used_days_ago=_optional_int(user.get(f"{key_name}_last_used_days_ago")),
                )
            )
        for key in user.get("access_keys", []) or []:
            if not isinstance(key, dict):
                continue
            keys.append(
                AWSAccessKey(
                    user=user_name,
                    key_id=str(key.get("key_id") or key.get("access_key_id") or key.get("AccessKeyId") or "unknown"),
                    active=_truthy(key.get("active", key.get("status", key.get("Status", "Active")))) is not False,
                    age_days=_optional_int(key.get("age_days") or key.get("created_at_days_ago") or key.get("AgeDays")),
                    last_used_days_ago=_optional_int(key.get("last_used_days_ago")),
                )
            )
    for key in data.get("access_keys", []) or []:
        if not isinstance(key, dict):
            continue
        keys.append(
            AWSAccessKey(
                user=str(key.get("user") or key.get("user_name") or "unknown"),
                key_id=str(key.get("key_id") or key.get("access_key_id") or key.get("AccessKeyId") or "unknown"),
                active=_truthy(key.get("active", key.get("status", key.get("Status", "Active")))) is not False,
                age_days=_optional_int(key.get("age_days") or key.get("created_at_days_ago") or key.get("AgeDays")),
                last_used_days_ago=_optional_int(key.get("last_used_days_ago")),
            )
        )
    return keys


def _extract_policies(data: dict[str, Any]) -> list[AWSPolicyDocument]:
    raw_policies = data.get("policies", [])
    policies: list[AWSPolicyDocument] = []
    for index, raw_policy in enumerate(raw_policies, start=1):
        if not isinstance(raw_policy, dict):
            continue
        name = str(raw_policy.get("name") or raw_policy.get("PolicyName") or f"policy-{index}")
        document = raw_policy.get("document") or raw_policy.get("PolicyDocument") or raw_policy
        raw_statements = document.get("Statement", []) if isinstance(document, dict) else []
        if isinstance(raw_statements, dict):
            raw_statements = [raw_statements]
        statements = [
            AWSPolicyStatement(
                effect=str(statement.get("Effect", "")),
                action=_as_str_list(statement.get("Action", [])),
                resource=_as_str_list(statement.get("Resource", [])),
                condition=dict(statement.get("Condition") or {}),
            )
            for statement in raw_statements
            if isinstance(statement, dict)
        ]
        policies.append(AWSPolicyDocument(name=name, statements=statements))
    return policies


def _is_allow(effect: str) -> bool:
    return effect.lower() == "allow"


def _is_global_resource(resources: list[str]) -> bool:
    return "*" in resources or not resources


def _has_broad_action(actions: list[str]) -> bool:
    for action in actions:
        normalized = action.lower()
        if normalized == "iam:passrole":
            continue
        for pattern in _ADMIN_ACTION_PATTERNS:
            if pattern == "*" and normalized != "*":
                continue
            if fnmatch.fnmatchcase(normalized, pattern.lower()):
                return True
    return False


def _has_sensitive_service_wildcard(actions: list[str]) -> bool:
    return any(action.lower() in _SENSITIVE_SERVICE_WILDCARDS for action in actions)


def _has_passrole_wildcard(actions: list[str]) -> bool:
    return any(action.lower() == "iam:passrole" for action in actions)


def _truthy(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "yes", "1", "active"}:
        return True
    if normalized in {"false", "no", "0", "inactive"}:
        return False
    return None


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []
