"""
GCP IAM Security Analyzer
============================
Analyzes GCP IAM policy bindings for security risks: overly broad roles,
primitive roles (Owner/Editor/Viewer), service account key age, external
members in sensitive bindings, and allUsers/allAuthenticatedUsers grants.

Operates on structured IAM policy dicts (GCP IAM policy JSON format).
No live GCP API calls required.

Check IDs
----------
GCP-IAM-001   Primitive role granted (roles/owner, roles/editor, roles/viewer)
GCP-IAM-002   allUsers or allAuthenticatedUsers granted any role
GCP-IAM-003   Service account has Owner or Editor role
GCP-IAM-004   External member (non-org domain) in sensitive role binding
GCP-IAM-005   Default service account used (Compute/AppEngine default SA)
GCP-IAM-006   Service account key older than max_key_age_days (default 90)
GCP-IAM-007   Overly broad role: roles/iam.securityAdmin or roles/iam.admin

Usage::

    from analyzers.gcp_iam_analyzer import GCPIAMAnalyzer, IAMPolicy

    policy = IAMPolicy(
        resource="projects/my-project",
        bindings=[
            {"role": "roles/owner", "members": ["user:admin@example.com"]},
            {"role": "roles/storage.admin", "members": ["allUsers"]},
        ],
    )
    analyzer = GCPIAMAnalyzer(org_domains=["example.com"])
    report = analyzer.analyze([policy])
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class GCPIAMSeverity(str, Enum):
    """Severity levels for GCP IAM findings."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

@dataclass
class IAMBinding:
    """
    A single GCP IAM policy binding (role → members).

    Attributes:
        role:    Full role identifier, e.g. "roles/owner".
        members: List of member identifiers, e.g. ["user:a@b.com", "allUsers"].
    """
    role:    str
    members: List[str] = field(default_factory=list)


@dataclass
class IAMPolicy:
    """
    GCP IAM policy snapshot for one resource.

    Attributes:
        resource:             Resource identifier (e.g. "projects/my-project").
        bindings:             List of IAMBinding objects.
        service_account_keys: List of SA key metadata dicts.  Each dict may
                              contain ``"created_at_days_ago"`` (int) and
                              ``"key_id"`` (str) for GCP-IAM-006 checks.
    """
    resource:             str
    bindings:             List[IAMBinding] = field(default_factory=list)
    service_account_keys: List[Dict]       = field(default_factory=list)

    @classmethod
    def from_dict(cls, resource: str, policy_dict: Dict) -> "IAMPolicy":
        """
        Construct an IAMPolicy from a raw GCP IAM policy dict.

        The ``policy_dict`` is expected to follow the GCP IAM API shape::

            {
                "bindings": [
                    {"role": "roles/owner", "members": ["user:a@example.com"]},
                    ...
                ]
            }

        ``service_account_keys`` can be passed as a top-level key in
        ``policy_dict`` for convenience; it defaults to an empty list.

        Args:
            resource:    Resource identifier string.
            policy_dict: Raw GCP IAM policy document (parsed JSON dict).

        Returns:
            A fully constructed IAMPolicy instance.
        """
        raw_bindings = policy_dict.get("bindings", [])
        bindings: List[IAMBinding] = [
            IAMBinding(
                role=b["role"],
                members=list(b.get("members", [])),
            )
            for b in raw_bindings
        ]
        sa_keys: List[Dict] = list(policy_dict.get("service_account_keys", []))
        return cls(resource=resource, bindings=bindings, service_account_keys=sa_keys)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class GCPIAMFinding:
    """
    A single GCP IAM security finding.

    Attributes:
        check_id:    GCP-IAM-* identifier.
        severity:    Severity level.
        resource:    Resource the finding applies to.
        role:        Role involved in the finding.
        member:      Specific member involved (empty string if N/A).
        title:       Short human-readable description.
        detail:      Extended explanation.
        remediation: Recommended remediation step.
    """
    check_id:    str
    severity:    GCPIAMSeverity
    resource:    str
    role:        str
    member:      str
    title:       str
    detail:      str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding to a plain dict (suitable for JSON output)."""
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "resource":    self.resource,
            "role":        self.role,
            "member":      self.member,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """One-line summary string."""
        return (
            f"[{self.check_id}] {self.severity.value}: {self.title} "
            f"(resource={self.resource}, role={self.role}, member={self.member})"
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class GCPIAMReport:
    """
    Aggregated result of analyzing one or more IAM policies.

    Attributes:
        findings:          All findings across analyzed policies.
        risk_score:        0–100 aggregate risk score.
        policies_analyzed: Number of IAMPolicy objects examined.
        generated_at:      Unix timestamp of report creation.
    """
    findings:          List[GCPIAMFinding] = field(default_factory=list)
    risk_score:        int                  = 0
    policies_analyzed: int                  = 0
    generated_at:      float                = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        """Total number of findings in the report."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[GCPIAMFinding]:
        """All CRITICAL-severity findings."""
        return [f for f in self.findings if f.severity == GCPIAMSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[GCPIAMFinding]:
        """All HIGH-severity findings."""
        return [f for f in self.findings if f.severity == GCPIAMSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[GCPIAMFinding]:
        """Return all findings matching the given check ID."""
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_resource(self, resource: str) -> List[GCPIAMFinding]:
        """Return all findings for the given resource identifier."""
        return [f for f in self.findings if f.resource == resource]

    def summary(self) -> str:
        """Short human-readable summary of the report."""
        return (
            f"GCP IAM Report: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"critical={len(self.critical_findings)}, "
            f"high={len(self.high_findings)}, "
            f"policies_analyzed={self.policies_analyzed}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full report to a plain dict."""
        return {
            "total_findings":    self.total_findings,
            "risk_score":        self.risk_score,
            "policies_analyzed": self.policies_analyzed,
            "critical":          len(self.critical_findings),
            "high":              len(self.high_findings),
            "generated_at":      self.generated_at,
            "findings":          [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# GCP primitive roles — broad by definition and discouraged in production.
_PRIMITIVE_ROLES: frozenset = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",
})

# Roles considered sensitive for external-member checks.
_SENSITIVE_ROLES: frozenset = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/iam.admin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
})

# Special public member identifiers used by GCP.
_PUBLIC_MEMBERS: frozenset = frozenset({
    "allUsers",
    "allAuthenticatedUsers",
})

# Per-check weights used to compute the aggregate risk score (capped at 100).
_CHECK_WEIGHTS: Dict[str, int] = {
    "GCP-IAM-001": 25,
    "GCP-IAM-002": 50,
    "GCP-IAM-003": 40,
    "GCP-IAM-004": 30,
    "GCP-IAM-005": 20,
    "GCP-IAM-006": 25,
    "GCP-IAM-007": 35,
}


def _is_default_service_account(member: str) -> bool:
    """
    Return True if *member* matches a GCP default service account pattern.

    Detects:
    - Compute Engine default SA: ``<project-number>-compute@developer.gserviceaccount.com``
    - App Engine default SA:     ``<project-id>@appspot.gserviceaccount.com``
    """
    # Strip the "serviceAccount:" prefix before checking suffixes.
    sa_id = member[len("serviceAccount:"):] if member.startswith("serviceAccount:") else member
    return (
        sa_id.endswith("-compute@developer.gserviceaccount.com")
        or sa_id.endswith(".appspot.gserviceaccount.com")
    )


def _extract_domain(member: str) -> Optional[str]:
    """
    Extract the email domain from a ``user:email`` member string.

    Returns None if the member does not follow the ``user:local@domain`` shape.
    """
    if not member.startswith("user:"):
        return None
    email = member[len("user:"):]
    if "@" not in email:
        return None
    return email.split("@", 1)[1].lower()


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class GCPIAMAnalyzer:
    """
    Analyze one or more GCP IAM policies for security risks.

    Args:
        org_domains:           Trusted organization domains (e.g. ["example.com"]).
                               When provided and ``check_external_members`` is True,
                               user members whose domain is not in this list and who
                               hold sensitive roles are flagged as GCP-IAM-004.
        max_key_age_days:      Maximum acceptable service account key age in days
                               (default 90). Keys older than this trigger GCP-IAM-006.
        check_external_members: Enable/disable the external-member check (GCP-IAM-004).
                               Defaults to True.
    """

    def __init__(
        self,
        org_domains: Optional[List[str]] = None,
        max_key_age_days: int = 90,
        check_external_members: bool = True,
    ) -> None:
        # Normalize domains to lowercase for reliable comparison.
        self._org_domains: Optional[List[str]] = (
            [d.lower() for d in org_domains] if org_domains else None
        )
        self._max_key_age_days    = max_key_age_days
        self._check_external      = check_external_members

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, policies: List[IAMPolicy]) -> GCPIAMReport:
        """
        Analyze a list of IAMPolicy objects and return a consolidated report.

        Args:
            policies: IAMPolicy objects to evaluate.

        Returns:
            GCPIAMReport containing all findings and an aggregate risk score.
        """
        all_findings: List[GCPIAMFinding] = []

        for policy in policies:
            # Normalize bindings: accept both IAMBinding objects and raw dicts.
            bindings = self._normalize_bindings(policy.bindings)

            for binding in bindings:
                all_findings.extend(self._check_001_primitive_role(policy.resource, binding))
                all_findings.extend(self._check_002_public_member(policy.resource, binding))
                all_findings.extend(self._check_003_sa_privileged(policy.resource, binding))
                all_findings.extend(self._check_004_external_member(policy.resource, binding))
                all_findings.extend(self._check_005_default_sa(policy.resource, binding))
                all_findings.extend(self._check_007_broad_iam_role(policy.resource, binding))

            # Key-age check operates at the policy level (not per-binding).
            all_findings.extend(self._check_006_key_age(policy))

        # Risk score: sum weights of unique check IDs that fired, capped at 100.
        fired_checks = {f.check_id for f in all_findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired_checks))

        return GCPIAMReport(
            findings=all_findings,
            risk_score=risk_score,
            policies_analyzed=len(policies),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_bindings(
        bindings: List[Any],
    ) -> List[IAMBinding]:
        """
        Accept either IAMBinding instances or raw dicts and return IAMBinding list.
        This allows IAMPolicy.bindings to be populated from either source.
        """
        result: List[IAMBinding] = []
        for b in bindings:
            if isinstance(b, IAMBinding):
                result.append(b)
            elif isinstance(b, dict):
                result.append(IAMBinding(
                    role=b.get("role", ""),
                    members=list(b.get("members", [])),
                ))
        return result

    # ------------------------------------------------------------------
    # Per-binding checks
    # ------------------------------------------------------------------

    def _check_001_primitive_role(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-001: Flag every non-public member that holds a primitive role.

        Primitive roles (Owner / Editor / Viewer) grant project-wide permissions
        and should be replaced by predefined or custom roles.
        """
        findings: List[GCPIAMFinding] = []
        if binding.role not in _PRIMITIVE_ROLES:
            return findings

        for member in binding.members:
            # Public members are caught by GCP-IAM-002; skip them here.
            if member in _PUBLIC_MEMBERS:
                continue
            sev = (
                GCPIAMSeverity.CRITICAL
                if binding.role == "roles/owner"
                else GCPIAMSeverity.HIGH
            )
            findings.append(GCPIAMFinding(
                check_id="GCP-IAM-001",
                severity=sev,
                resource=resource,
                role=binding.role,
                member=member,
                title=f"Primitive role '{binding.role}' granted",
                detail=(
                    f"Member '{member}' has been granted the primitive role "
                    f"'{binding.role}' on resource '{resource}'. Primitive roles "
                    f"are overly broad and grant project-wide permissions."
                ),
                remediation=(
                    "Replace primitive roles with the most restrictive predefined "
                    "or custom role that satisfies the use case. "
                    "See https://cloud.google.com/iam/docs/understanding-roles."
                ),
            ))
        return findings

    def _check_002_public_member(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-002: Flag bindings that include allUsers or allAuthenticatedUsers.

        Any role granted to these special members makes the resource publicly
        accessible without authentication (allUsers) or to all Google accounts
        (allAuthenticatedUsers).
        """
        findings: List[GCPIAMFinding] = []
        for member in binding.members:
            if member not in _PUBLIC_MEMBERS:
                continue
            findings.append(GCPIAMFinding(
                check_id="GCP-IAM-002",
                severity=GCPIAMSeverity.CRITICAL,
                resource=resource,
                role=binding.role,
                member=member,
                title=f"Public member '{member}' granted role '{binding.role}'",
                detail=(
                    f"The role '{binding.role}' on resource '{resource}' has been "
                    f"granted to '{member}', making it accessible to the public "
                    f"internet with no authentication requirement."
                ),
                remediation=(
                    "Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM "
                    "bindings. Grant roles only to specific authenticated identities."
                ),
            ))
        return findings

    def _check_003_sa_privileged(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-003: Flag service accounts with Owner or Editor primitive roles.

        Service accounts with Owner or Editor roles can perform any operation on
        the project, creating a severe blast radius if compromised.
        """
        findings: List[GCPIAMFinding] = []
        if binding.role not in {"roles/owner", "roles/editor"}:
            return findings

        for member in binding.members:
            if not member.startswith("serviceAccount:"):
                continue
            findings.append(GCPIAMFinding(
                check_id="GCP-IAM-003",
                severity=GCPIAMSeverity.CRITICAL,
                resource=resource,
                role=binding.role,
                member=member,
                title=(
                    f"Service account granted privileged role '{binding.role}'"
                ),
                detail=(
                    f"Service account '{member}' has been granted '{binding.role}' "
                    f"on resource '{resource}'. A compromised service account with "
                    f"Owner or Editor access can exfiltrate data or escalate privilege "
                    f"across the entire project."
                ),
                remediation=(
                    "Revoke Owner/Editor from service accounts. Grant only the "
                    "minimum necessary predefined role. Consider Workload Identity "
                    "Federation for workload authentication."
                ),
            ))
        return findings

    def _check_004_external_member(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-004: Flag external (non-org-domain) users in sensitive bindings.

        Enabled only when ``check_external_members=True`` and ``org_domains`` is set.
        """
        findings: List[GCPIAMFinding] = []
        if not self._check_external:
            return findings
        if not self._org_domains:
            return findings
        if binding.role not in _SENSITIVE_ROLES:
            return findings

        for member in binding.members:
            domain = _extract_domain(member)
            if domain is None:
                continue  # not a user: member type
            if domain not in self._org_domains:
                findings.append(GCPIAMFinding(
                    check_id="GCP-IAM-004",
                    severity=GCPIAMSeverity.HIGH,
                    resource=resource,
                    role=binding.role,
                    member=member,
                    title=(
                        f"External user '{member}' in sensitive role '{binding.role}'"
                    ),
                    detail=(
                        f"User '{member}' (domain: '{domain}') is not a member of "
                        f"the trusted organization domains {self._org_domains} but "
                        f"holds the sensitive role '{binding.role}' on '{resource}'."
                    ),
                    remediation=(
                        "Remove external users from sensitive IAM bindings. "
                        "If cross-org collaboration is required, use VPC Service "
                        "Controls or restrict via Organization Policy constraints."
                    ),
                ))
        return findings

    def _check_005_default_sa(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-005: Flag use of Compute Engine or App Engine default service accounts.

        Default service accounts are automatically created and may have overly broad
        permissions (Editor role by default). Their use should be avoided in favor of
        purpose-built service accounts with minimal permissions.
        """
        findings: List[GCPIAMFinding] = []
        for member in binding.members:
            if not member.startswith("serviceAccount:"):
                continue
            if _is_default_service_account(member):
                findings.append(GCPIAMFinding(
                    check_id="GCP-IAM-005",
                    severity=GCPIAMSeverity.MEDIUM,
                    resource=resource,
                    role=binding.role,
                    member=member,
                    title=f"Default service account used: '{member}'",
                    detail=(
                        f"The default service account '{member}' appears in a binding "
                        f"for role '{binding.role}' on resource '{resource}'. Default "
                        f"service accounts are broadly scoped and their use is "
                        f"discouraged by GCP best practices."
                    ),
                    remediation=(
                        "Create dedicated, purpose-built service accounts with only "
                        "the permissions required. Disable automatic IAM grants on "
                        "default service accounts via Organization Policy."
                    ),
                ))
        return findings

    def _check_007_broad_iam_role(
        self, resource: str, binding: IAMBinding
    ) -> List[GCPIAMFinding]:
        """
        GCP-IAM-007: Flag use of roles/iam.admin or roles/iam.securityAdmin.

        These roles grant the ability to modify IAM policies or view sensitive
        security data, providing a strong privilege-escalation vector.
        """
        findings: List[GCPIAMFinding] = []
        if binding.role not in {"roles/iam.admin", "roles/iam.securityAdmin"}:
            return findings

        for member in binding.members:
            findings.append(GCPIAMFinding(
                check_id="GCP-IAM-007",
                severity=GCPIAMSeverity.HIGH,
                resource=resource,
                role=binding.role,
                member=member,
                title=f"Overly broad IAM role '{binding.role}' granted to '{member}'",
                detail=(
                    f"Member '{member}' has been granted '{binding.role}' on "
                    f"resource '{resource}'. This role provides broad IAM management "
                    f"capabilities and represents a significant privilege-escalation "
                    f"risk if the identity is compromised."
                ),
                remediation=(
                    "Restrict roles/iam.admin and roles/iam.securityAdmin to a small "
                    "set of break-glass accounts. Prefer granular alternatives such as "
                    "roles/iam.roleViewer or purpose-scoped custom roles."
                ),
            ))
        return findings

    # ------------------------------------------------------------------
    # Policy-level checks
    # ------------------------------------------------------------------

    def _check_006_key_age(self, policy: IAMPolicy) -> List[GCPIAMFinding]:
        """
        GCP-IAM-006: Flag service account keys older than max_key_age_days.

        Each key dict in ``policy.service_account_keys`` may contain:
        - ``"created_at_days_ago"`` (int): how many days ago the key was created.
        - ``"key_id"`` (str, optional): human-readable key identifier.
        - ``"service_account"`` (str, optional): owning SA email.
        """
        findings: List[GCPIAMFinding] = []
        for key in policy.service_account_keys:
            age: Any = key.get("created_at_days_ago")
            if not isinstance(age, int):
                continue  # skip keys without age metadata
            if age > self._max_key_age_days:
                key_id  = key.get("key_id", "<unknown>")
                sa_name = key.get("service_account", "<unknown>")
                findings.append(GCPIAMFinding(
                    check_id="GCP-IAM-006",
                    severity=GCPIAMSeverity.HIGH,
                    resource=policy.resource,
                    role="",
                    member=sa_name,
                    title=(
                        f"Service account key '{key_id}' is {age} days old "
                        f"(limit: {self._max_key_age_days} days)"
                    ),
                    detail=(
                        f"Key '{key_id}' for service account '{sa_name}' on "
                        f"resource '{policy.resource}' was created {age} days ago, "
                        f"exceeding the configured maximum of "
                        f"{self._max_key_age_days} days. Long-lived keys increase "
                        f"exposure in the event of credential leakage."
                    ),
                    remediation=(
                        "Rotate or delete the stale service account key immediately. "
                        "Prefer Workload Identity Federation to eliminate long-lived "
                        "keys entirely. Automate key rotation using Cloud Scheduler."
                    ),
                ))
        return findings
