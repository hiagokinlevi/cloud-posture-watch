"""
Azure AD / Entra ID Security Analyzer
========================================
Analyzes Azure Active Directory tenant configurations for identity
security risks: disabled MFA, legacy authentication, guest user excess,
privileged role assignments without PIM, and Conditional Access gaps.

Operates on structured AAD configuration dicts.
No live Azure API calls required.

Check IDs
----------
AAD-001   MFA not enforced for privileged user (Global Admin/etc.)
AAD-002   Legacy authentication protocols not blocked (basic auth)
AAD-003   Guest user with privileged role assignment
AAD-004   Privileged role assignment outside Privileged Identity Management (PIM)
AAD-005   No Conditional Access policy requiring MFA for all users
AAD-006   Service principal with client secret older than max_secret_age_days
AAD-007   External user count exceeds tenant guest ratio threshold

Usage::

    from analyzers.azure_ad_analyzer import AzureADAnalyzer, AADTenantConfig

    config = AADTenantConfig(
        tenant_id="abc-123",
        users=[{"id": "u1", "mfa_enabled": False, "roles": ["GlobalAdministrator"]}],
        conditional_access_policies=[],
    )
    analyzer = AzureADAnalyzer()
    report = analyzer.analyze(config)
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

class AADSeverity(str, Enum):
    """Severity levels for Azure AD findings."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

@dataclass
class AADTenantConfig:
    """
    Snapshot of an Azure AD tenant configuration.

    Attributes:
        tenant_id:                   Azure AD tenant identifier (GUID or name).
        users:                       List of user dicts.  Each user dict contains:
                                     ``id`` (str), ``display_name`` (str),
                                     ``mfa_enabled`` (bool), ``roles`` (List[str]),
                                     ``is_guest`` (bool, default False),
                                     ``is_service_principal`` (bool, default False).
        service_principals:          List of service principal dicts.  Each SP dict
                                     contains: ``id`` (str), ``name`` (str),
                                     ``client_secrets`` (List[Dict]) where each secret
                                     dict has ``"age_days"`` (int).
        conditional_access_policies: List of CA policy dicts.  Each dict contains:
                                     ``name`` (str), ``state`` (str: "enabled" or
                                     "disabled"), ``conditions`` (Dict),
                                     ``grant_controls`` (Dict).
        legacy_auth_blocked:         Whether legacy/basic authentication protocols
                                     (IMAP, POP3, SMTP AUTH, etc.) are blocked
                                     tenant-wide.  Defaults to False.
        pim_enabled:                 Whether Privileged Identity Management is
                                     enabled for the tenant.  Defaults to False.
        total_users:                 Total number of user objects in the tenant,
                                     used for guest ratio calculation.  Defaults to 0.
        total_guests:                Total number of guest (B2B) user objects.
                                     Defaults to 0.
    """
    tenant_id:                   str
    users:                       List[Dict] = field(default_factory=list)
    service_principals:          List[Dict] = field(default_factory=list)
    conditional_access_policies: List[Dict] = field(default_factory=list)
    legacy_auth_blocked:         bool       = False
    pim_enabled:                 bool       = False
    total_users:                 int        = 0
    total_guests:                int        = 0


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class AADFinding:
    """
    A single Azure AD security finding.

    Attributes:
        check_id:    AAD-* identifier.
        severity:    Severity level.
        tenant_id:   Tenant the finding applies to.
        subject:     User display name, SP name, or "tenant" for tenant-wide checks.
        title:       Short human-readable description.
        detail:      Extended explanation.
        remediation: Recommended remediation step.
    """
    check_id:    str
    severity:    AADSeverity
    tenant_id:   str
    subject:     str
    title:       str
    detail:      str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding to a plain dict (suitable for JSON output)."""
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "tenant_id":   self.tenant_id,
            "subject":     self.subject,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """One-line summary string."""
        return (
            f"[{self.check_id}] {self.severity.value}: {self.title} "
            f"(tenant={self.tenant_id}, subject={self.subject})"
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class AADReport:
    """
    Aggregated result of analyzing one AAD tenant configuration.

    Attributes:
        findings:          All findings from the analysis.
        risk_score:        0-100 aggregate risk score.
        tenant_id:         Tenant that was analyzed.
        policies_analyzed: Number of Conditional Access policies examined.
        generated_at:      Unix timestamp of report creation.
    """
    findings:          List[AADFinding] = field(default_factory=list)
    risk_score:        int               = 0
    tenant_id:         str               = ""
    policies_analyzed: int               = 0
    generated_at:      float             = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        """Total number of findings in the report."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[AADFinding]:
        """All CRITICAL-severity findings."""
        return [f for f in self.findings if f.severity == AADSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[AADFinding]:
        """All HIGH-severity findings."""
        return [f for f in self.findings if f.severity == AADSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[AADFinding]:
        """Return all findings matching the given check ID."""
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_subject(self, subject: str) -> List[AADFinding]:
        """Return all findings for the given subject (user name, SP name, or 'tenant')."""
        return [f for f in self.findings if f.subject == subject]

    def summary(self) -> str:
        """Short human-readable summary of the report."""
        return (
            f"AAD Report [{self.tenant_id}]: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"critical={len(self.critical_findings)}, "
            f"high={len(self.high_findings)}, "
            f"policies_analyzed={self.policies_analyzed}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full report to a plain dict."""
        return {
            "tenant_id":         self.tenant_id,
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

# Privileged Azure AD / Entra ID roles that receive elevated scrutiny.
_PRIVILEGED_ROLES: frozenset = frozenset({
    "globaladministrator",
    "privilegedidentityadministrator",
    "securityadministrator",
    "useraccessadministrator",
    "complianceadministrator",
    "exchangeadministrator",
    "sharepointadministrator",
    "applicationadministrator",
    "cloudapplicationadministrator",
    "authenticationadministrator",
})

# Per-check weights used to compute the aggregate risk score (capped at 100).
_CHECK_WEIGHTS: Dict[str, int] = {
    "AAD-001": 50,
    "AAD-002": 45,
    "AAD-003": 40,
    "AAD-004": 35,
    "AAD-005": 30,
    "AAD-006": 25,
    "AAD-007": 15,
}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AzureADAnalyzer:
    """
    Analyze an Azure AD tenant configuration for identity security risks.

    Args:
        max_secret_age_days: Maximum acceptable client secret age in days (default 365).
                             Service principal secrets older than this trigger AAD-006.
        max_guest_ratio:     Maximum acceptable ratio of guest users to total users
                             (default 0.20).  Exceeding this triggers AAD-007.
    """

    def __init__(
        self,
        max_secret_age_days: int   = 365,
        max_guest_ratio:     float = 0.20,
    ) -> None:
        self._max_secret_age_days = max_secret_age_days
        self._max_guest_ratio     = max_guest_ratio

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, config: AADTenantConfig) -> AADReport:
        """
        Analyze an AADTenantConfig and return a consolidated report.

        Args:
            config: Tenant configuration snapshot to evaluate.

        Returns:
            AADReport containing all findings and an aggregate risk score.
        """
        all_findings: List[AADFinding] = []

        # Per-user checks.
        for user in config.users:
            all_findings.extend(self._check_001_mfa_privileged(config.tenant_id, user))
            all_findings.extend(self._check_003_guest_privileged(config.tenant_id, user))

        # Tenant-wide single-finding checks.
        all_findings.extend(self._check_002_legacy_auth(config))
        all_findings.extend(self._check_004_pim_missing(config))
        all_findings.extend(self._check_005_ca_mfa_gap(config))
        all_findings.extend(self._check_007_guest_ratio(config))

        # Per-service-principal checks.
        for sp in config.service_principals:
            all_findings.extend(self._check_006_sp_secret_age(config.tenant_id, sp))

        # Risk score: sum weights of unique fired check IDs, capped at 100.
        fired_checks = {f.check_id for f in all_findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired_checks))

        return AADReport(
            findings=all_findings,
            risk_score=risk_score,
            tenant_id=config.tenant_id,
            policies_analyzed=len(config.conditional_access_policies),
        )

    # ------------------------------------------------------------------
    # Per-user checks
    # ------------------------------------------------------------------

    def _check_001_mfa_privileged(
        self, tenant_id: str, user: Dict[str, Any]
    ) -> List[AADFinding]:
        """
        AAD-001: Flag privileged users that do not have MFA enabled.

        A user is considered privileged when any entry in their ``roles`` list
        matches a role in ``_PRIVILEGED_ROLES`` (case-insensitive).  Missing MFA
        on such accounts is the single highest-impact identity risk in AAD.
        """
        # Service principals are not interactive accounts; skip them here.
        if user.get("is_service_principal", False):
            return []

        roles: List[str] = user.get("roles", [])
        is_privileged = any(r.lower() in _PRIVILEGED_ROLES for r in roles)
        if not is_privileged:
            return []

        # Only fire when MFA is explicitly disabled.
        if user.get("mfa_enabled", True):
            return []

        display_name = user.get("display_name", user.get("id", "<unknown>"))
        privileged_roles = [r for r in roles if r.lower() in _PRIVILEGED_ROLES]
        return [AADFinding(
            check_id="AAD-001",
            severity=AADSeverity.CRITICAL,
            tenant_id=tenant_id,
            subject=display_name,
            title=f"Privileged user '{display_name}' does not have MFA enabled",
            detail=(
                f"User '{display_name}' holds privileged role(s) "
                f"{privileged_roles} but has MFA disabled. "
                f"An account takeover on this identity can grant full tenant control."
            ),
            remediation=(
                "Enable per-user MFA or enforce MFA via a Conditional Access policy "
                "targeting privileged roles. Consider requiring phishing-resistant "
                "authentication (FIDO2 / Windows Hello) for Global Administrators."
            ),
        )]

    def _check_003_guest_privileged(
        self, tenant_id: str, user: Dict[str, Any]
    ) -> List[AADFinding]:
        """
        AAD-003: Flag guest (B2B) users that hold privileged role assignments.

        Guest accounts originate from external tenants and have a weaker identity
        assurance level.  Granting them privileged roles violates least-privilege
        and the principle of separation of duties.
        """
        if not user.get("is_guest", False):
            return []

        roles: List[str] = user.get("roles", [])
        privileged_roles = [r for r in roles if r.lower() in _PRIVILEGED_ROLES]
        if not privileged_roles:
            return []

        display_name = user.get("display_name", user.get("id", "<unknown>"))
        return [AADFinding(
            check_id="AAD-003",
            severity=AADSeverity.CRITICAL,
            tenant_id=tenant_id,
            subject=display_name,
            title=(
                f"Guest user '{display_name}' has privileged role assignment"
            ),
            detail=(
                f"External guest user '{display_name}' holds the privileged "
                f"role(s) {privileged_roles}. Guest accounts are managed by an "
                f"external identity provider and should never hold tenant-wide "
                f"administrative privileges."
            ),
            remediation=(
                "Remove privileged role assignments from guest accounts immediately. "
                "If cross-tenant administration is required, use Azure Lighthouse or "
                "negotiate a dedicated internal account for the external collaborator."
            ),
        )]

    # ------------------------------------------------------------------
    # Tenant-wide checks (at most one finding each)
    # ------------------------------------------------------------------

    def _check_002_legacy_auth(self, config: AADTenantConfig) -> List[AADFinding]:
        """
        AAD-002: Flag tenants that have not blocked legacy authentication.

        Legacy protocols (Basic Auth / SMTP AUTH / POP3 / IMAP / MAPI) do not
        support modern MFA challenges.  Attackers use credential-stuffing and
        password-spray attacks against these endpoints to bypass MFA entirely.
        """
        if config.legacy_auth_blocked:
            return []

        return [AADFinding(
            check_id="AAD-002",
            severity=AADSeverity.HIGH,
            tenant_id=config.tenant_id,
            subject="tenant",
            title="Legacy authentication protocols are not blocked",
            detail=(
                f"Tenant '{config.tenant_id}' does not have legacy authentication "
                f"(Basic Auth / SMTP AUTH / POP3 / IMAP) blocked.  These protocols "
                f"cannot honour MFA challenges and are a primary password-spray "
                f"attack vector against Microsoft 365 environments."
            ),
            remediation=(
                "Create a Conditional Access policy that blocks legacy authentication "
                "clients (condition: client apps = Exchange ActiveSync + Other clients). "
                "Alternatively, enable the 'Block legacy authentication' Security Default. "
                "Monitor Sign-In logs for legacy auth attempts before enforcing."
            ),
        )]

    def _check_004_pim_missing(self, config: AADTenantConfig) -> List[AADFinding]:
        """
        AAD-004: Flag tenants where PIM is absent but privileged roles are assigned.

        Without PIM, privileged role assignments are permanent (standing access).
        PIM enforces just-in-time activation, approval workflows, and access reviews,
        dramatically reducing the blast radius of a compromised privileged account.
        """
        if config.pim_enabled:
            return []

        # Only raise this finding if there are actually privileged role holders.
        has_privileged_users = any(
            any(r.lower() in _PRIVILEGED_ROLES for r in u.get("roles", []))
            for u in config.users
        )
        if not has_privileged_users:
            return []

        return [AADFinding(
            check_id="AAD-004",
            severity=AADSeverity.HIGH,
            tenant_id=config.tenant_id,
            subject="tenant",
            title="Privileged roles assigned without Privileged Identity Management (PIM)",
            detail=(
                f"Tenant '{config.tenant_id}' has users with privileged role "
                f"assignments but PIM is not enabled.  Standing access to privileged "
                f"roles increases the attack surface because accounts are persistently "
                f"elevated, even when those privileges are not actively needed."
            ),
            remediation=(
                "Enable Azure AD Privileged Identity Management (P2 license required). "
                "Convert all permanent privileged role assignments to PIM-eligible "
                "assignments.  Configure activation time limits, MFA on activation, "
                "and periodic access reviews for all privileged roles."
            ),
        )]

    def _check_005_ca_mfa_gap(self, config: AADTenantConfig) -> List[AADFinding]:
        """
        AAD-005: Flag tenants with no enabled Conditional Access policy that enforces MFA.

        MFA is the single most effective control against credential-based attacks.
        At least one CA policy should target all users (or all cloud apps) and require
        MFA as a grant control.
        """
        for policy in config.conditional_access_policies:
            # Only examine enabled policies.
            if str(policy.get("state", "")).lower() != "enabled":
                continue

            grant_controls = policy.get("grant_controls", {})
            # Check for the string "mfa" anywhere in the grant_controls representation
            # (handles nested structures: {"operator": "OR", "builtInControls": ["mfa"]}).
            if "mfa" in str(grant_controls).lower():
                return []  # At least one enabled policy enforces MFA — no finding.

        return [AADFinding(
            check_id="AAD-005",
            severity=AADSeverity.MEDIUM,
            tenant_id=config.tenant_id,
            subject="tenant",
            title="No Conditional Access policy enforcing MFA for all users",
            detail=(
                f"Tenant '{config.tenant_id}' has no enabled Conditional Access "
                f"policy whose grant controls require MFA.  Without a CA-enforced "
                f"MFA baseline, users can authenticate with only a password, making "
                f"the tenant vulnerable to credential-stuffing and phishing attacks."
            ),
            remediation=(
                "Create a Conditional Access policy with: Assignments → All users, "
                "Cloud apps → All cloud apps, Grant → Require multi-factor "
                "authentication.  Use report-only mode initially to assess impact, "
                "then switch to enabled after reviewing the sign-in report."
            ),
        )]

    def _check_007_guest_ratio(self, config: AADTenantConfig) -> List[AADFinding]:
        """
        AAD-007: Flag tenants where guest users exceed the configured ratio threshold.

        An unusually high proportion of external guest accounts may indicate
        over-permissive B2B collaboration settings or unreviewed stale guest access.
        """
        if config.total_users <= 0:
            return []  # Cannot compute a ratio without total_users.

        ratio = config.total_guests / config.total_users
        if ratio <= self._max_guest_ratio:
            return []

        ratio_pct    = round(ratio * 100, 1)
        max_pct      = round(self._max_guest_ratio * 100, 1)
        return [AADFinding(
            check_id="AAD-007",
            severity=AADSeverity.LOW,
            tenant_id=config.tenant_id,
            subject="tenant",
            title=(
                f"Guest user ratio {ratio_pct}% exceeds threshold {max_pct}%"
            ),
            detail=(
                f"Tenant '{config.tenant_id}' has {config.total_guests} guest users "
                f"out of {config.total_users} total users ({ratio_pct}%), exceeding "
                f"the configured maximum guest ratio of {max_pct}%.  A high guest "
                f"count may indicate stale B2B invitations, shadow IT collaboration, "
                f"or overly permissive external sharing policies."
            ),
            remediation=(
                "Run an Azure AD Access Review targeting guest users to identify and "
                "remove stale or unneeded external accounts.  Tighten B2B collaboration "
                "settings to require admin approval for new guest invitations.  "
                "Consider setting a Guest User Access Restriction policy."
            ),
        )]

    # ------------------------------------------------------------------
    # Per-service-principal checks
    # ------------------------------------------------------------------

    def _check_006_sp_secret_age(
        self, tenant_id: str, sp: Dict[str, Any]
    ) -> List[AADFinding]:
        """
        AAD-006: Flag service principals with client secrets older than max_secret_age_days.

        Long-lived client secrets are a common source of credential leakage.
        Rotating secrets regularly limits the exposure window if a secret is
        exfiltrated through code, logs, or configuration drift.
        """
        findings: List[AADFinding] = []
        sp_name = sp.get("name", sp.get("id", "<unknown>"))

        for secret in sp.get("client_secrets", []):
            age: Any = secret.get("age_days")
            if not isinstance(age, int):
                continue  # Skip secrets without age metadata.
            if age <= self._max_secret_age_days:
                continue  # Within acceptable age — no finding.

            findings.append(AADFinding(
                check_id="AAD-006",
                severity=AADSeverity.HIGH,
                tenant_id=tenant_id,
                subject=sp_name,
                title=(
                    f"Service principal '{sp_name}' has a client secret "
                    f"{age} days old (limit: {self._max_secret_age_days} days)"
                ),
                detail=(
                    f"A client secret for service principal '{sp_name}' in tenant "
                    f"'{tenant_id}' is {age} days old, exceeding the configured "
                    f"maximum of {self._max_secret_age_days} days.  Long-lived "
                    f"secrets increase the blast radius of a credential leak and "
                    f"complicate incident response."
                ),
                remediation=(
                    "Rotate the stale client secret immediately and update the "
                    "consuming application's configuration.  Prefer managed identities "
                    "or certificate-based authentication to eliminate long-lived secrets "
                    "entirely.  Automate secret rotation using Azure Key Vault references."
                ),
            ))

        return findings
