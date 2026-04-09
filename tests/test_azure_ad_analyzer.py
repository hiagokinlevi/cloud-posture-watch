"""
Tests for analyzers/azure_ad_analyzer.py

Coverage targets
----------------
- AADFinding: to_dict(), summary()
- AADReport: properties, helpers, summary(), to_dict()
- AzureADAnalyzer.analyze(): all 7 check IDs fire and don't fire
- AAD-001: MFA not enforced for privileged user (CRITICAL)
- AAD-002: Legacy auth not blocked (HIGH); blocked = no finding
- AAD-003: Guest user with privileged role (CRITICAL)
- AAD-004: Privileged role without PIM (HIGH); PIM enabled = no finding
- AAD-005: CA policy MFA detection — enabled policy with mfa in grant_controls = no finding
- AAD-006: SP secret age boundary (exactly max = no fire, max+1 = fire)
- AAD-007: Guest ratio threshold (exactly at = no fire, over = fire)
- Multiple users generating multiple independent findings
- to_dict structure validation
- findings_for_subject filtering
- Clean config produces zero findings
- Risk score: unique check weights, not double-counted, capped at 100
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow running tests directly from the repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.azure_ad_analyzer import (
    AADFinding,
    AADReport,
    AADSeverity,
    AADTenantConfig,
    AzureADAnalyzer,
    _CHECK_WEIGHTS,
    _PRIVILEGED_ROLES,
)


# ===========================================================================
# Shared helpers
# ===========================================================================

TENANT_ID = "tenant-abc-123"


def _analyzer(**kwargs) -> AzureADAnalyzer:
    """Construct an analyzer with optional overrides."""
    return AzureADAnalyzer(**kwargs)


def _check_ids(report: AADReport) -> set:
    """Return the set of check IDs that fired in a report."""
    return {f.check_id for f in report.findings}


def _clean_config() -> AADTenantConfig:
    """
    A tenant config that should produce zero findings with a default analyzer.
    - No users with privileged roles.
    - Legacy auth blocked.
    - PIM enabled.
    - One enabled CA policy that requires MFA.
    - Guest ratio well within threshold.
    - No service principals.
    """
    return AADTenantConfig(
        tenant_id=TENANT_ID,
        users=[
            {
                "id": "u-safe",
                "display_name": "Safe User",
                "mfa_enabled": True,
                "roles": ["User"],
                "is_guest": False,
                "is_service_principal": False,
            }
        ],
        service_principals=[],
        conditional_access_policies=[
            {
                "name": "Require MFA for all users",
                "state": "enabled",
                "conditions": {},
                "grant_controls": {"operator": "OR", "builtInControls": ["mfa"]},
            }
        ],
        legacy_auth_blocked=True,
        pim_enabled=True,
        total_users=100,
        total_guests=5,
    )


def _privileged_user(
    uid: str = "u1",
    display_name: str = "Admin User",
    mfa_enabled: bool = True,
    roles: Optional[list] = None,
    is_guest: bool = False,
    is_service_principal: bool = False,
) -> dict:
    """Factory for a user dict with privileged roles."""
    return {
        "id": uid,
        "display_name": display_name,
        "mfa_enabled": mfa_enabled,
        "roles": roles if roles is not None else ["GlobalAdministrator"],
        "is_guest": is_guest,
        "is_service_principal": is_service_principal,
    }


def _sp(
    sp_id: str = "sp-1",
    name: str = "MyApp",
    secret_ages: Optional[list] = None,
) -> dict:
    """Factory for a service principal dict."""
    secrets = [{"age_days": age} for age in (secret_ages or [])]
    return {"id": sp_id, "name": name, "client_secrets": secrets}


# Needed for type hints inside helpers above without Python 3.10+ syntax.
from typing import Optional  # noqa: E402


# ===========================================================================
# AADFinding unit tests
# ===========================================================================

class TestAADFinding:
    def _finding(self) -> AADFinding:
        return AADFinding(
            check_id="AAD-001",
            severity=AADSeverity.CRITICAL,
            tenant_id=TENANT_ID,
            subject="Admin User",
            title="Privileged user lacks MFA",
            detail="Admin has no MFA.",
            remediation="Enable MFA.",
        )

    def test_to_dict_has_all_required_keys(self):
        d = self._finding().to_dict()
        for key in ("check_id", "severity", "tenant_id", "subject",
                    "title", "detail", "remediation"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_severity_is_string_value(self):
        assert self._finding().to_dict()["severity"] == "CRITICAL"

    def test_to_dict_check_id_correct(self):
        assert self._finding().to_dict()["check_id"] == "AAD-001"

    def test_to_dict_subject_correct(self):
        assert self._finding().to_dict()["subject"] == "Admin User"

    def test_to_dict_tenant_id_correct(self):
        assert self._finding().to_dict()["tenant_id"] == TENANT_ID

    def test_summary_contains_check_id(self):
        assert "AAD-001" in self._finding().summary()

    def test_summary_contains_severity(self):
        assert "CRITICAL" in self._finding().summary()

    def test_summary_contains_tenant_id(self):
        assert TENANT_ID in self._finding().summary()

    def test_summary_contains_subject(self):
        assert "Admin User" in self._finding().summary()

    def test_remediation_defaults_to_empty_string(self):
        f = AADFinding(
            check_id="AAD-002",
            severity=AADSeverity.HIGH,
            tenant_id=TENANT_ID,
            subject="tenant",
            title="t",
            detail="d",
        )
        assert f.remediation == ""

    def test_to_dict_remediation_present_when_set(self):
        d = self._finding().to_dict()
        assert d["remediation"] == "Enable MFA."


# ===========================================================================
# AADReport unit tests
# ===========================================================================

class TestAADReport:
    def _report(self) -> AADReport:
        f1 = AADFinding("AAD-001", AADSeverity.CRITICAL, TENANT_ID, "Admin", "t", "d")
        f2 = AADFinding("AAD-002", AADSeverity.HIGH,     TENANT_ID, "tenant", "t", "d")
        f3 = AADFinding("AAD-005", AADSeverity.MEDIUM,   TENANT_ID, "tenant", "t", "d")
        return AADReport(
            findings=[f1, f2, f3],
            risk_score=80,
            tenant_id=TENANT_ID,
            policies_analyzed=3,
        )

    def test_total_findings(self):
        assert self._report().total_findings == 3

    def test_critical_findings_count(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings_count(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check_returns_correct_subset(self):
        r = self._report()
        assert len(r.findings_by_check("AAD-001")) == 1
        assert len(r.findings_by_check("AAD-002")) == 1
        assert len(r.findings_by_check("AAD-999")) == 0

    def test_findings_for_subject_admin(self):
        r = self._report()
        assert len(r.findings_for_subject("Admin")) == 1

    def test_findings_for_subject_tenant(self):
        r = self._report()
        # AAD-002 and AAD-005 both have subject "tenant".
        assert len(r.findings_for_subject("tenant")) == 2

    def test_findings_for_subject_missing_returns_empty(self):
        r = self._report()
        assert r.findings_for_subject("nobody") == []

    def test_summary_contains_risk_score(self):
        assert "80" in self._report().summary()

    def test_summary_contains_tenant_id(self):
        assert TENANT_ID in self._report().summary()

    def test_summary_contains_policies_analyzed(self):
        assert "3" in self._report().summary()

    def test_to_dict_has_all_keys(self):
        d = self._report().to_dict()
        for key in ("tenant_id", "total_findings", "risk_score", "policies_analyzed",
                    "critical", "high", "generated_at", "findings"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_findings_is_list_of_dicts(self):
        d = self._report().to_dict()
        assert isinstance(d["findings"], list)
        assert isinstance(d["findings"][0], dict)

    def test_to_dict_tenant_id_correct(self):
        assert self._report().to_dict()["tenant_id"] == TENANT_ID

    def test_empty_report_zero_total(self):
        r = AADReport()
        assert r.total_findings == 0

    def test_generated_at_is_float(self):
        assert isinstance(AADReport().generated_at, float)

    def test_policies_analyzed_reflected_in_to_dict(self):
        assert self._report().to_dict()["policies_analyzed"] == 3


# ===========================================================================
# AAD-001: MFA not enforced for privileged user
# ===========================================================================

class TestAAD001:
    def test_fires_when_privileged_user_has_no_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(mfa_enabled=False)],
        )
        r = _analyzer().analyze(config)
        assert "AAD-001" in _check_ids(r)

    def test_not_fired_when_privileged_user_has_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(mfa_enabled=True)],
        )
        r = _analyzer().analyze(config)
        assert "AAD-001" not in _check_ids(r)

    def test_not_fired_for_non_privileged_user_without_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[{
                "id": "u2", "display_name": "Normal User",
                "mfa_enabled": False, "roles": ["User"],
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-001" not in _check_ids(r)

    def test_severity_is_critical(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(mfa_enabled=False)],
        )
        r = _analyzer().analyze(config)
        f = r.findings_by_check("AAD-001")[0]
        assert f.severity == AADSeverity.CRITICAL

    def test_fires_once_per_privileged_user_without_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "Admin1", mfa_enabled=False),
                _privileged_user("u2", "Admin2", mfa_enabled=False),
                _privileged_user("u3", "Admin3", mfa_enabled=True),
            ],
        )
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-001")) == 2

    def test_subject_is_display_name(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(display_name="Jane Admin", mfa_enabled=False)],
        )
        r = _analyzer().analyze(config)
        f = r.findings_by_check("AAD-001")[0]
        assert f.subject == "Jane Admin"

    def test_all_privileged_role_names_trigger(self):
        # Each role in _PRIVILEGED_ROLES should cause AAD-001 to fire.
        for role in list(_PRIVILEGED_ROLES)[:5]:  # spot-check first 5
            config = AADTenantConfig(
                tenant_id=TENANT_ID,
                users=[_privileged_user(roles=[role.capitalize()], mfa_enabled=False)],
            )
            r = _analyzer().analyze(config)
            assert "AAD-001" in _check_ids(r), f"AAD-001 did not fire for role {role}"

    def test_service_principal_skipped_for_001(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(mfa_enabled=False, is_service_principal=True)],
        )
        r = _analyzer().analyze(config)
        assert "AAD-001" not in _check_ids(r)


# ===========================================================================
# AAD-002: Legacy authentication protocols not blocked
# ===========================================================================

class TestAAD002:
    def test_fires_when_legacy_auth_not_blocked(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, legacy_auth_blocked=False)
        r = _analyzer().analyze(config)
        assert "AAD-002" in _check_ids(r)

    def test_not_fired_when_legacy_auth_blocked(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, legacy_auth_blocked=True)
        r = _analyzer().analyze(config)
        assert "AAD-002" not in _check_ids(r)

    def test_severity_is_high(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, legacy_auth_blocked=False)
        r = _analyzer().analyze(config)
        f = r.findings_by_check("AAD-002")[0]
        assert f.severity == AADSeverity.HIGH

    def test_exactly_one_finding_per_tenant(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, legacy_auth_blocked=False)
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-002")) == 1

    def test_subject_is_tenant(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, legacy_auth_blocked=False)
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-002")[0].subject == "tenant"


# ===========================================================================
# AAD-003: Guest user with privileged role assignment
# ===========================================================================

class TestAAD003:
    def test_fires_for_guest_with_privileged_role(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(is_guest=True)],
        )
        r = _analyzer().analyze(config)
        assert "AAD-003" in _check_ids(r)

    def test_not_fired_for_non_guest_with_privileged_role(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(is_guest=False)],
        )
        r = _analyzer().analyze(config)
        assert "AAD-003" not in _check_ids(r)

    def test_not_fired_for_guest_without_privileged_role(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[{
                "id": "g1", "display_name": "External Guest",
                "mfa_enabled": True, "roles": ["User"], "is_guest": True,
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-003" not in _check_ids(r)

    def test_severity_is_critical(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(is_guest=True)],
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-003")[0].severity == AADSeverity.CRITICAL

    def test_fires_once_per_guest_with_privileged_role(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("g1", "Guest1", is_guest=True),
                _privileged_user("g2", "Guest2", is_guest=True),
                _privileged_user("u1", "Internal", is_guest=False),
            ],
        )
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-003")) == 2


# ===========================================================================
# AAD-004: Privileged role assignment without PIM
# ===========================================================================

class TestAAD004:
    def test_fires_when_pim_disabled_and_privileged_users_exist(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user()],
            pim_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert "AAD-004" in _check_ids(r)

    def test_not_fired_when_pim_enabled(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user()],
            pim_enabled=True,
        )
        r = _analyzer().analyze(config)
        assert "AAD-004" not in _check_ids(r)

    def test_not_fired_when_no_privileged_users_despite_pim_disabled(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[{
                "id": "u1", "display_name": "Normal",
                "mfa_enabled": True, "roles": ["User"],
            }],
            pim_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert "AAD-004" not in _check_ids(r)

    def test_severity_is_high(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user()],
            pim_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-004")[0].severity == AADSeverity.HIGH

    def test_exactly_one_finding_regardless_of_user_count(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "Admin1"),
                _privileged_user("u2", "Admin2"),
            ],
            pim_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-004")) == 1


# ===========================================================================
# AAD-005: No Conditional Access policy requiring MFA for all users
# ===========================================================================

class TestAAD005:
    def test_fires_when_no_ca_policies(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" in _check_ids(r)

    def test_fires_when_all_ca_policies_disabled(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[{
                "name": "Disabled MFA Policy",
                "state": "disabled",
                "conditions": {},
                "grant_controls": {"builtInControls": ["mfa"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" in _check_ids(r)

    def test_fires_when_enabled_policy_has_no_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[{
                "name": "Require compliant device",
                "state": "enabled",
                "conditions": {},
                "grant_controls": {"builtInControls": ["compliantDevice"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" in _check_ids(r)

    def test_not_fired_when_enabled_policy_requires_mfa(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[{
                "name": "Require MFA",
                "state": "enabled",
                "conditions": {},
                "grant_controls": {"builtInControls": ["mfa"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" not in _check_ids(r)

    def test_not_fired_when_mfa_appears_in_nested_grant_controls(self):
        # mfa referenced via a nested dict structure.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[{
                "name": "Require MFA nested",
                "state": "enabled",
                "conditions": {},
                "grant_controls": {
                    "operator": "AND",
                    "controls": [{"type": "mfa"}, {"type": "compliantDevice"}],
                },
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" not in _check_ids(r)

    def test_not_fired_when_mfa_is_mixed_case(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[{
                "name": "MFA Policy",
                "state": "enabled",
                "conditions": {},
                "grant_controls": {"builtInControls": ["MFA"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert "AAD-005" not in _check_ids(r)

    def test_severity_is_medium(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            conditional_access_policies=[],
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-005")[0].severity == AADSeverity.MEDIUM

    def test_exactly_one_finding_when_fired(self):
        config = AADTenantConfig(tenant_id=TENANT_ID)
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-005")) == 1


# ===========================================================================
# AAD-006: Service principal with stale client secret
# ===========================================================================

class TestAAD006:
    def test_fires_when_secret_exceeds_limit(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(secret_ages=[366])],
        )
        r = _analyzer(max_secret_age_days=365).analyze(config)
        assert "AAD-006" in _check_ids(r)

    def test_not_fired_when_secret_at_exact_limit(self):
        # Exactly at limit: age_days == max_secret_age_days — no finding.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(secret_ages=[365])],
        )
        r = _analyzer(max_secret_age_days=365).analyze(config)
        assert "AAD-006" not in _check_ids(r)

    def test_not_fired_when_secret_under_limit(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(secret_ages=[100])],
        )
        r = _analyzer(max_secret_age_days=365).analyze(config)
        assert "AAD-006" not in _check_ids(r)

    def test_custom_limit_respected(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(secret_ages=[91])],
        )
        r = _analyzer(max_secret_age_days=90).analyze(config)
        assert "AAD-006" in _check_ids(r)

    def test_fires_per_stale_secret_not_per_sp(self):
        # Two stale secrets on one SP → two findings.
        sp = {"id": "sp-1", "name": "MyApp", "client_secrets": [
            {"age_days": 400},
            {"age_days": 500},
        ]}
        config = AADTenantConfig(tenant_id=TENANT_ID, service_principals=[sp])
        r = _analyzer(max_secret_age_days=365).analyze(config)
        assert len(r.findings_by_check("AAD-006")) == 2

    def test_only_stale_secrets_from_mixed_sp_fire(self):
        sp = {"id": "sp-1", "name": "MyApp", "client_secrets": [
            {"age_days": 30},   # fresh
            {"age_days": 400},  # stale
        ]}
        config = AADTenantConfig(tenant_id=TENANT_ID, service_principals=[sp])
        r = _analyzer(max_secret_age_days=365).analyze(config)
        assert len(r.findings_by_check("AAD-006")) == 1

    def test_severity_is_high(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(secret_ages=[400])],
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-006")[0].severity == AADSeverity.HIGH

    def test_subject_is_sp_name(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            service_principals=[_sp(name="CriticalApp", secret_ages=[400])],
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-006")[0].subject == "CriticalApp"

    def test_skips_secret_without_age_metadata(self):
        sp = {"id": "sp-1", "name": "App", "client_secrets": [{}]}  # no age_days
        config = AADTenantConfig(tenant_id=TENANT_ID, service_principals=[sp])
        r = _analyzer().analyze(config)
        assert "AAD-006" not in _check_ids(r)

    def test_no_findings_when_no_service_principals(self):
        config = AADTenantConfig(tenant_id=TENANT_ID, service_principals=[])
        r = _analyzer().analyze(config)
        assert "AAD-006" not in _check_ids(r)


# ===========================================================================
# AAD-007: Guest user ratio exceeds threshold
# ===========================================================================

class TestAAD007:
    def test_fires_when_ratio_exceeds_threshold(self):
        # 21 guests / 100 users = 0.21 > 0.20
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=21,
        )
        r = _analyzer(max_guest_ratio=0.20).analyze(config)
        assert "AAD-007" in _check_ids(r)

    def test_not_fired_when_ratio_exactly_at_threshold(self):
        # 20 guests / 100 users = 0.20 — not strictly over threshold.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=20,
        )
        r = _analyzer(max_guest_ratio=0.20).analyze(config)
        assert "AAD-007" not in _check_ids(r)

    def test_not_fired_when_ratio_under_threshold(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=10,
        )
        r = _analyzer(max_guest_ratio=0.20).analyze(config)
        assert "AAD-007" not in _check_ids(r)

    def test_not_fired_when_total_users_is_zero(self):
        # Prevent divide-by-zero; ratio is undefined.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=0,
            total_guests=5,
        )
        r = _analyzer().analyze(config)
        assert "AAD-007" not in _check_ids(r)

    def test_custom_threshold_respected(self):
        # Custom threshold of 0.10: 11/100 should fire.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=11,
        )
        r = _analyzer(max_guest_ratio=0.10).analyze(config)
        assert "AAD-007" in _check_ids(r)

    def test_severity_is_low(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=21,
        )
        r = _analyzer(max_guest_ratio=0.20).analyze(config)
        assert r.findings_by_check("AAD-007")[0].severity == AADSeverity.LOW

    def test_exactly_one_finding_when_fired(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=50,
        )
        r = _analyzer().analyze(config)
        assert len(r.findings_by_check("AAD-007")) == 1

    def test_subject_is_tenant(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            total_users=100,
            total_guests=50,
        )
        r = _analyzer().analyze(config)
        assert r.findings_by_check("AAD-007")[0].subject == "tenant"


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_config_zero_score(self):
        r = _analyzer().analyze(_clean_config())
        assert r.risk_score == 0

    def test_score_positive_when_issues_found(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[_privileged_user(mfa_enabled=False)],
        )
        r = _analyzer().analyze(config)
        assert r.risk_score > 0

    def test_score_matches_single_check_weight(self):
        # Only AAD-002 fires: legacy_auth_blocked=False, no users, no SP, no CA issues.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            legacy_auth_blocked=False,
            pim_enabled=True,  # PIM on: suppress AAD-004
            conditional_access_policies=[{  # MFA CA: suppress AAD-005
                "name": "MFA", "state": "enabled",
                "conditions": {}, "grant_controls": {"builtInControls": ["mfa"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert r.risk_score == _CHECK_WEIGHTS["AAD-002"]

    def test_score_not_double_counted_for_multiple_users_same_check(self):
        # Two users without MFA both trigger AAD-001 but the weight is counted once.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "Admin1", mfa_enabled=False),
                _privileged_user("u2", "Admin2", mfa_enabled=False),
            ],
            pim_enabled=True,
            legacy_auth_blocked=True,
            conditional_access_policies=[{
                "name": "MFA", "state": "enabled",
                "conditions": {}, "grant_controls": {"builtInControls": ["mfa"]},
            }],
        )
        r = _analyzer().analyze(config)
        assert r.risk_score == _CHECK_WEIGHTS["AAD-001"]

    def test_score_capped_at_100_for_worst_case(self):
        # Fire all 7 checks: total weights = 50+45+40+35+30+25+15 = 240 → capped at 100.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "Admin", mfa_enabled=False),        # AAD-001
                _privileged_user("g1", "GuestAdmin", is_guest=True),       # AAD-003
            ],
            service_principals=[_sp(secret_ages=[400])],                   # AAD-006
            conditional_access_policies=[],                                 # AAD-005
            legacy_auth_blocked=False,                                      # AAD-002
            pim_enabled=False,                                              # AAD-004
            total_users=100,
            total_guests=50,                                                # AAD-007
        )
        r = _analyzer().analyze(config)
        assert r.risk_score == 100

    def test_score_additive_for_distinct_checks(self):
        # AAD-002 (45) + AAD-005 (30) = 75.
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            legacy_auth_blocked=False,         # AAD-002
            pim_enabled=True,
            conditional_access_policies=[],    # AAD-005
        )
        r = _analyzer().analyze(config)
        expected = _CHECK_WEIGHTS["AAD-002"] + _CHECK_WEIGHTS["AAD-005"]
        assert r.risk_score == expected


# ===========================================================================
# Clean config (zero findings)
# ===========================================================================

class TestCleanConfig:
    def test_clean_config_produces_no_findings(self):
        r = _analyzer().analyze(_clean_config())
        assert r.total_findings == 0

    def test_clean_config_risk_score_zero(self):
        r = _analyzer().analyze(_clean_config())
        assert r.risk_score == 0

    def test_clean_config_summary_shows_zero(self):
        r = _analyzer().analyze(_clean_config())
        assert "0" in r.summary()

    def test_findings_for_subject_returns_empty_for_clean(self):
        r = _analyzer().analyze(_clean_config())
        assert r.findings_for_subject("Safe User") == []

    def test_policies_analyzed_reflects_ca_count(self):
        r = _analyzer().analyze(_clean_config())
        assert r.policies_analyzed == 1


# ===========================================================================
# Multi-check integration
# ===========================================================================

class TestMultiCheckIntegration:
    def test_multiple_findings_accumulate_correctly(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "NoMFA Admin", mfa_enabled=False),
                _privileged_user("g1", "Guest Admin", is_guest=True),
            ],
            legacy_auth_blocked=False,
            pim_enabled=False,
            conditional_access_policies=[],
            service_principals=[_sp(secret_ages=[400])],
            total_users=10,
            total_guests=5,
        )
        r = _analyzer().analyze(config)
        # All 7 check IDs should be present.
        fired = _check_ids(r)
        assert fired == {"AAD-001", "AAD-002", "AAD-003", "AAD-004",
                         "AAD-005", "AAD-006", "AAD-007"}

    def test_findings_for_subject_isolates_user(self):
        config = AADTenantConfig(
            tenant_id=TENANT_ID,
            users=[
                _privileged_user("u1", "Alice", mfa_enabled=False),
                _privileged_user("g1", "Bob", is_guest=True),
            ],
        )
        r = _analyzer().analyze(config)
        alice_findings = r.findings_for_subject("Alice")
        bob_findings   = r.findings_for_subject("Bob")
        # Alice triggers AAD-001; Bob triggers AAD-003.
        assert any(f.check_id == "AAD-001" for f in alice_findings)
        assert any(f.check_id == "AAD-003" for f in bob_findings)

    def test_tenant_id_propagated_to_all_findings(self):
        config = AADTenantConfig(
            tenant_id="my-tenant",
            users=[_privileged_user(mfa_enabled=False)],
            legacy_auth_blocked=False,
        )
        r = _analyzer().analyze(config)
        for finding in r.findings:
            assert finding.tenant_id == "my-tenant"

    def test_report_tenant_id_matches_config(self):
        config = AADTenantConfig(tenant_id="special-tenant")
        r = _analyzer().analyze(config)
        assert r.tenant_id == "special-tenant"
