"""
Tests for analyzers/gcp_iam_analyzer.py

Coverage targets
----------------
- GCPIAMFinding: to_dict(), summary()
- GCPIAMReport: properties, helpers, summary(), to_dict()
- IAMPolicy.from_dict(): parses bindings and service_account_keys
- GCPIAMAnalyzer.analyze(): all 7 check IDs
- Org-domain filtering (GCP-IAM-004)
- Default service account detection (GCP-IAM-005)
- Key-age threshold boundary (GCP-IAM-006)
- Clean (no-finding) policies
- Risk score capping at 100
- Severity levels for each check
- check_external_members=False suppresses GCP-IAM-004
- Raw dict bindings accepted alongside IAMBinding objects
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

# Allow running tests directly from the repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.gcp_iam_analyzer import (
    GCPIAMAnalyzer,
    GCPIAMFinding,
    GCPIAMReport,
    GCPIAMSeverity,
    IAMBinding,
    IAMPolicy,
    _CHECK_WEIGHTS,
    _PRIMITIVE_ROLES,
    _SENSITIVE_ROLES,
    load_gcp_iam_policies_from_export,
)
from cli.main import cli


# ===========================================================================
# Shared helpers
# ===========================================================================

def _analyzer(**kwargs) -> GCPIAMAnalyzer:
    """Construct an analyzer with optional overrides."""
    return GCPIAMAnalyzer(**kwargs)


def _check_ids(report: GCPIAMReport) -> set:
    """Return the set of check IDs that fired in a report."""
    return {f.check_id for f in report.findings}


def _clean_policy(resource: str = "projects/clean-project") -> IAMPolicy:
    """
    An IAMPolicy with no risky bindings and no service account keys.
    Should produce zero findings with a default analyzer.
    """
    return IAMPolicy(
        resource=resource,
        bindings=[
            IAMBinding(
                role="roles/logging.viewer",
                members=["user:audit@example.com"],
            ),
        ],
        service_account_keys=[],
    )


def _policy_with_binding(
    role: str,
    members: list,
    resource: str = "projects/test-project",
    sa_keys: list = None,
) -> IAMPolicy:
    """Convenience factory for single-binding policies."""
    return IAMPolicy(
        resource=resource,
        bindings=[IAMBinding(role=role, members=members)],
        service_account_keys=sa_keys or [],
    )


# ===========================================================================
# GCPIAMFinding
# ===========================================================================

class TestGCPIAMFinding:
    def _finding(self) -> GCPIAMFinding:
        return GCPIAMFinding(
            check_id="GCP-IAM-001",
            severity=GCPIAMSeverity.CRITICAL,
            resource="projects/my-project",
            role="roles/owner",
            member="user:admin@example.com",
            title="Primitive role granted",
            detail="Owner role is too broad.",
            remediation="Replace with a predefined role.",
        )

    def test_to_dict_has_all_required_keys(self):
        d = self._finding().to_dict()
        for key in ("check_id", "severity", "resource", "role", "member",
                    "title", "detail", "remediation"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_severity_is_string(self):
        assert self._finding().to_dict()["severity"] == "CRITICAL"

    def test_to_dict_check_id(self):
        assert self._finding().to_dict()["check_id"] == "GCP-IAM-001"

    def test_summary_contains_check_id(self):
        assert "GCP-IAM-001" in self._finding().summary()

    def test_summary_contains_severity(self):
        assert "CRITICAL" in self._finding().summary()

    def test_summary_contains_resource(self):
        assert "projects/my-project" in self._finding().summary()

    def test_remediation_defaults_to_empty_string(self):
        f = GCPIAMFinding(
            check_id="GCP-IAM-002",
            severity=GCPIAMSeverity.CRITICAL,
            resource="projects/x",
            role="roles/viewer",
            member="allUsers",
            title="t",
            detail="d",
        )
        assert f.remediation == ""

    def test_to_dict_empty_member(self):
        f = GCPIAMFinding("GCP-IAM-006", GCPIAMSeverity.HIGH,
                          "projects/x", "", "", "t", "d")
        assert f.to_dict()["member"] == ""


# ===========================================================================
# GCPIAMReport
# ===========================================================================

class TestGCPIAMReport:
    def _report(self) -> GCPIAMReport:
        f1 = GCPIAMFinding("GCP-IAM-001", GCPIAMSeverity.CRITICAL,
                           "projects/a", "roles/owner", "user:x@y.com", "t", "d")
        f2 = GCPIAMFinding("GCP-IAM-005", GCPIAMSeverity.MEDIUM,
                           "projects/a", "roles/viewer", "serviceAccount:sa@a.com", "t", "d")
        f3 = GCPIAMFinding("GCP-IAM-007", GCPIAMSeverity.HIGH,
                           "projects/b", "roles/iam.admin", "user:b@b.com", "t", "d")
        return GCPIAMReport(findings=[f1, f2, f3], risk_score=70, policies_analyzed=2)

    def test_total_findings(self):
        assert self._report().total_findings == 3

    def test_critical_findings_count(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings_count(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check(self):
        r = self._report()
        assert len(r.findings_by_check("GCP-IAM-001")) == 1
        assert len(r.findings_by_check("GCP-IAM-005")) == 1
        assert len(r.findings_by_check("GCP-IAM-999")) == 0

    def test_findings_for_resource(self):
        r = self._report()
        assert len(r.findings_for_resource("projects/a")) == 2
        assert len(r.findings_for_resource("projects/b")) == 1
        assert len(r.findings_for_resource("projects/missing")) == 0

    def test_summary_contains_risk_score(self):
        assert "70" in self._report().summary()

    def test_summary_contains_policies_analyzed(self):
        assert "2" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for key in ("total_findings", "risk_score", "policies_analyzed",
                    "critical", "high", "generated_at", "findings"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_findings_is_list_of_dicts(self):
        d = self._report().to_dict()
        assert isinstance(d["findings"], list)
        assert isinstance(d["findings"][0], dict)

    def test_empty_report_zero_total(self):
        r = GCPIAMReport()
        assert r.total_findings == 0

    def test_generated_at_is_float(self):
        assert isinstance(GCPIAMReport().generated_at, float)


# ===========================================================================
# IAMPolicy.from_dict
# ===========================================================================

class TestIAMPolicyFromDict:
    def _raw(self) -> dict:
        return {
            "bindings": [
                {"role": "roles/owner", "members": ["user:admin@example.com"]},
                {"role": "roles/viewer", "members": ["user:reader@example.com", "allUsers"]},
            ]
        }

    def test_parses_bindings(self):
        p = IAMPolicy.from_dict("projects/x", self._raw())
        assert len(p.bindings) == 2

    def test_binding_roles_correct(self):
        p = IAMPolicy.from_dict("projects/x", self._raw())
        roles = {b.role for b in p.bindings}
        assert roles == {"roles/owner", "roles/viewer"}

    def test_binding_members_correct(self):
        p = IAMPolicy.from_dict("projects/x", self._raw())
        owner_binding = next(b for b in p.bindings if b.role == "roles/owner")
        assert "user:admin@example.com" in owner_binding.members

    def test_resource_set_correctly(self):
        p = IAMPolicy.from_dict("projects/my-project", self._raw())
        assert p.resource == "projects/my-project"

    def test_empty_bindings(self):
        p = IAMPolicy.from_dict("projects/x", {"bindings": []})
        assert p.bindings == []

    def test_missing_bindings_key(self):
        p = IAMPolicy.from_dict("projects/x", {})
        assert p.bindings == []

    def test_service_account_keys_parsed(self):
        raw = {
            "bindings": [],
            "service_account_keys": [{"key_id": "k1", "created_at_days_ago": 120}],
        }
        p = IAMPolicy.from_dict("projects/x", raw)
        assert len(p.service_account_keys) == 1
        assert p.service_account_keys[0]["key_id"] == "k1"

    def test_service_account_keys_defaults_to_empty(self):
        p = IAMPolicy.from_dict("projects/x", {"bindings": []})
        assert p.service_account_keys == []

    def test_members_default_to_empty_list_when_absent(self):
        raw = {"bindings": [{"role": "roles/viewer"}]}
        p = IAMPolicy.from_dict("projects/x", raw)
        assert p.bindings[0].members == []


# ===========================================================================
# GCP-IAM-001: Primitive roles
# ===========================================================================

class TestGCPIAM001:
    def test_fires_for_owner(self):
        policy = _policy_with_binding("roles/owner", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" in _check_ids(r)

    def test_fires_for_editor(self):
        policy = _policy_with_binding("roles/editor", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" in _check_ids(r)

    def test_fires_for_viewer(self):
        policy = _policy_with_binding("roles/viewer", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" in _check_ids(r)

    def test_not_fired_for_predefined_role(self):
        policy = _policy_with_binding("roles/storage.objectViewer", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" not in _check_ids(r)

    def test_one_finding_per_member(self):
        policy = _policy_with_binding(
            "roles/editor",
            ["user:a@x.com", "user:b@x.com", "user:c@x.com"],
        )
        r = _analyzer().analyze([policy])
        assert len(r.findings_by_check("GCP-IAM-001")) == 3

    def test_severity_critical_for_owner(self):
        policy = _policy_with_binding("roles/owner", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-001")[0]
        assert f.severity == GCPIAMSeverity.CRITICAL

    def test_severity_high_for_editor(self):
        policy = _policy_with_binding("roles/editor", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-001")[0]
        assert f.severity == GCPIAMSeverity.HIGH

    def test_allusers_skipped_in_001(self):
        # allUsers in a primitive role should NOT produce a GCP-IAM-001 finding
        # (it is caught by GCP-IAM-002 instead).
        policy = _policy_with_binding("roles/viewer", ["allUsers"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" not in _check_ids(r)


# ===========================================================================
# GCP-IAM-002: allUsers / allAuthenticatedUsers
# ===========================================================================

class TestGCPIAM002:
    def test_fires_for_allusers(self):
        policy = _policy_with_binding("roles/storage.admin", ["allUsers"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-002" in _check_ids(r)

    def test_fires_for_allauthenticatedusers(self):
        policy = _policy_with_binding("roles/viewer", ["allAuthenticatedUsers"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-002" in _check_ids(r)

    def test_severity_is_critical(self):
        policy = _policy_with_binding("roles/viewer", ["allUsers"])
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-002")[0]
        assert f.severity == GCPIAMSeverity.CRITICAL

    def test_not_fired_for_specific_user(self):
        policy = _policy_with_binding("roles/viewer", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-002" not in _check_ids(r)

    def test_fires_once_per_public_member(self):
        policy = _policy_with_binding(
            "roles/viewer", ["allUsers", "allAuthenticatedUsers"]
        )
        r = _analyzer().analyze([policy])
        assert len(r.findings_by_check("GCP-IAM-002")) == 2


# ===========================================================================
# GCP-IAM-003: Service account with Owner/Editor
# ===========================================================================

class TestGCPIAM003:
    def test_fires_for_sa_with_owner(self):
        policy = _policy_with_binding(
            "roles/owner",
            ["serviceAccount:svc@my-project.iam.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-003" in _check_ids(r)

    def test_fires_for_sa_with_editor(self):
        policy = _policy_with_binding(
            "roles/editor",
            ["serviceAccount:svc@my-project.iam.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-003" in _check_ids(r)

    def test_not_fired_for_user_with_owner(self):
        # GCP-IAM-003 is SA-specific; users are caught by GCP-IAM-001.
        policy = _policy_with_binding("roles/owner", ["user:admin@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-003" not in _check_ids(r)

    def test_not_fired_for_sa_with_viewer(self):
        policy = _policy_with_binding(
            "roles/viewer",
            ["serviceAccount:svc@my-project.iam.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-003" not in _check_ids(r)

    def test_severity_is_critical(self):
        policy = _policy_with_binding(
            "roles/editor",
            ["serviceAccount:svc@my-project.iam.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-003")[0]
        assert f.severity == GCPIAMSeverity.CRITICAL


# ===========================================================================
# GCP-IAM-004: External member in sensitive role
# ===========================================================================

class TestGCPIAM004:
    def _ext_analyzer(self) -> GCPIAMAnalyzer:
        return _analyzer(org_domains=["example.com"])

    def test_fires_for_external_user_in_owner(self):
        policy = _policy_with_binding("roles/owner", ["user:outsider@external.org"])
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" in _check_ids(r)

    def test_fires_for_external_user_in_iam_admin(self):
        policy = _policy_with_binding(
            "roles/iam.admin", ["user:outsider@other.io"]
        )
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" in _check_ids(r)

    def test_not_fired_for_internal_user(self):
        policy = _policy_with_binding("roles/owner", ["user:insider@example.com"])
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_not_fired_when_no_org_domains_set(self):
        policy = _policy_with_binding("roles/owner", ["user:outsider@external.org"])
        r = _analyzer().analyze([policy])  # no org_domains
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_not_fired_for_service_account_member(self):
        # GCP-IAM-004 only triggers for user: members.
        policy = _policy_with_binding(
            "roles/owner",
            ["serviceAccount:svc@external.iam.gserviceaccount.com"],
        )
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_not_fired_for_non_sensitive_role(self):
        policy = _policy_with_binding(
            "roles/storage.objectViewer", ["user:outsider@external.org"]
        )
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_check_external_members_false_suppresses(self):
        policy = _policy_with_binding("roles/owner", ["user:outsider@external.org"])
        r = _analyzer(
            org_domains=["example.com"], check_external_members=False
        ).analyze([policy])
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_severity_is_high(self):
        policy = _policy_with_binding("roles/owner", ["user:outsider@external.org"])
        r = self._ext_analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-004")[0]
        assert f.severity == GCPIAMSeverity.HIGH

    def test_multiple_org_domains(self):
        policy = _policy_with_binding(
            "roles/owner", ["user:dev@partner.com", "user:sre@example.com"]
        )
        r = _analyzer(org_domains=["example.com", "partner.com"]).analyze([policy])
        assert "GCP-IAM-004" not in _check_ids(r)

    def test_fires_for_org_admin_role(self):
        policy = _policy_with_binding(
            "roles/resourcemanager.organizationAdmin",
            ["user:attacker@evil.com"],
        )
        r = self._ext_analyzer().analyze([policy])
        assert "GCP-IAM-004" in _check_ids(r)


# ===========================================================================
# GCP-IAM-005: Default service accounts
# ===========================================================================

class TestGCPIAM005:
    def test_fires_for_compute_default_sa(self):
        policy = _policy_with_binding(
            "roles/editor",
            ["serviceAccount:123456789012-compute@developer.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-005" in _check_ids(r)

    def test_fires_for_appengine_default_sa(self):
        policy = _policy_with_binding(
            "roles/viewer",
            ["serviceAccount:my-project.appspot.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-005" in _check_ids(r)

    def test_not_fired_for_custom_sa(self):
        policy = _policy_with_binding(
            "roles/viewer",
            ["serviceAccount:custom-sa@my-project.iam.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-005" not in _check_ids(r)

    def test_not_fired_for_user_member(self):
        policy = _policy_with_binding(
            "roles/viewer", ["user:not-a-sa@example.com"]
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-005" not in _check_ids(r)

    def test_severity_is_medium(self):
        policy = _policy_with_binding(
            "roles/editor",
            ["serviceAccount:987654321098-compute@developer.gserviceaccount.com"],
        )
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-005")[0]
        assert f.severity == GCPIAMSeverity.MEDIUM


# ===========================================================================
# GCP-IAM-006: Service account key age
# ===========================================================================

class TestGCPIAM006:
    def _policy_with_key(self, age_days: int, resource: str = "projects/p") -> IAMPolicy:
        return IAMPolicy(
            resource=resource,
            bindings=[],
            service_account_keys=[
                {"key_id": "key-abc", "created_at_days_ago": age_days,
                 "service_account": "svc@p.iam.gserviceaccount.com"},
            ],
        )

    def test_fires_when_key_older_than_limit(self):
        r = _analyzer(max_key_age_days=90).analyze([self._policy_with_key(91)])
        assert "GCP-IAM-006" in _check_ids(r)

    def test_not_fired_when_key_at_limit(self):
        r = _analyzer(max_key_age_days=90).analyze([self._policy_with_key(90)])
        assert "GCP-IAM-006" not in _check_ids(r)

    def test_not_fired_when_key_under_limit(self):
        r = _analyzer(max_key_age_days=90).analyze([self._policy_with_key(45)])
        assert "GCP-IAM-006" not in _check_ids(r)

    def test_custom_limit_respected(self):
        r = _analyzer(max_key_age_days=30).analyze([self._policy_with_key(31)])
        assert "GCP-IAM-006" in _check_ids(r)

    def test_not_fired_with_no_keys(self):
        r = _analyzer().analyze([IAMPolicy(resource="projects/x", bindings=[])])
        assert "GCP-IAM-006" not in _check_ids(r)

    def test_skips_key_without_age_metadata(self):
        policy = IAMPolicy(
            resource="projects/x",
            bindings=[],
            service_account_keys=[{"key_id": "k1"}],  # no created_at_days_ago
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-006" not in _check_ids(r)

    def test_severity_is_high(self):
        r = _analyzer().analyze([self._policy_with_key(200)])
        f = r.findings_by_check("GCP-IAM-006")[0]
        assert f.severity == GCPIAMSeverity.HIGH

    def test_multiple_stale_keys_produce_multiple_findings(self):
        policy = IAMPolicy(
            resource="projects/x",
            bindings=[],
            service_account_keys=[
                {"key_id": "k1", "created_at_days_ago": 100},
                {"key_id": "k2", "created_at_days_ago": 200},
            ],
        )
        r = _analyzer(max_key_age_days=90).analyze([policy])
        assert len(r.findings_by_check("GCP-IAM-006")) == 2

    def test_only_stale_key_fires_when_mixed(self):
        policy = IAMPolicy(
            resource="projects/x",
            bindings=[],
            service_account_keys=[
                {"key_id": "fresh", "created_at_days_ago": 10},
                {"key_id": "stale", "created_at_days_ago": 150},
            ],
        )
        r = _analyzer(max_key_age_days=90).analyze([policy])
        findings = r.findings_by_check("GCP-IAM-006")
        assert len(findings) == 1
        assert "stale" in findings[0].title


# ===========================================================================
# GCP-IAM-007: Overly broad IAM role
# ===========================================================================

class TestGCPIAM007:
    def test_fires_for_iam_admin(self):
        policy = _policy_with_binding("roles/iam.admin", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-007" in _check_ids(r)

    def test_fires_for_security_admin(self):
        policy = _policy_with_binding(
            "roles/iam.securityAdmin", ["user:dev@example.com"]
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-007" in _check_ids(r)

    def test_not_fired_for_role_viewer(self):
        policy = _policy_with_binding(
            "roles/iam.roleViewer", ["user:dev@example.com"]
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-007" not in _check_ids(r)

    def test_severity_is_high(self):
        policy = _policy_with_binding("roles/iam.admin", ["user:dev@example.com"])
        r = _analyzer().analyze([policy])
        f = r.findings_by_check("GCP-IAM-007")[0]
        assert f.severity == GCPIAMSeverity.HIGH

    def test_fires_once_per_member(self):
        policy = _policy_with_binding(
            "roles/iam.admin",
            ["user:a@x.com", "user:b@x.com"],
        )
        r = _analyzer().analyze([policy])
        assert len(r.findings_by_check("GCP-IAM-007")) == 2


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_policy_zero_score(self):
        r = _analyzer().analyze([_clean_policy()])
        assert r.risk_score == 0

    def test_score_positive_for_issues(self):
        policy = _policy_with_binding("roles/owner", ["user:admin@example.com"])
        r = _analyzer().analyze([policy])
        assert r.risk_score > 0

    def test_score_matches_weight_for_single_check(self):
        # Only GCP-IAM-007 fires here (custom-sa, non-primitive role).
        policy = _policy_with_binding("roles/iam.admin", ["user:x@example.com"])
        r = _analyzer().analyze([policy])
        # GCP-IAM-007 weight = 35
        assert r.risk_score == _CHECK_WEIGHTS["GCP-IAM-007"]

    def test_score_capped_at_100(self):
        # Trigger as many checks as possible to exceed 100 before capping.
        policy = IAMPolicy(
            resource="projects/worst",
            bindings=[
                IAMBinding(role="roles/owner", members=[
                    "allUsers",
                    "user:ext@external.org",
                    "serviceAccount:123-compute@developer.gserviceaccount.com",
                    "serviceAccount:svc@p.iam.gserviceaccount.com",
                ]),
                IAMBinding(role="roles/iam.admin", members=["user:hack@external.org"]),
            ],
            service_account_keys=[{"key_id": "old", "created_at_days_ago": 500}],
        )
        r = _analyzer(org_domains=["safe.com"]).analyze([policy])
        assert r.risk_score <= 100

    def test_score_not_double_counted_for_same_check(self):
        # Two bindings both firing GCP-IAM-001 should not double the weight.
        policy = IAMPolicy(
            resource="projects/x",
            bindings=[
                IAMBinding(role="roles/owner", members=["user:a@x.com"]),
                IAMBinding(role="roles/editor", members=["user:b@x.com"]),
            ],
        )
        r = _analyzer().analyze([policy])
        # GCP-IAM-001 weight = 25; only counted once.
        assert r.risk_score == _CHECK_WEIGHTS["GCP-IAM-001"]


# ===========================================================================
# Policies analyzed counter
# ===========================================================================

class TestPoliciesAnalyzed:
    def test_single_policy(self):
        r = _analyzer().analyze([_clean_policy()])
        assert r.policies_analyzed == 1

    def test_multiple_policies(self):
        policies = [_clean_policy(f"projects/proj-{i}") for i in range(5)]
        r = _analyzer().analyze(policies)
        assert r.policies_analyzed == 5

    def test_empty_list(self):
        r = _analyzer().analyze([])
        assert r.policies_analyzed == 0
        assert r.total_findings == 0
        assert r.risk_score == 0


# ===========================================================================
# Raw dict bindings accepted via IAMPolicy
# ===========================================================================

class TestRawDictBindings:
    def test_raw_dict_binding_triggers_checks(self):
        # IAMPolicy constructed manually with raw dict bindings in bindings list.
        # The analyzer normalizes them internally.
        policy = IAMPolicy(
            resource="projects/test",
            bindings=[
                {"role": "roles/owner", "members": ["user:dev@example.com"]}  # type: ignore
            ],
        )
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-001" in _check_ids(r)

    def test_from_dict_triggers_check_002(self):
        raw = {
            "bindings": [
                {"role": "roles/storage.admin", "members": ["allUsers"]}
            ]
        }
        policy = IAMPolicy.from_dict("projects/x", raw)
        r = _analyzer().analyze([policy])
        assert "GCP-IAM-002" in _check_ids(r)


# ===========================================================================
# Clean policy (zero findings)
# ===========================================================================

class TestCleanPolicy:
    def test_clean_policy_no_findings(self):
        r = _analyzer(org_domains=["example.com"]).analyze([_clean_policy()])
        assert r.total_findings == 0

    def test_clean_policy_report_summary_shows_zero(self):
        r = _analyzer().analyze([_clean_policy()])
        assert "0" in r.summary()

    def test_finding_for_resource_returns_empty_for_clean(self):
        r = _analyzer().analyze([_clean_policy("projects/clean")])
        assert r.findings_for_resource("projects/clean") == []


def _gcp_iam_export_payload() -> dict:
    return {
        "policies": [
            {
                "project_id": "prod-project",
                "policy": {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                "user:platform@example.com",
                                "user:vendor@external.test",
                                "serviceAccount:123456789-compute@developer.gserviceaccount.com",
                            ],
                        },
                        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                    ]
                },
                "service_account_keys": [
                    {
                        "key_id": "legacy-key",
                        "service_account": "deploy@prod-project.iam.gserviceaccount.com",
                        "created_at_days_ago": 181,
                    }
                ],
            }
        ]
    }


def test_gcp_iam_loader_accepts_wrapped_policy_exports(tmp_path):
    export_path = tmp_path / "gcp-iam.json"
    export_path.write_text(json.dumps(_gcp_iam_export_payload()), encoding="utf-8")

    policies = load_gcp_iam_policies_from_export(export_path)

    assert len(policies) == 1
    assert policies[0].resource == "projects/prod-project"
    assert len(policies[0].bindings) == 2
    assert policies[0].service_account_keys[0]["key_id"] == "legacy-key"


def test_scan_gcp_iam_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "gcp-iam.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_gcp_iam_export_payload()), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-gcp-iam",
            "--input",
            str(export_path),
            "--org-domain",
            "example.com",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "GCP IAM export: 1 policy snapshot(s), 8 finding(s)" in result.output
    reports = list(output_dir.glob("posture_gcp_*.md"))
    assert len(reports) == 1
    report_text = reports[0].read_text(encoding="utf-8")
    assert "Public member 'allUsers' granted role 'roles/storage.objectViewer'" in report_text
    assert "Service account key 'legacy-key' is 181 days old" in report_text
