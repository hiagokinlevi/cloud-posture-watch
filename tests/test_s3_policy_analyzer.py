"""
Tests for analyzers/s3_policy_analyzer.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.s3_policy_analyzer import (
    BucketConfig,
    S3Finding,
    S3PolicyAnalyzer,
    S3PolicyReport,
    S3Severity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _analyzer(**kwargs) -> S3PolicyAnalyzer:
    return S3PolicyAnalyzer(**kwargs)


def _check_ids(report: S3PolicyReport) -> set[str]:
    return {f.check_id for f in report.findings}


def _clean_bucket(name: str = "my-bucket") -> BucketConfig:
    """A bucket with the recommended deny-enc + deny-tls + logging + versioning."""
    return BucketConfig(
        name=name,
        policy={
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{name}/*",
                    "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}},
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{name}/*",
                    "Condition": {"Bool": {"aws:SecureTransport": False}},
                },
            ]
        },
        acl_grants=[],
        versioning_enabled=True,
        logging_enabled=True,
        account_id="123456789012",
    )


# ===========================================================================
# S3Finding
# ===========================================================================

class TestS3Finding:
    def _f(self) -> S3Finding:
        return S3Finding(
            check_id="S3-PUB-001",
            severity=S3Severity.CRITICAL,
            bucket="my-bucket",
            title="Public access",
            detail="Details here",
            evidence="Principal=*",
            remediation="Fix it",
        )

    def test_to_dict_has_required_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "bucket", "title",
                  "detail", "evidence", "remediation"):
            assert k in d

    def test_severity_as_string(self):
        assert self._f().to_dict()["severity"] == "CRITICAL"

    def test_summary_contains_check_id(self):
        assert "S3-PUB-001" in self._f().summary()

    def test_evidence_truncated_to_512(self):
        f = S3Finding("S3-PUB-001", S3Severity.LOW, "b", "t", "d", evidence="x" * 600)
        assert len(f.to_dict()["evidence"]) == 512


# ===========================================================================
# S3PolicyReport
# ===========================================================================

class TestS3PolicyReport:
    def _report(self) -> S3PolicyReport:
        f1 = S3Finding("S3-PUB-001", S3Severity.CRITICAL, "b", "t", "d")
        f2 = S3Finding("S3-LOG-001", S3Severity.MEDIUM, "b", "t", "d")
        return S3PolicyReport(findings=[f1, f2], risk_score=65)

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 0

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("S3-PUB-001")) == 1

    def test_findings_for_bucket(self):
        assert len(self._report().findings_for_bucket("b")) == 2

    def test_summary_contains_risk_score(self):
        assert "65" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for k in ("total_findings", "risk_score", "critical", "high",
                  "generated_at", "findings"):
            assert k in d

    def test_empty_report(self):
        r = S3PolicyReport()
        assert r.total_findings == 0


# ===========================================================================
# S3-PUB-001: Public policy
# ===========================================================================

class TestS3PUB001:
    def test_fires_for_principal_star(self):
        config = BucketConfig(
            name="pub",
            policy={"Statement": [{"Effect": "Allow", "Principal": "*",
                                   "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::pub/*"}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-PUB-001" in _check_ids(r)

    def test_fires_for_aws_star(self):
        config = BucketConfig(
            name="pub",
            policy={"Statement": [{"Effect": "Allow",
                                   "Principal": {"AWS": "*"},
                                   "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::pub/*"}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-PUB-001" in _check_ids(r)

    def test_not_fired_for_deny_statement(self):
        config = BucketConfig(
            name="safe",
            policy={"Statement": [{"Effect": "Deny", "Principal": "*",
                                   "Action": "s3:PutObject",
                                   "Resource": "arn:aws:s3:::safe/*",
                                   "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-PUB-001" not in _check_ids(r)

    def test_not_fired_for_specific_principal(self):
        config = BucketConfig(
            name="safe",
            policy={"Statement": [{"Effect": "Allow",
                                   "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                                   "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::safe/*"}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-PUB-001" not in _check_ids(r)

    def test_severity_critical_for_dangerous_action(self):
        config = BucketConfig(
            name="pub",
            policy={"Statement": [{"Effect": "Allow", "Principal": "*",
                                   "Action": "s3:PutObject",
                                   "Resource": "arn:aws:s3:::pub/*"}]},
        )
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-PUB-001")
        assert f.severity == S3Severity.CRITICAL

    def test_severity_high_for_get_object(self):
        config = BucketConfig(
            name="pub",
            policy={"Statement": [{"Effect": "Allow", "Principal": "*",
                                   "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::pub/*"}]},
        )
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-PUB-001")
        assert f.severity == S3Severity.HIGH


# ===========================================================================
# S3-PUB-002: ACL public
# ===========================================================================

class TestS3PUB002:
    def _public_read_grant(self) -> dict:
        return {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
            },
            "Permission": "READ",
        }

    def test_fires_for_all_users_read(self):
        config = BucketConfig(name="pub", acl_grants=[self._public_read_grant()])
        r = _analyzer().analyze(config)
        assert "S3-PUB-002" in _check_ids(r)

    def test_fires_for_full_control(self):
        grant = {
            "Grantee": {"Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "FULL_CONTROL",
        }
        config = BucketConfig(name="pub", acl_grants=[grant])
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-PUB-002")
        assert f.severity == S3Severity.CRITICAL

    def test_not_fired_for_private_acl(self):
        grant = {
            "Grantee": {"Type": "CanonicalUser", "ID": "abc123"},
            "Permission": "FULL_CONTROL",
        }
        config = BucketConfig(name="priv", acl_grants=[grant])
        r = _analyzer().analyze(config)
        assert "S3-PUB-002" not in _check_ids(r)

    def test_not_fired_for_empty_acl(self):
        config = BucketConfig(name="empty", acl_grants=[])
        r = _analyzer().analyze(config)
        assert "S3-PUB-002" not in _check_ids(r)


# ===========================================================================
# S3-XACCT-001: Cross-account
# ===========================================================================

class TestS3XACCT001:
    def test_fires_for_cross_account_with_dangerous_action(self):
        config = BucketConfig(
            name="bucket",
            account_id="111111111111",
            policy={"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-XACCT-001" in _check_ids(r)

    def test_not_fired_for_same_account(self):
        config = BucketConfig(
            name="bucket",
            account_id="123456789012",
            policy={"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-XACCT-001" not in _check_ids(r)

    def test_not_fired_when_no_account_id_set(self):
        config = BucketConfig(
            name="bucket",
            account_id="",  # unknown owner
            policy={"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-XACCT-001" not in _check_ids(r)

    def test_not_fired_for_cross_account_read_only(self):
        config = BucketConfig(
            name="bucket",
            account_id="111111111111",
            policy={"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-XACCT-001" not in _check_ids(r)


# ===========================================================================
# S3-ENC-001: Encryption enforcement
# ===========================================================================

class TestS3ENC001:
    def test_fires_when_no_deny_enc_statement(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/R"},
                                   "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-ENC-001" in _check_ids(r)

    def test_not_fired_when_deny_enc_present(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}},
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-ENC-001" not in _check_ids(r)

    def test_severity_is_medium(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/R"},
                                   "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]},
        )
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-ENC-001")
        assert f.severity == S3Severity.MEDIUM


# ===========================================================================
# S3-TLS-001: TLS enforcement
# ===========================================================================

class TestS3TLS001:
    def test_fires_when_no_deny_tls(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/R"},
                                   "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]},
        )
        r = _analyzer().analyze(config)
        assert "S3-TLS-001" in _check_ids(r)

    def test_not_fired_when_deny_tls_present(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {"Bool": {"aws:SecureTransport": False}},
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-TLS-001" not in _check_ids(r)

    def test_not_fired_when_deny_tls_string_false(self):
        config = BucketConfig(
            name="bucket",
            policy={"Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }]},
        )
        r = _analyzer().analyze(config)
        assert "S3-TLS-001" not in _check_ids(r)


# ===========================================================================
# S3-LOG-001: Logging
# ===========================================================================

class TestS3LOG001:
    def test_fires_when_no_logging(self):
        config = BucketConfig(name="bucket", policy=None, logging_enabled=False)
        r = _analyzer().analyze(config)
        assert "S3-LOG-001" in _check_ids(r)

    def test_not_fired_when_logging_enabled(self):
        config = BucketConfig(name="bucket", policy=None, logging_enabled=True)
        r = _analyzer().analyze(config)
        assert "S3-LOG-001" not in _check_ids(r)

    def test_severity_is_medium(self):
        config = BucketConfig(name="bucket", policy=None, logging_enabled=False)
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-LOG-001")
        assert f.severity == S3Severity.MEDIUM

    def test_flag_off_disables_check(self):
        config = BucketConfig(name="bucket", policy=None, logging_enabled=False)
        r = S3PolicyAnalyzer(check_logging=False).analyze(config)
        assert "S3-LOG-001" not in _check_ids(r)


# ===========================================================================
# S3-VERS-001: Versioning
# ===========================================================================

class TestS3VERS001:
    def test_fires_when_versioning_disabled(self):
        config = BucketConfig(name="bucket", policy=None, versioning_enabled=False)
        r = _analyzer().analyze(config)
        assert "S3-VERS-001" in _check_ids(r)

    def test_not_fired_when_versioning_enabled(self):
        config = BucketConfig(name="bucket", policy=None, versioning_enabled=True)
        r = _analyzer().analyze(config)
        assert "S3-VERS-001" not in _check_ids(r)

    def test_severity_is_low(self):
        config = BucketConfig(name="bucket", policy=None, versioning_enabled=False)
        r = _analyzer().analyze(config)
        f = next(f for f in r.findings if f.check_id == "S3-VERS-001")
        assert f.severity == S3Severity.LOW

    def test_flag_off_disables_check(self):
        config = BucketConfig(name="bucket", policy=None, versioning_enabled=False)
        r = S3PolicyAnalyzer(check_versioning=False).analyze(config)
        assert "S3-VERS-001" not in _check_ids(r)


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_bucket_zero_score(self):
        r = _analyzer().analyze(_clean_bucket())
        assert r.risk_score == 0

    def test_score_positive_for_issues(self):
        config = BucketConfig(
            name="bad",
            policy={"Statement": [{"Effect": "Allow", "Principal": "*",
                                   "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::bad/*"}]},
            logging_enabled=False,
            versioning_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert r.risk_score > 0

    def test_score_capped_at_100(self):
        config = BucketConfig(
            name="worst",
            policy={"Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:*",
                 "Resource": "arn:aws:s3:::worst/*"},
            ]},
            acl_grants=[{
                "Grantee": {"Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "FULL_CONTROL",
            }],
            versioning_enabled=False,
            logging_enabled=False,
        )
        r = _analyzer().analyze(config)
        assert r.risk_score <= 100


# ===========================================================================
# analyze_many
# ===========================================================================

class TestAnalyzeMany:
    def test_combines_findings_from_multiple_buckets(self):
        configs = [
            BucketConfig(name="a", policy={"Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::a/*"}]}, logging_enabled=True),
            BucketConfig(name="b", policy=None, logging_enabled=False),
        ]
        r = _analyzer().analyze_many(configs)
        buckets = {f.bucket for f in r.findings}
        assert "a" in buckets
        assert "b" in buckets

    def test_empty_list_returns_empty_report(self):
        r = _analyzer().analyze_many([])
        assert r.total_findings == 0
