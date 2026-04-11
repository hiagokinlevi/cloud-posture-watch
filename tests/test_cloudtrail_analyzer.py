"""
Tests for analyzers/cloudtrail_analyzer.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.cloudtrail_analyzer import (
    CloudTrailAnalyzer,
    CloudTrailReport,
    TrailFinding,
    TrailPosture,
    TrailSeverity,
    _get,
    load_cloudtrail_export,
    load_cloudtrail_export_dict,
)
from cli.main import cli


# ===========================================================================
# Fixtures / helpers
# ===========================================================================

def _perfect_trail(name: str = "my-trail") -> dict:
    """A trail config with zero findings (all checks pass)."""
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{name}",
        "IsMultiRegionTrail": True,
        "IncludeGlobalServiceEvents": True,
        "LogFileValidationEnabled": True,
        "KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc123",
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail",
        "S3MfaDeleteEnabled": True,
        "ManagementEventsEnabled": True,
    }


def _perfect_status(is_logging: bool = True) -> dict:
    return {"IsLogging": is_logging}


def _worst_trail(name: str = "bad-trail") -> dict:
    """A trail config that triggers every check."""
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{name}",
        "IsMultiRegionTrail": False,
        "IncludeGlobalServiceEvents": False,
        "LogFileValidationEnabled": False,
        "KMSKeyId": None,
        "CloudWatchLogsLogGroupArn": None,
        "S3MfaDeleteEnabled": False,
        "ManagementEventsEnabled": False,
        "IsLogging": False,
    }


# ===========================================================================
# _get helper
# ===========================================================================

class TestGet:
    def test_first_key_wins(self):
        assert _get({"a": 1, "b": 2}, "a", "b") == 1

    def test_fallback_to_second_key(self):
        assert _get({"b": 2}, "a", "b") == 2

    def test_returns_default_when_no_match(self):
        assert _get({}, "x", default="fallback") == "fallback"

    def test_default_none(self):
        assert _get({}, "x") is None

    def test_false_value_returned(self):
        assert _get({"a": False}, "a", default=True) is False

    def test_zero_value_returned(self):
        assert _get({"a": 0}, "a", default=99) == 0


# ===========================================================================
# Export loaders
# ===========================================================================

class TestCloudTrailExportLoaders:
    def test_load_cloudtrail_export_dict_accepts_wrapped_trails_and_status_map(self):
        bad_trail = _worst_trail("bad-trail")
        bad_trail.pop("IsLogging")
        payload = {
            "results": {
                "trailList": [_perfect_trail("good-trail"), bad_trail],
            },
            "status_map": {
                "bad-trail": {"IsLogging": False},
            },
        }

        trails, status_map = load_cloudtrail_export_dict(payload)

        assert len(trails) == 2
        assert trails[0]["Name"] == "good-trail"
        assert status_map["bad-trail"]["IsLogging"] is False

    def test_load_cloudtrail_export_accepts_status_list(self, tmp_path):
        export_path = tmp_path / "cloudtrail.json"
        export_path.write_text(
            json.dumps(
                {
                    "trailList": [_perfect_trail("ops-trail")],
                    "trail_statuses": [{"Name": "ops-trail", "IsLogging": False}],
                }
            ),
            encoding="utf-8",
        )

        trails, status_map = load_cloudtrail_export(export_path)

        assert len(trails) == 1
        assert status_map["ops-trail"]["IsLogging"] is False


# ===========================================================================
# TrailFinding
# ===========================================================================

class TestTrailFinding:
    def _f(self) -> TrailFinding:
        return TrailFinding(
            check_id="CT-001",
            severity=TrailSeverity.CRITICAL,
            title="Trail not logging",
            detail="Detail text",
            remediation="Fix it",
            trail_name="my-trail",
            trail_arn="arn:aws:...",
        )

    def test_to_dict_has_required_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "title", "detail", "remediation", "trail_name", "trail_arn"):
            assert k in d

    def test_severity_serialized_as_string(self):
        d = self._f().to_dict()
        assert d["severity"] == "CRITICAL"


# ===========================================================================
# TrailPosture
# ===========================================================================

class TestTrailPosture:
    def _posture(self) -> TrailPosture:
        f_critical = TrailFinding("CT-001", TrailSeverity.CRITICAL, "t", "d", "r", "trail")
        f_high     = TrailFinding("CT-002", TrailSeverity.HIGH,     "t", "d", "r", "trail")
        f_medium   = TrailFinding("CT-003", TrailSeverity.MEDIUM,   "t", "d", "r", "trail")
        return TrailPosture(
            trail_name="trail",
            trail_arn="arn",
            is_logging=False,
            multi_region=False,
            findings=[f_critical, f_high, f_medium],
            risk_score=55,
        )

    def test_finding_count(self):
        assert self._posture().finding_count == 3

    def test_critical_count(self):
        assert self._posture().critical_count == 1

    def test_high_count(self):
        assert self._posture().high_count == 1

    def test_risk_summary_contains_name(self):
        assert "trail" in self._posture().risk_summary()

    def test_risk_summary_contains_score(self):
        assert "55" in self._posture().risk_summary()

    def test_to_dict_has_keys(self):
        d = self._posture().to_dict()
        for k in ("trail_name", "trail_arn", "is_logging", "risk_score", "findings"):
            assert k in d

    def test_to_dict_findings_is_list(self):
        d = self._posture().to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 3


# ===========================================================================
# CloudTrailReport
# ===========================================================================

class TestCloudTrailReport:
    def _report(self) -> CloudTrailReport:
        f1 = TrailFinding("CT-001", TrailSeverity.CRITICAL, "t", "d", "r", "t1")
        f2 = TrailFinding("CT-002", TrailSeverity.HIGH,     "t", "d", "r", "t1")
        f3 = TrailFinding("CT-003", TrailSeverity.MEDIUM,   "t", "d", "r", "t2")
        p1 = TrailPosture("t1", is_logging=False, findings=[f1, f2], risk_score=45)
        p2 = TrailPosture("t2", is_logging=True,  findings=[f3],     risk_score=10)
        return CloudTrailReport(
            trail_postures=[p1, p2],
            total_trails=2,
            trails_disabled=1,
            all_findings=[f1, f2, f3],
        )

    def test_total_findings(self):
        assert self._report().total_findings == 3

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check(self):
        fs = self._report().findings_by_check("CT-001")
        assert len(fs) == 1 and fs[0].check_id == "CT-001"

    def test_findings_by_severity(self):
        fs = self._report().findings_by_severity(TrailSeverity.MEDIUM)
        assert len(fs) == 1

    def test_summary_contains_trail_count(self):
        assert "2" in self._report().summary()

    def test_summary_contains_disabled_count(self):
        assert "1" in self._report().summary()

    def test_empty_report(self):
        r = CloudTrailReport()
        assert r.total_findings == 0
        assert r.total_trails == 0


# ===========================================================================
# CloudTrailAnalyzer — perfect trail (no findings)
# ===========================================================================

class TestPerfectTrail:
    def test_no_findings_for_perfect_trail(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert posture.finding_count == 0

    def test_risk_score_zero_for_perfect_trail(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert posture.risk_score == 0

    def test_trail_name_preserved(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail("prod-trail"), _perfect_status())
        assert posture.trail_name == "prod-trail"

    def test_trail_arn_preserved(self):
        analyzer = CloudTrailAnalyzer()
        trail = _perfect_trail("prod-trail")
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert "prod-trail" in posture.trail_arn


# ===========================================================================
# CT-001: Trail disabled
# ===========================================================================

class TestCT001:
    def test_ct001_fires_when_not_logging(self):
        analyzer = CloudTrailAnalyzer()
        trail = _perfect_trail()
        status = {"IsLogging": False}
        posture = analyzer.analyze_trail_config(trail, status)
        check_ids = [f.check_id for f in posture.findings]
        assert "CT-001" in check_ids

    def test_ct001_is_critical(self):
        analyzer = CloudTrailAnalyzer()
        trail = _perfect_trail()
        status = {"IsLogging": False}
        posture = analyzer.analyze_trail_config(trail, status)
        f = next(f for f in posture.findings if f.check_id == "CT-001")
        assert f.severity == TrailSeverity.CRITICAL

    def test_ct001_not_fired_when_logging(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status(True))
        assert not any(f.check_id == "CT-001" for f in posture.findings)

    def test_ct001_is_logging_from_config(self):
        """IsLogging can be embedded in config itself."""
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IsLogging": False}
        posture = analyzer.analyze_trail_config(trail)
        assert any(f.check_id == "CT-001" for f in posture.findings)


# ===========================================================================
# CT-002: Log file validation
# ===========================================================================

class TestCT002:
    def test_ct002_fires_when_validation_disabled(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "LogFileValidationEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-002" for f in posture.findings)

    def test_ct002_is_high(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "LogFileValidationEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-002")
        assert f.severity == TrailSeverity.HIGH

    def test_ct002_not_fired_when_enabled(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-002" for f in posture.findings)

    def test_ct002_fires_when_key_absent(self):
        """Missing key defaults to False → should fire."""
        analyzer = CloudTrailAnalyzer()
        trail = {k: v for k, v in _perfect_trail().items()
                 if k != "LogFileValidationEnabled"}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-002" for f in posture.findings)


# ===========================================================================
# CT-003: Single-region
# ===========================================================================

class TestCT003:
    def test_ct003_fires_for_single_region(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IsMultiRegionTrail": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-003" for f in posture.findings)

    def test_ct003_is_medium(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IsMultiRegionTrail": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-003")
        assert f.severity == TrailSeverity.MEDIUM

    def test_ct003_not_fired_for_multi_region(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-003" for f in posture.findings)


# ===========================================================================
# CT-004: Global service events
# ===========================================================================

class TestCT004:
    def test_ct004_fires_when_global_excluded(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IncludeGlobalServiceEvents": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-004" for f in posture.findings)

    def test_ct004_is_high(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IncludeGlobalServiceEvents": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-004")
        assert f.severity == TrailSeverity.HIGH

    def test_ct004_not_fired_when_included(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-004" for f in posture.findings)


# ===========================================================================
# CT-005: MFA delete
# ===========================================================================

class TestCT005:
    def test_ct005_fires_when_mfa_delete_false(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "S3MfaDeleteEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-005" for f in posture.findings)

    def test_ct005_is_high(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "S3MfaDeleteEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-005")
        assert f.severity == TrailSeverity.HIGH

    def test_ct005_not_fired_when_true(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-005" for f in posture.findings)

    def test_ct005_not_fired_when_key_absent(self):
        """Missing key → default None → check skipped (can't verify)."""
        analyzer = CloudTrailAnalyzer()
        trail = {k: v for k, v in _perfect_trail().items()
                 if k != "S3MfaDeleteEnabled"}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert not any(f.check_id == "CT-005" for f in posture.findings)


# ===========================================================================
# CT-006: KMS encryption
# ===========================================================================

class TestCT006:
    def test_ct006_fires_when_no_kms(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "KMSKeyId": None}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-006" for f in posture.findings)

    def test_ct006_fires_when_key_absent(self):
        analyzer = CloudTrailAnalyzer()
        trail = {k: v for k, v in _perfect_trail().items() if k != "KMSKeyId"}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-006" for f in posture.findings)

    def test_ct006_is_medium(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "KMSKeyId": None}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-006")
        assert f.severity == TrailSeverity.MEDIUM

    def test_ct006_not_fired_when_kms_set(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-006" for f in posture.findings)


# ===========================================================================
# CT-007: CloudWatch Logs
# ===========================================================================

class TestCT007:
    def test_ct007_fires_when_no_cw(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "CloudWatchLogsLogGroupArn": None}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-007" for f in posture.findings)

    def test_ct007_fires_when_key_absent(self):
        analyzer = CloudTrailAnalyzer()
        trail = {k: v for k, v in _perfect_trail().items()
                 if k != "CloudWatchLogsLogGroupArn"}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-007" for f in posture.findings)

    def test_ct007_is_medium(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "CloudWatchLogsLogGroupArn": None}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-007")
        assert f.severity == TrailSeverity.MEDIUM

    def test_ct007_not_fired_when_configured(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-007" for f in posture.findings)


# ===========================================================================
# CT-008: Management events
# ===========================================================================

class TestCT008:
    def test_ct008_fires_when_disabled(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "ManagementEventsEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert any(f.check_id == "CT-008" for f in posture.findings)

    def test_ct008_is_critical(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "ManagementEventsEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-008")
        assert f.severity == TrailSeverity.CRITICAL

    def test_ct008_not_fired_when_enabled(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_perfect_trail(), _perfect_status())
        assert not any(f.check_id == "CT-008" for f in posture.findings)

    def test_ct008_not_fired_when_key_absent(self):
        """Missing key defaults to True → management events assumed present."""
        analyzer = CloudTrailAnalyzer()
        trail = {k: v for k, v in _perfect_trail().items()
                 if k != "ManagementEventsEnabled"}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert not any(f.check_id == "CT-008" for f in posture.findings)


# ===========================================================================
# Worst-case trail (all checks fire)
# ===========================================================================

class TestWorstTrail:
    def test_all_checks_fire(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_worst_trail())
        check_ids = {f.check_id for f in posture.findings}
        for cid in ("CT-001", "CT-002", "CT-003", "CT-004", "CT-005",
                    "CT-006", "CT-007", "CT-008"):
            assert cid in check_ids, f"{cid} did not fire"

    def test_risk_score_capped_at_100(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_worst_trail())
        assert posture.risk_score <= 100

    def test_worst_trail_risk_score_equals_sum_of_weights(self):
        # CT-001=30 + CT-002=15 + CT-003=10 + CT-004=10 + CT-005=15 + CT-006=5 +
        # CT-007=10 + CT-008=20 = 115 → capped at 100
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_worst_trail())
        assert posture.risk_score == 100

    def test_critical_count_is_two(self):
        analyzer = CloudTrailAnalyzer()
        posture = analyzer.analyze_trail_config(_worst_trail())
        assert posture.critical_count == 2


# ===========================================================================
# Risk score calculation
# ===========================================================================

class TestRiskScore:
    def test_only_ct001_score_is_30(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "IsLogging": False}
        posture = analyzer.analyze_trail_config(trail, {})
        ct001_findings = [f for f in posture.findings if f.check_id == "CT-001"]
        assert any(f.check_id == "CT-001" for f in posture.findings)
        # Risk score = 30 (CT-001 weight only, if all others pass)
        assert posture.risk_score == 30

    def test_only_ct008_score_is_20(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(), "ManagementEventsEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        assert posture.risk_score == 20

    def test_two_checks_additive(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail(),
                 "LogFileValidationEnabled": False,
                 "CloudWatchLogsLogGroupArn": None}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        # CT-002=15 + CT-007=10 = 25
        assert posture.risk_score == 25


# ===========================================================================
# Snake_case key support
# ===========================================================================

class TestSnakeCaseKeys:
    def test_snake_case_name(self):
        analyzer = CloudTrailAnalyzer()
        trail = {
            "name": "snake-trail",
            "trail_arn": "arn:aws:...",
            "is_multi_region_trail": True,
            "include_global_service_events": True,
            "log_file_validation_enabled": True,
            "kms_key_id": "arn:kms:...",
            "cloud_watch_logs_log_group_arn": "arn:logs:...",
            "s3_mfa_delete_enabled": True,
            "management_events_enabled": True,
        }
        status = {"is_logging": True}
        posture = analyzer.analyze_trail_config(trail, status)
        assert posture.trail_name == "snake-trail"
        assert posture.finding_count == 0


# ===========================================================================
# analyze_trails and build_report
# ===========================================================================

class TestAnalyzeTrailsAndReport:
    def test_analyze_multiple_trails(self):
        analyzer = CloudTrailAnalyzer()
        trails = [_perfect_trail("t1"), _perfect_trail("t2")]
        postures = analyzer.analyze_trails(trails)
        assert len(postures) == 2

    def test_analyze_trails_uses_status_map(self):
        analyzer = CloudTrailAnalyzer()
        trails = [_perfect_trail("t1")]
        status_map = {"t1": {"IsLogging": False}}
        postures = analyzer.analyze_trails(trails, status_map)
        assert any(f.check_id == "CT-001" for f in postures[0].findings)

    def test_build_report_counts_trails(self):
        analyzer = CloudTrailAnalyzer()
        postures = analyzer.analyze_trails([_perfect_trail("t1"), _worst_trail("t2")])
        report = analyzer.build_report(postures)
        assert report.total_trails == 2

    def test_build_report_counts_disabled(self):
        analyzer = CloudTrailAnalyzer()
        trails = [_perfect_trail("t1"), _worst_trail("t2")]
        postures = analyzer.analyze_trails(trails)
        report = analyzer.build_report(postures)
        assert report.trails_disabled == 1  # worst_trail has IsLogging=False

    def test_build_report_aggregates_findings(self):
        analyzer = CloudTrailAnalyzer()
        postures = analyzer.analyze_trails([_perfect_trail("t1"), _worst_trail("t2")])
        report = analyzer.build_report(postures)
        # perfect has 0 findings, worst has 8 → total 8
        assert report.total_findings == 8

    def test_build_report_findings_by_check(self):
        analyzer = CloudTrailAnalyzer()
        # Two worst trails → 2 CT-001 findings
        postures = analyzer.analyze_trails([_worst_trail("t1"), _worst_trail("t2")])
        report = analyzer.build_report(postures)
        ct001 = report.findings_by_check("CT-001")
        assert len(ct001) == 2

    def test_empty_trails_list(self):
        analyzer = CloudTrailAnalyzer()
        report = analyzer.build_report(analyzer.analyze_trails([]))
        assert report.total_trails == 0
        assert report.total_findings == 0

    def test_report_summary_str(self):
        analyzer = CloudTrailAnalyzer()
        postures = analyzer.analyze_trails([_worst_trail()])
        report = analyzer.build_report(postures)
        s = report.summary()
        assert "1" in s  # 1 trail


# ===========================================================================
# Finding trail_name and trail_arn propagation
# ===========================================================================

class TestFindingPropagation:
    def test_trail_name_in_findings(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail("named-trail"), "LogFileValidationEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-002")
        assert f.trail_name == "named-trail"

    def test_trail_arn_in_findings(self):
        analyzer = CloudTrailAnalyzer()
        trail = {**_perfect_trail("named-trail"), "LogFileValidationEnabled": False}
        posture = analyzer.analyze_trail_config(trail, _perfect_status())
        f = next(f for f in posture.findings if f.check_id == "CT-002")
        assert "named-trail" in f.trail_arn


def test_scan_aws_cloudtrail_cli_writes_report_and_gates(tmp_path):
    bad_trail = _worst_trail("bad-trail")
    bad_trail.pop("IsLogging")
    export_path = tmp_path / "cloudtrail.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(
        json.dumps(
            {
                "trailList": [_perfect_trail("good-trail"), bad_trail],
                "status_map": {"bad-trail": {"IsLogging": False}},
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-aws-cloudtrail",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "AWS CloudTrail export: 2 trail(s), 1 disabled, 8 finding(s)" in result.output
    reports = list(output_dir.glob("posture_aws_*.md"))
    assert len(reports) == 1
    report_text = reports[0].read_text(encoding="utf-8")
    assert "CloudTrail trail is not logging" in report_text
    assert "Global service events not included" in report_text
