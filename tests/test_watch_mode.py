"""Tests for diff-based watch mode on saved posture reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli
from reports.posture_report_json import save_json_report
from reports.watch_mode import (
    build_watch_notification_report,
    diff_posture_reports,
    should_alert,
)
from schemas.posture import PostureFinding, PostureReport, Provider, Severity


def _finding(
    severity: Severity,
    flag: str,
    resource_name: str,
) -> PostureFinding:
    return PostureFinding(
        provider=Provider.AWS,
        resource_type="s3_bucket",
        resource_name=resource_name,
        severity=severity,
        flag=flag,
        title=f"{resource_name} finding",
        recommendation="Restrict exposure and re-run the review.",
    )


def _report(run_id: str, findings: list[PostureFinding]) -> PostureReport:
    return PostureReport(
        run_id=run_id,
        provider=Provider.AWS,
        baseline_name="standard",
        assessed_at=datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc),
        total_resources=4,
        findings=findings,
    )


def test_diff_posture_reports_tracks_new_resolved_and_persistent_findings():
    previous = _report(
        "prev1234",
        [
            _finding(Severity.HIGH, "PUBLIC_BUCKET", "bucket-a"),
            _finding(Severity.MEDIUM, "NO_LOGGING", "bucket-b"),
        ],
    )
    current = _report(
        "curr5678",
        [
            _finding(Severity.HIGH, "PUBLIC_BUCKET", "bucket-a"),
            _finding(Severity.CRITICAL, "ROOT_KEY", "account-root"),
        ],
    )

    delta = diff_posture_reports(current, previous)

    assert [finding.flag for finding in delta.new_findings] == ["ROOT_KEY"]
    assert [finding.flag for finding in delta.resolved_findings] == ["NO_LOGGING"]
    assert [finding.flag for finding in delta.persistent_findings] == ["PUBLIC_BUCKET"]


def test_should_alert_respects_first_run_and_threshold():
    current = _report("curr5678", [_finding(Severity.HIGH, "PUBLIC_BUCKET", "bucket-a")])
    delta = diff_posture_reports(current, None)

    assert not should_alert(delta, alert_on="high", first_run=True, alert_on_first_run=False)
    assert should_alert(delta, alert_on="high", first_run=True, alert_on_first_run=True)
    assert not should_alert(delta, alert_on="critical", first_run=True, alert_on_first_run=True)


def test_build_watch_notification_report_includes_only_new_findings():
    previous = _report("prev1234", [_finding(Severity.HIGH, "PUBLIC_BUCKET", "bucket-a")])
    current = _report(
        "curr5678",
        [
            _finding(Severity.HIGH, "PUBLIC_BUCKET", "bucket-a"),
            _finding(Severity.CRITICAL, "ROOT_KEY", "account-root"),
        ],
    )

    delta = diff_posture_reports(current, previous)
    watch_report = build_watch_notification_report(current, delta)

    assert watch_report.run_id == "curr5678"
    assert [finding.flag for finding in watch_report.findings] == ["ROOT_KEY"]


def test_watch_report_uses_state_file_and_prints_dry_run_payload(tmp_path):
    previous_path = save_json_report(
        _report("prev1234", [_finding(Severity.LOW, "LOW_FLAG", "bucket-old")]),
        tmp_path / "seed",
    )
    current_path = save_json_report(
        _report(
            "curr5678",
            [
                _finding(Severity.LOW, "LOW_FLAG", "bucket-old"),
                _finding(Severity.CRITICAL, "ROOT_KEY", "account-root"),
            ],
        ),
        tmp_path / "current",
    )
    state_path = tmp_path / "watch-state.json"
    state_path.write_text(previous_path.read_text(encoding="utf-8"), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "watch-report",
            "--input",
            str(current_path),
            "--state-file",
            str(state_path),
            "--alert-on",
            "high",
            "--target",
            "slack",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "new=1 resolved=0 persistent=1" in result.output
    assert "Compared against previous run: prev1234" in result.output
    assert "ROOT_KEY" in result.output
    assert "\"text\": \"AWS posture run curr5678" in result.output
    saved_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved_state["run_id"] == "curr5678"


def test_watch_report_initializes_state_without_alerting_by_default(tmp_path):
    current_path = save_json_report(
        _report("curr5678", [_finding(Severity.CRITICAL, "ROOT_KEY", "account-root")]),
        tmp_path / "current",
    )
    state_path = tmp_path / "watch-state.json"

    result = CliRunner().invoke(
        cli,
        [
            "watch-report",
            "--input",
            str(current_path),
            "--state-file",
            str(state_path),
            "--alert-on",
            "high",
            "--target",
            "teams",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Compared against previous run: none" in result.output
    assert "Alert status: no new findings met the configured threshold." in result.output
    assert Path(state_path).exists()
