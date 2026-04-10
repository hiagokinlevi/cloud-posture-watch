"""Tests for Slack and Teams webhook notification payloads."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from click.testing import CliRunner

from cli.main import cli
from reports.posture_report_json import save_json_report
from reports.webhook_notifications import build_webhook_payload
from schemas.posture import PostureFinding, PostureReport, Provider, Severity


def _finding(severity: Severity, flag: str, resource_name: str) -> PostureFinding:
    return PostureFinding(
        provider=Provider.AWS,
        resource_type="s3_bucket",
        resource_name=resource_name,
        severity=severity,
        flag=flag,
        title=f"{resource_name} posture finding",
        recommendation="Restrict access and re-run the posture review.",
    )


def _report() -> PostureReport:
    return PostureReport(
        run_id="notify123",
        provider=Provider.AWS,
        baseline_name="standard",
        assessed_at=datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc),
        total_resources=4,
        findings=[
            _finding(Severity.LOW, "LOW_FLAG", "bucket-low"),
            _finding(Severity.CRITICAL, "CRITICAL_FLAG", "bucket-critical"),
            _finding(Severity.HIGH, "HIGH_FLAG", "bucket-high"),
        ],
    )


def test_build_slack_payload_summarizes_counts_and_orders_top_findings():
    payload = build_webhook_payload(_report(), target="slack", dashboard_url="https://example.com/report")

    assert payload["text"].startswith("AWS posture run notify123")
    assert "CRITICAL=1 HIGH=1 MEDIUM=0 LOW=1" in payload["text"]
    block_texts = [block["text"]["text"] for block in payload["blocks"] if "text" in block]
    assert any("Report: https://example.com/report" in text for text in block_texts)
    assert "CRITICAL CRITICAL_FLAG" in block_texts[2]


def test_build_teams_payload_uses_message_card_format():
    payload = build_webhook_payload(_report(), target="teams")

    assert payload["@type"] == "MessageCard"
    assert payload["title"] == "AWS posture findings"
    assert payload["themeColor"] == "B00020"
    fact_names = [fact["name"] for fact in payload["sections"][0]["facts"]]
    assert "CRITICAL CRITICAL_FLAG" in fact_names


def test_notify_webhook_dry_run_prints_payload(tmp_path):
    input_path = save_json_report(_report(), tmp_path)
    result = CliRunner().invoke(
        cli,
        [
            "notify-webhook",
            "--input",
            str(input_path),
            "--target",
            "slack",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["text"].startswith("AWS posture run notify123")


def test_notify_webhook_requires_url_when_not_dry_run(tmp_path):
    input_path = save_json_report(_report(), tmp_path)
    result = CliRunner().invoke(
        cli,
        ["notify-webhook", "--input", str(input_path), "--target", "teams"],
    )

    assert result.exit_code == 2
    assert "Provide --webhook-url" in result.output


def test_notify_webhook_does_not_print_webhook_url_on_success(monkeypatch, tmp_path):
    input_path = save_json_report(_report(), tmp_path)
    captured: dict[str, object] = {}

    def fake_send(webhook_url, payload, timeout_seconds=10):
        captured["webhook_url"] = webhook_url
        captured["payload"] = payload
        captured["timeout_seconds"] = timeout_seconds
        return 204

    monkeypatch.setattr("reports.webhook_notifications.send_webhook_payload", fake_send)
    secret_url = "https://hooks.slack.com/services/T000/B000/secret"
    result = CliRunner().invoke(
        cli,
        [
            "notify-webhook",
            "--input",
            str(input_path),
            "--target",
            "slack",
            "--webhook-url",
            secret_url,
            "--timeout",
            "3",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "HTTP 204" in result.output
    assert secret_url not in result.output
    assert captured["webhook_url"] == secret_url
    assert captured["timeout_seconds"] == 3
