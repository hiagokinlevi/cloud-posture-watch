"""Tests for offline GCP firewall export scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.network_exposure import analyze_network_exposure
from cli.main import cli
from providers.gcp.network_collector import load_firewall_rules_from_export


def _export_payload() -> list[dict]:
    return [
        {
            "id": "12345",
            "name": "allow-ssh-public",
            "network": "global/networks/prod",
            "direction": "INGRESS",
            "priority": 1000,
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        },
        {
            "id": "67890",
            "name": "allow-web-public",
            "network": "global/networks/prod",
            "direction": "INGRESS",
            "sourceRanges": ["10.0.0.0/8", "::/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}],
        },
        {
            "id": "deny-db-public",
            "name": "deny-db-public",
            "direction": "INGRESS",
            "sourceRanges": ["0.0.0.0/0"],
            "denied": [{"IPProtocol": "tcp", "ports": ["5432"]}],
        },
    ]


def test_load_firewall_rules_from_gcloud_export(tmp_path):
    export_path = tmp_path / "firewalls.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    firewalls = load_firewall_rules_from_export(export_path)

    assert len(firewalls) == 3
    assert firewalls[0].resource_name == "allow-ssh-public"
    assert firewalls[0].inbound_rules[0].protocol == "tcp"
    assert firewalls[0].inbound_rules[0].from_port == 22
    assert firewalls[1].inbound_rules[0].cidr_ranges == ["10.0.0.0/8", "::/0"]
    assert firewalls[2].inbound_rules == []


def test_loaded_export_feeds_network_analyzer(tmp_path):
    export_path = tmp_path / "firewalls.json"
    export_path.write_text(json.dumps({"items": _export_payload()}), encoding="utf-8")

    findings = analyze_network_exposure(
        load_firewall_rules_from_export(export_path),
        provider="gcp",
        resource_type="firewall_rule",
    )

    assert [finding.rule_id for finding in findings][:3] == ["NET002", "NET005", "NET005"]
    assert findings[0].resource_name == "allow-ssh-public"
    assert all("deny-db-public" not in finding.resource_name for finding in findings)


def test_scan_gcp_firewalls_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "firewalls.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-gcp-firewalls",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "GCP firewall export: 3 rule(s), 3 finding(s)" in result.output
    reports = list(output_dir.glob("posture_gcp_*.md"))
    assert len(reports) == 1
    assert "allow-ssh-public" in reports[0].read_text(encoding="utf-8")
