"""Tests for offline Azure NSG export scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.nsg_exposure import analyze_nsg_exposure
from cli.main import cli
from providers.azure.network_collector import load_nsgs_from_export


def _export_payload() -> list[dict]:
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg-prod/providers/"
                "Microsoft.Network/networkSecurityGroups/prod-nsg"
            ),
            "name": "prod-nsg",
            "location": "eastus",
            "securityRules": [
                {
                    "name": "AllowSSHFromInternet",
                    "properties": {
                        "protocol": "Tcp",
                        "direction": "Inbound",
                        "access": "Allow",
                        "priority": 100,
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "22",
                    },
                },
                {
                    "name": "AllowWeb",
                    "protocol": "Tcp",
                    "direction": "Inbound",
                    "access": "Allow",
                    "priority": 110,
                    "sourceAddressPrefixes": ["10.0.0.0/8", "Internet"],
                    "destinationPortRanges": ["80", "443"],
                },
            ],
        }
    ]


def test_load_nsgs_from_azure_cli_export(tmp_path):
    export_path = tmp_path / "nsgs.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    nsgs = load_nsgs_from_export(export_path)

    assert len(nsgs) == 1
    assert nsgs[0].name == "prod-nsg"
    assert nsgs[0].resource_group == "rg-prod"
    assert [rule.name for rule in nsgs[0].rules] == ["AllowSSHFromInternet", "AllowWeb"]
    assert nsgs[0].rules[1].source_address_prefix == "Internet"
    assert nsgs[0].rules[1].destination_port_ranges == ["80", "443"]


def test_loaded_export_feeds_nsg_analyzer(tmp_path):
    export_path = tmp_path / "nsgs.json"
    export_path.write_text(json.dumps({"value": _export_payload()}), encoding="utf-8")

    findings = analyze_nsg_exposure(load_nsgs_from_export(export_path))

    assert [finding.rule_id for finding in findings][:2] == ["NET-AZ-001", "NET-AZ-004"]
    assert findings[0].resource_name == "prod-nsg"


def test_scan_azure_nsgs_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "nsgs.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-azure-nsgs",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "Azure NSG export: 1 NSG(s), 2 finding(s)" in result.output
    reports = list(output_dir.glob("posture_azure_*.md"))
    assert len(reports) == 1
    assert "AllowSSHFromInternet" in reports[0].read_text(encoding="utf-8")
