"""Tests for offline Azure SQL posture scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.azure_sql_analyzer import (
    AzureSQLAnalyzer,
    AzureSQLDatabase,
    AzureSQLServer,
    load_azure_sql_from_export,
    load_azure_sql_from_export_dict,
)
from cli.main import cli


def _export_payload() -> dict:
    return {
        "servers": [
            {
                "name": "prod-sql",
                "publicNetworkAccess": "Enabled",
                "firewallRules": [
                    {
                        "name": "AllowAzureServices",
                        "properties": {
                            "startIpAddress": "0.0.0.0",
                            "endIpAddress": "0.0.0.0",
                        },
                    },
                    {
                        "name": "BroadInternet",
                        "properties": {
                            "startIpAddress": "0.0.0.0",
                            "endIpAddress": "255.255.255.255",
                        },
                    },
                ],
            },
            {
                "name": "private-sql",
                "properties": {
                    "publicNetworkAccess": "Disabled",
                    "firewallRules": [
                        {
                            "name": "Office",
                            "startIpAddress": "203.0.113.10",
                            "endIpAddress": "203.0.113.10",
                        }
                    ],
                },
            },
        ],
        "databases": [
            {
                "name": "appdb",
                "serverName": "prod-sql",
                "transparentDataEncryptionStatus": "Disabled",
            },
            {
                "name": "inventory",
                "properties": {
                    "serverName": "private-sql",
                    "transparentDataEncryptionStatus": "Enabled",
                },
            },
        ],
    }


def test_loader_accepts_servers_and_databases(tmp_path):
    export_path = tmp_path / "azure-sql.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    servers, databases = load_azure_sql_from_export(export_path)

    assert len(servers) == 2
    assert len(databases) == 2
    assert servers[0].server_name == "prod-sql"
    assert len(servers[0].firewall_rules) == 2
    assert databases[0].server_name == "prod-sql"


def test_loader_accepts_wrapped_shapes():
    payload = {"results": _export_payload()}

    servers, databases = load_azure_sql_from_export_dict(payload)

    assert len(servers) == 2
    assert len(databases) == 2


def test_azure_sql_analyzer_flags_encryption_and_firewall_risks():
    servers, databases = load_azure_sql_from_export_dict(_export_payload())

    report = AzureSQLAnalyzer().analyze(servers, databases)

    assert report.risk_score == 100
    assert {finding.check_id for finding in report.findings} == {
        "AZ-SQL-001",
        "AZ-SQL-002",
        "AZ-SQL-003",
        "AZ-SQL-004",
    }
    assert "prod-sql/appdb" == report.findings_by_check("AZ-SQL-001")[0].resource_name
    assert "prod-sql" == report.findings_by_check("AZ-SQL-002")[0].resource_name


def test_azure_sql_analyzer_ignores_private_encrypted_inventory():
    report = AzureSQLAnalyzer().analyze(
        [
            AzureSQLServer(
                server_name="private-sql",
                public_network_access=False,
                firewall_rules=[],
            )
        ],
        [
            AzureSQLDatabase(
                database_name="inventory",
                server_name="private-sql",
                transparent_data_encryption_enabled=True,
            )
        ],
    )

    assert report.total_findings == 0
    assert report.risk_score == 0


def test_scan_azure_sql_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "azure-sql.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-azure-sql",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "Azure SQL export: 2 server(s), 2 database(s), 4 finding(s)" in result.output
    reports = list(output_dir.glob("posture_azure_*.md"))
    assert len(reports) == 1
    assert "Azure SQL server allows public network access" in reports[0].read_text(encoding="utf-8")
