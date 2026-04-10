"""Tests for offline GCP Cloud SQL posture scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.gcp_cloud_sql_analyzer import (
    GCPCloudSQLAnalyzer,
    load_gcp_cloud_sql_from_export,
    load_gcp_cloud_sql_from_export_dict,
)
from cli.main import cli


def _export_payload() -> list[dict]:
    return [
        {
            "name": "prod-sql",
            "databaseVersion": "POSTGRES_15",
            "region": "us-central1",
            "settings": {
                "ipConfiguration": {
                    "ipv4Enabled": True,
                    "requireSsl": False,
                    "authorizedNetworks": [
                        {"name": "internet", "value": "0.0.0.0/0"},
                    ],
                }
            },
            "ipAddresses": [
                {"type": "PRIMARY", "ipAddress": "34.72.10.10"},
                {"type": "PRIVATE", "ipAddress": "10.42.0.5"},
            ],
        },
        {
            "name": "private-sql",
            "databaseVersion": "MYSQL_8_0",
            "settings": {
                "ipConfiguration": {
                    "ipv4Enabled": False,
                    "sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
                    "authorizedNetworks": [
                        {"name": "corp", "value": "203.0.113.0/24"},
                    ],
                }
            },
            "ipAddresses": [
                {"type": "PRIVATE", "ipAddress": "10.50.0.9"},
            ],
        },
    ]


def test_loader_accepts_list_export(tmp_path):
    export_path = tmp_path / "cloud-sql.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    instances = load_gcp_cloud_sql_from_export(export_path)

    assert len(instances) == 2
    assert instances[0].instance_name == "prod-sql"
    assert instances[0].ipv4_enabled is True
    assert instances[0].public_ip_addresses == ["34.72.10.10"]


def test_loader_accepts_wrapped_shapes():
    payload = {"results": {"items": _export_payload()}}

    instances = load_gcp_cloud_sql_from_export_dict(payload)

    assert len(instances) == 2
    assert instances[1].require_ssl is True


def test_analyzer_flags_public_ip_ssl_and_broad_networks():
    instances = load_gcp_cloud_sql_from_export_dict(_export_payload())

    report = GCPCloudSQLAnalyzer().analyze(instances)

    assert report.risk_score == 100
    assert {finding.check_id for finding in report.findings} == {
        "GCP-SQL-001",
        "GCP-SQL-002",
        "GCP-SQL-003",
    }
    assert report.findings_by_check("GCP-SQL-001")[0].resource_name == "prod-sql"


def test_analyzer_ignores_private_tls_enforced_instance():
    payload = [
        {
            "name": "private-sql",
            "databaseVersion": "POSTGRES_15",
            "settings": {
                "ipConfiguration": {
                    "ipv4Enabled": False,
                    "sslMode": "ENCRYPTED_ONLY",
                }
            },
            "ipAddresses": [
                {"type": "PRIVATE", "ipAddress": "10.10.0.4"},
            ],
        }
    ]

    instances = load_gcp_cloud_sql_from_export_dict(payload)
    report = GCPCloudSQLAnalyzer().analyze(instances)

    assert report.total_findings == 0
    assert report.risk_score == 0


def test_scan_gcp_cloud_sql_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "cloud-sql.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-gcp-cloud-sql",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "GCP Cloud SQL export: 2 instance(s), 3 finding(s)" in result.output
    reports = list(output_dir.glob("posture_gcp_*.md"))
    assert len(reports) == 1
    assert "GCP Cloud SQL instance has public IPv4 exposure enabled" in reports[0].read_text(encoding="utf-8")
