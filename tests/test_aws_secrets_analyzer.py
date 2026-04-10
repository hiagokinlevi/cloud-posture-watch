"""Tests for offline AWS managed secrets correlation and hardcoded credential review."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.aws_secrets_analyzer import (
    AWSSecretsAnalyzer,
    load_aws_secrets_from_export,
    load_aws_secrets_from_export_dict,
)
from cli.main import cli


def _export_payload() -> dict:
    return {
        "secrets": [
            {
                "Name": "prod/orders/db-password",
                "RotationEnabled": True,
                "KmsKeyId": "alias/orders",
            }
        ],
        "parameters": [
            {
                "Name": "/prod/orders/api-token",
                "Type": "String",
            },
            {
                "Name": "/prod/orders/webhook-secret",
                "Type": "SecureString",
            },
        ],
        "hardcoded_credentials": [
            {
                "path": "services/orders/settings.py",
                "category": "password",
                "identifier": "DB_PASSWORD",
            },
            {
                "path": "services/orders/client.py",
                "category": "token",
                "identifier": "API_TOKEN",
            },
            {
                "path": "bootstrap/export.sh",
                "category": "access_key",
                "identifier": "AWS_ACCESS_KEY_ID",
            },
        ],
    }


def test_loader_accepts_wrapped_export_shapes(tmp_path):
    export_path = tmp_path / "aws-secrets.json"
    export_path.write_text(json.dumps({"results": _export_payload()}), encoding="utf-8")

    managed_entries, hardcoded_evidence = load_aws_secrets_from_export(export_path)

    assert len(managed_entries) == 3
    assert len(hardcoded_evidence) == 3
    assert managed_entries[0].name == "prod/orders/db-password"
    assert managed_entries[1].secure is False
    assert hardcoded_evidence[1].identifier == "API_TOKEN"


def test_analyzer_flags_duplicate_unmanaged_and_plaintext_parameter():
    managed_entries, hardcoded_evidence = load_aws_secrets_from_export_dict(_export_payload())

    report = AWSSecretsAnalyzer().analyze(managed_entries, hardcoded_evidence)

    assert report.risk_score == 95
    assert {finding.check_id for finding in report.findings} == {
        "AWS-SEC-001",
        "AWS-SEC-002",
        "AWS-SEC-003",
    }
    duplicate_findings = report.findings_by_check("AWS-SEC-001")
    assert len(duplicate_findings) == 2
    assert duplicate_findings[0].resource_name in {
        "prod/orders/db-password",
        "/prod/orders/api-token",
    }
    assert report.findings_by_check("AWS-SEC-002")[0].severity.value == "critical"
    assert report.findings_by_check("AWS-SEC-003")[0].resource_name == "/prod/orders/api-token"


def test_analyzer_ignores_secure_non_credential_parameters():
    payload = {
        "parameters": [
            {"Name": "/prod/orders/retry-count", "Type": "String"},
            {"Name": "/prod/orders/db-password", "Type": "SecureString"},
        ],
        "hardcoded_credentials": [],
    }

    managed_entries, hardcoded_evidence = load_aws_secrets_from_export_dict(payload)
    report = AWSSecretsAnalyzer().analyze(managed_entries, hardcoded_evidence)

    assert hardcoded_evidence == []
    assert report.total_findings == 0
    assert report.risk_score == 0


def test_scan_aws_secrets_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "aws-secrets.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-aws-secrets",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "AWS secrets export: 3 managed entrie(s), 3 hardcoded evidence item(s), 4 finding(s)" in result.output
    reports = list(output_dir.glob("posture_aws_*.md"))
    assert len(reports) == 1
    report_text = reports[0].read_text(encoding="utf-8")
    assert "Hardcoded credential appears to duplicate an AWS managed secret" in report_text
    assert "Credential-like SSM parameter is stored as plaintext" in report_text
