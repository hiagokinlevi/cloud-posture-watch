"""Tests for offline AWS IAM posture scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.aws_iam_analyzer import (
    AWSIAMAnalyzer,
    AWSIAMSnapshot,
    load_aws_iam_snapshot_from_export,
)
from cli.main import cli


def _export_payload() -> dict:
    return {
        "account_id": "123456789012",
        "root_mfa_enabled": False,
        "root_account": {
            "access_keys": [
                {"access_key_id": "AKIAROOTACTIVE", "status": "Active"},
                {"access_key_id": "AKIAROOTINACTIVE", "status": "Inactive"},
            ]
        },
        "users": [
            {
                "user_name": "deploy-bot",
                "access_keys": [
                    {
                        "access_key_id": "AKIAUSERSTALE",
                        "status": "Active",
                        "created_at_days_ago": 181,
                    },
                    {
                        "access_key_id": "AKIAUSERFRESH",
                        "status": "Active",
                        "created_at_days_ago": 12,
                    },
                ],
            }
        ],
        "policies": [
            {
                "name": "AdminEverything",
                "arn": "arn:aws:iam::123456789012:policy/AdminEverything",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
            },
            {
                "name": "PassRoleWildcard",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:PassRole", "s3:GetObject"], "Resource": "*"}
                    ]
                },
            },
            {
                "name": "ScopedReadOnly",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::logs/*",
                        }
                    ]
                },
            },
        ],
    }


def test_snapshot_loader_accepts_single_account_export(tmp_path):
    export_path = tmp_path / "iam.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    snapshots = load_aws_iam_snapshot_from_export(str(export_path))

    assert len(snapshots) == 1
    assert snapshots[0].account_id == "123456789012"
    assert snapshots[0].root_mfa_enabled is False
    assert snapshots[0].access_keys[0].key_id == "AKIAROOTACTIVE"
    assert [policy.name for policy in snapshots[0].policies] == [
        "AdminEverything",
        "PassRoleWildcard",
        "ScopedReadOnly",
    ]


def test_aws_iam_analyzer_flags_root_key_age_and_policy_risks():
    report = AWSIAMAnalyzer(max_access_key_age_days=90).analyze(
        [AWSIAMSnapshot.from_dict(_export_payload())]
    )

    assert report.risk_score == 100
    assert {finding.check_id for finding in report.findings} == {
        "AWS-IAM-001",
        "AWS-IAM-002",
        "AWS-IAM-003",
        "AWS-IAM-004",
        "AWS-IAM-006",
    }
    assert len(report.findings_by_check("AWS-IAM-002")) == 1
    assert "deploy-bot" in report.findings_by_check("AWS-IAM-003")[0].resource
    assert "AdminEverything" in report.findings_by_check("AWS-IAM-004")[0].resource
    assert "PassRoleWildcard" in report.findings_by_check("AWS-IAM-006")[0].resource


def test_aws_iam_analyzer_flags_sensitive_service_wildcard():
    payload = {
        "account_id": "123456789012",
        "root_mfa_enabled": True,
        "policies": [
            {
                "name": "BroadKMS",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["kms:*"], "Resource": "*"},
                        {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    ]
                },
            }
        ],
    }

    report = AWSIAMAnalyzer().analyze([AWSIAMSnapshot.from_dict(payload)])

    assert [finding.check_id for finding in report.findings] == ["AWS-IAM-005"]
    assert report.risk_score == 35


def test_snapshot_loader_accepts_accounts_list(tmp_path):
    export_path = tmp_path / "iam.json"
    export_path.write_text(json.dumps({"accounts": [_export_payload(), _export_payload()]}), encoding="utf-8")

    snapshots = load_aws_iam_snapshot_from_export(str(export_path))

    assert len(snapshots) == 2


def test_scan_aws_iam_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "iam.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-aws-iam",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "AWS IAM export: 1 account snapshot(s), 5 finding(s)" in result.output
    reports = list(output_dir.glob("posture_aws_*.md"))
    assert len(reports) == 1
    assert "Root account MFA is not enabled" in reports[0].read_text(encoding="utf-8")
