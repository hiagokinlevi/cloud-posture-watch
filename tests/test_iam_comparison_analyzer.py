"""Tests for cross-cloud IAM comparison reports."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.aws_iam_analyzer import AWSIAMAnalyzer, AWSIAMSnapshot
from analyzers.azure_rbac_analyzer import AzureRBACAnalyzer, AzureRoleAssignment, AzureRoleDefinition
from analyzers.gcp_iam_analyzer import GCPIAMAnalyzer, IAMPolicy
from analyzers.iam_comparison_analyzer import (
    build_iam_comparison_report,
    generate_iam_comparison_markdown,
)
from cli.main import cli


def _aws_payload() -> dict:
    return {
        "account_id": "123456789012",
        "root_mfa_enabled": False,
        "users": [
            {
                "user_name": "deploy-bot",
                "access_keys": [
                    {
                        "access_key_id": "AKIAUSERSTALE",
                        "status": "Active",
                        "created_at_days_ago": 181,
                    }
                ],
            }
        ],
        "policies": [
            {
                "name": "AdminEverything",
                "document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
            }
        ],
    }


def _azure_payload() -> dict:
    return {
        "assignments": [
            {
                "id": "assign-owner",
                "scope": "/subscriptions/sub-123",
                "roleDefinitionName": "Owner",
                "principalName": "breakglass@example.com",
                "principalType": "User",
            },
            {
                "id": "assign-guest",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-app",
                "roleDefinitionName": "User Access Administrator",
                "principalName": "partner_external.com#EXT#@example.onmicrosoft.com",
                "principalType": "Guest",
            },
            {
                "id": "assign-custom",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-data",
                "roleDefinitionName": "Custom Everything",
                "roleDefinitionId": "custom-1",
                "principalName": "data-admin@example.com",
                "principalType": "User",
            },
        ],
        "role_definitions": [
            {
                "id": "custom-1",
                "roleName": "Custom Everything",
                "isCustom": True,
                "permissions": [{"actions": ["*"]}],
            }
        ],
    }


def _gcp_payload() -> dict:
    return {
        "policies": [
            {
                "project_id": "prod-project",
                "policy": {
                    "bindings": [
                        {"role": "roles/owner", "members": ["user:platform@example.com"]},
                        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                    ]
                },
                "service_account_keys": [
                    {
                        "key_id": "legacy-key",
                        "service_account": "deploy@prod-project.iam.gserviceaccount.com",
                        "created_at_days_ago": 181,
                    }
                ],
            }
        ]
    }


def test_build_iam_comparison_report_groups_findings_by_provider_and_theme():
    aws_report = AWSIAMAnalyzer(max_access_key_age_days=90).analyze(
        [AWSIAMSnapshot.from_dict(_aws_payload())]
    )
    azure_report = AzureRBACAnalyzer(trusted_domains=["example.com"]).analyze(
        [AzureRoleAssignment.from_dict(item) for item in _azure_payload()["assignments"]],
        [AzureRoleDefinition.from_dict(item) for item in _azure_payload()["role_definitions"]],
    )
    gcp_report = GCPIAMAnalyzer(org_domains=["example.com"]).analyze(
        [
            IAMPolicy.from_dict(
                "projects/prod-project",
                {
                    "bindings": _gcp_payload()["policies"][0]["policy"]["bindings"],
                    "service_account_keys": _gcp_payload()["policies"][0]["service_account_keys"],
                },
            )
        ]
    )

    comparison = build_iam_comparison_report(
        aws_report=aws_report,
        azure_report=azure_report,
        gcp_report=gcp_report,
    )

    assert comparison.total_findings > 0
    assert comparison.cross_cloud_risk_score == 100
    assert [summary.provider for summary in comparison.providers] == ["aws", "azure", "gcp"]
    assert comparison.category_counts["credential_hygiene"]["aws"] == 2
    assert comparison.category_counts["privileged_standing_access"]["azure"] == 2
    assert comparison.category_counts["external_or_public_access"]["gcp"] == 1
    assert comparison.findings[0].severity == "critical"

    markdown = generate_iam_comparison_markdown(comparison)
    assert "Cross-Cloud IAM Comparison Report" in markdown
    assert "Provider Summary" in markdown
    assert "Comparison Themes" in markdown


def test_scan_iam_comparison_cli_writes_markdown_and_json_and_gates(tmp_path):
    aws_path = tmp_path / "aws-iam.json"
    azure_path = tmp_path / "azure-rbac.json"
    gcp_path = tmp_path / "gcp-iam.json"
    output_dir = tmp_path / "reports"
    aws_path.write_text(json.dumps(_aws_payload()), encoding="utf-8")
    azure_path.write_text(json.dumps(_azure_payload()), encoding="utf-8")
    gcp_path.write_text(json.dumps(_gcp_payload()), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-iam-comparison",
            "--aws-input",
            str(aws_path),
            "--azure-input",
            str(azure_path),
            "--gcp-input",
            str(gcp_path),
            "--trusted-domain",
            "example.com",
            "--org-domain",
            "example.com",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "IAM comparison: 3 provider(s)" in result.output
    markdown_reports = list(output_dir.glob("iam_comparison_*.md"))
    json_reports = list(output_dir.glob("iam_comparison_*.json"))
    assert len(markdown_reports) == 1
    assert len(json_reports) == 1
    assert "Custom or wildcard permissions" in markdown_reports[0].read_text(encoding="utf-8")
    report_json = json.loads(json_reports[0].read_text(encoding="utf-8"))
    assert report_json["cross_cloud_risk_score"] == 100
    assert report_json["providers"][0]["provider"] == "aws"


def test_scan_iam_comparison_requires_at_least_two_inputs(tmp_path):
    aws_path = tmp_path / "aws-iam.json"
    aws_path.write_text(json.dumps(_aws_payload()), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "scan-iam-comparison",
            "--aws-input",
            str(aws_path),
        ],
    )

    assert result.exit_code == 2
    assert "Provide at least two" in result.output
