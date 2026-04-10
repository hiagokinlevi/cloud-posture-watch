"""Tests for offline Azure RBAC posture scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.azure_rbac_analyzer import (
    AzureRBACAnalyzer,
    AzureRoleAssignment,
    AzureRoleDefinition,
    load_azure_rbac_from_export,
)
from cli.main import cli


def _export_payload() -> dict:
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
                "id": "assign-contrib",
                "scope": "/subscriptions/sub-123",
                "roleDefinitionName": "Contributor",
                "principalName": "deploy@example.com",
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
                "id": "assign-sp-owner",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-app",
                "roleDefinitionName": "Owner",
                "principalName": "pipeline-sp",
                "principalType": "ServicePrincipal",
            },
            {
                "id": "assign-custom",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-data",
                "roleDefinitionName": "Custom Everything",
                "roleDefinitionId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/custom-1",
                "principalName": "data-admin@example.com",
                "principalType": "User",
            },
        ],
        "role_definitions": [
            {
                "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/custom-1",
                "roleName": "Custom Everything",
                "isCustom": True,
                "permissions": [{"actions": ["*"], "notActions": []}],
            }
        ],
    }


def test_loader_accepts_assignments_and_role_definitions(tmp_path):
    export_path = tmp_path / "azure-rbac.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    assignments, definitions = load_azure_rbac_from_export(export_path)

    assert len(assignments) == 5
    assert len(definitions) == 1
    assert assignments[0].scope == "/subscriptions/sub-123"
    assert definitions[0].name == "Custom Everything"


def test_azure_rbac_analyzer_flags_broad_guest_sp_and_custom_risks():
    assignments, definitions = load_azure_rbac_from_export_dict(_export_payload())

    report = AzureRBACAnalyzer(trusted_domains=["example.com"]).analyze(
        assignments,
        definitions,
    )

    assert report.risk_score == 100
    assert {finding.check_id for finding in report.findings} == {
        "AZ-RBAC-001",
        "AZ-RBAC-002",
        "AZ-RBAC-003",
        "AZ-RBAC-004",
        "AZ-RBAC-005",
        "AZ-RBAC-006",
    }
    assert "breakglass@example.com" in report.findings_by_check("AZ-RBAC-001")[0].principal
    assert "pipeline-sp" in report.findings_by_check("AZ-RBAC-004")[0].principal
    assert "Custom Everything" in report.findings_by_check("AZ-RBAC-005")[0].role


def test_azure_rbac_analyzer_ignores_scoped_reader_assignments():
    report = AzureRBACAnalyzer(trusted_domains=["example.com"]).analyze(
        [
            AzureRoleAssignment(
                scope="/subscriptions/sub-123/resourceGroups/rg-app",
                role_name="Reader",
                principal_name="reader@example.com",
                principal_type="User",
            )
        ]
    )

    assert report.total_findings == 0
    assert report.risk_score == 0


def test_external_check_can_be_disabled():
    report = AzureRBACAnalyzer(
        trusted_domains=["example.com"],
        check_external_principals=False,
    ).analyze(
        [
            AzureRoleAssignment(
                scope="/subscriptions/sub-123",
                role_name="User Access Administrator",
                principal_name="partner_external.com#EXT#@example.onmicrosoft.com",
                principal_type="Guest",
                condition="delegatedManagedIdentityResourceId != null",
            )
        ]
    )

    assert report.findings_by_check("AZ-RBAC-003") == []
    assert report.findings_by_check("AZ-RBAC-006") == []


def test_custom_role_without_wildcard_does_not_fire():
    assignment = AzureRoleAssignment(
        scope="/subscriptions/sub-123/resourceGroups/rg-data",
        role_name="Custom Reader",
        role_definition_id="custom-reader",
        principal_name="data-reader@example.com",
    )
    definition = AzureRoleDefinition(
        name="Custom Reader",
        role_id="custom-reader",
        is_custom=True,
        permissions=[],
    )

    report = AzureRBACAnalyzer().analyze([assignment], [definition])

    assert report.findings_by_check("AZ-RBAC-005") == []


def test_scan_azure_rbac_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "azure-rbac.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-azure-rbac",
            "--input",
            str(export_path),
            "--trusted-domain",
            "example.com",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "Azure RBAC export: 5 assignment(s), 1 role definition(s), 6 finding(s)" in result.output
    reports = list(output_dir.glob("posture_azure_*.md"))
    assert len(reports) == 1
    assert "Owner role assigned at broad Azure scope" in reports[0].read_text(encoding="utf-8")


def load_azure_rbac_from_export_dict(
    payload: dict,
) -> tuple[list[AzureRoleAssignment], list[AzureRoleDefinition]]:
    assignments = [AzureRoleAssignment.from_dict(item) for item in payload["assignments"]]
    definitions = [AzureRoleDefinition.from_dict(item) for item in payload["role_definitions"]]
    return assignments, definitions
