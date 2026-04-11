from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli
from soar.router import resolve_soar_route


def test_resolve_soar_route_matches_aws_public_bucket_rule() -> None:
    event = {
        "provider": "aws",
        "resource_type": "s3_bucket",
        "resource_name": "prod-customer-exports",
        "flag": "PUBLIC_BUCKET",
        "severity": "high",
    }

    route = resolve_soar_route(event)

    assert route.matched is True
    assert route.rule_id == "AWS-SOAR-002"
    assert route.playbook == "soar/playbooks/aws/public_s3_exposure.md"
    assert route.approval_mode == "required"
    assert "prepare_public_access_block" in route.actions


def test_resolve_soar_route_falls_back_to_default_playbook() -> None:
    event = {
        "provider": "aws",
        "resource_type": "ec2_instance",
        "resource_name": "prod-bastion-01",
        "flag": "UNKNOWN_FLAG",
        "severity": "medium",
    }

    route = resolve_soar_route(event)

    assert route.matched is False
    assert route.rule_id == "DEFAULT"
    assert route.playbook == "docs/cloud-soar.md"
    assert route.approval_mode == "recommended"
    assert route.actions == [
        "capture_evidence",
        "identify_owner",
        "verify_business_context",
    ]


def test_resolve_soar_cli_json_output(tmp_path: Path) -> None:
    input_path = tmp_path / "event.json"
    input_path.write_text(
        json.dumps(
            {
                "provider": "azure",
                "resource_type": "service_principal",
                "resource_name": "ci-prod-sp",
                "flag": "SERVICE_PRINCIPAL_OWNER",
                "severity": "high",
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["resolve-soar", "--input", str(input_path), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["rule_id"] == "AZURE-SOAR-001"
    assert payload["playbook"] == "soar/playbooks/azure/suspicious_service_principal.md"
