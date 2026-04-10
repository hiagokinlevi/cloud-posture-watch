"""Tests for offline AWS RDS posture scanning."""
from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.aws_rds_analyzer import (
    AWSRDSAnalyzer,
    load_aws_rds_from_export,
    load_aws_rds_from_export_dict,
)
from cli.main import cli


def _export_payload() -> dict:
    return {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "orders-db",
                "Engine": "postgres",
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "DBSubnetGroup": {
                    "DBSubnetGroupName": "public-data",
                    "Subnets": [
                        {"SubnetIdentifier": "subnet-public-a", "SubnetStatus": "Public"},
                        {"SubnetIdentifier": "subnet-private-b", "SubnetStatus": "Active"},
                    ],
                },
            },
            {
                "DBInstanceIdentifier": "billing-db",
                "Engine": "mysql",
                "StorageEncrypted": True,
                "PubliclyAccessible": False,
                "DBSubnetGroup": {
                    "DBSubnetGroupName": "private-data",
                    "Subnets": [
                        {"SubnetIdentifier": "subnet-private-a", "SubnetStatus": "Active"},
                    ],
                },
            },
        ],
        "DBClusters": [
            {
                "DBClusterIdentifier": "aurora-main",
                "Engine": "aurora-postgresql",
                "StorageEncrypted": False,
            }
        ],
    }


def test_loader_accepts_instance_and_cluster_export(tmp_path):
    export_path = tmp_path / "rds.json"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    db_instances, db_clusters = load_aws_rds_from_export(export_path)

    assert len(db_instances) == 2
    assert len(db_clusters) == 1
    assert db_instances[0].db_instance_identifier == "orders-db"
    assert db_instances[0].db_subnet_group_is_public is True
    assert db_clusters[0].db_cluster_identifier == "aurora-main"


def test_loader_accepts_wrapped_shapes():
    payload = {"results": {"DBInstances": _export_payload()["DBInstances"]}}

    db_instances, db_clusters = load_aws_rds_from_export_dict(payload)

    assert len(db_instances) == 2
    assert db_clusters == []


def test_aws_rds_analyzer_flags_unencrypted_and_public_risks():
    db_instances, db_clusters = load_aws_rds_from_export_dict(_export_payload())

    report = AWSRDSAnalyzer().analyze(db_instances, db_clusters)

    assert report.risk_score == 100
    assert {finding.check_id for finding in report.findings} == {
        "AWS-RDS-001",
        "AWS-RDS-002",
        "AWS-RDS-003",
    }
    assert "orders-db" in report.findings_by_check("AWS-RDS-002")[0].resource_name
    assert "aurora-main" in report.findings_by_check("AWS-RDS-001")[1].resource_name


def test_aws_rds_analyzer_ignores_private_encrypted_instances():
    payload = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "private-db",
                "Engine": "postgres",
                "StorageEncrypted": True,
                "PubliclyAccessible": False,
                "DBSubnetGroup": {
                    "Subnets": [{"SubnetIdentifier": "subnet-private-a", "SubnetStatus": "Active"}]
                },
            }
        ]
    }

    db_instances, db_clusters = load_aws_rds_from_export_dict(payload)
    report = AWSRDSAnalyzer().analyze(db_instances, db_clusters)

    assert report.total_findings == 0
    assert report.risk_score == 0


def test_scan_aws_rds_cli_writes_report_and_gates(tmp_path):
    export_path = tmp_path / "rds.json"
    output_dir = tmp_path / "reports"
    export_path.write_text(json.dumps(_export_payload()), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output-dir",
            str(output_dir),
            "scan-aws-rds",
            "--input",
            str(export_path),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    assert "AWS RDS export: 2 DB instance(s), 1 DB cluster(s), 4 finding(s)" in result.output
    reports = list(output_dir.glob("posture_aws_*.md"))
    assert len(reports) == 1
    assert "RDS instance is publicly accessible" in reports[0].read_text(encoding="utf-8")
