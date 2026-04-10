"""
Offline AWS RDS posture analyzer.

Reviews approved `describe-db-instances` and optional `describe-db-clusters`
JSON exports for encryption and public exposure risk without requiring live AWS
credentials or boto3.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class AWSRDSSeverity(str, Enum):
    """Severity levels for AWS RDS findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RDSSubnet:
    """Minimal subnet metadata from a DB subnet group export."""

    subnet_identifier: str
    is_public: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RDSSubnet":
        subnet_id = (
            data.get("SubnetIdentifier")
            or data.get("subnet_identifier")
            or data.get("subnetId")
            or "unknown"
        )
        subnet_status = str(data.get("SubnetStatus") or data.get("subnet_status") or "")
        subnet_outpost = data.get("SubnetOutpost") if isinstance(data.get("SubnetOutpost"), dict) else {}
        public_flag = (
            data.get("PubliclyAccessible")
            or data.get("is_public")
            or data.get("public")
            or subnet_outpost.get("PubliclyAccessible")
        )
        return cls(
            subnet_identifier=str(subnet_id),
            is_public=bool(public_flag) or subnet_status.lower() == "public",
        )


@dataclass
class RDSDBInstance:
    """Normalized AWS RDS DB instance evidence."""

    db_instance_identifier: str
    engine: str = "unknown"
    storage_encrypted: bool = False
    publicly_accessible: bool = False
    multi_az: bool = False
    engine_version: str = ""
    db_subnet_group_name: str = ""
    db_subnet_group_is_public: bool = False
    source: str = "db-instance"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RDSDBInstance":
        subnet_group = data.get("DBSubnetGroup") if isinstance(data.get("DBSubnetGroup"), dict) else {}
        subnets = subnet_group.get("Subnets") if isinstance(subnet_group.get("Subnets"), list) else []
        normalized_subnets = [RDSSubnet.from_dict(item) for item in subnets if isinstance(item, dict)]
        return cls(
            db_instance_identifier=str(
                data.get("DBInstanceIdentifier")
                or data.get("db_instance_identifier")
                or data.get("DBInstanceArn")
                or "unknown"
            ),
            engine=str(data.get("Engine") or data.get("engine") or "unknown"),
            storage_encrypted=bool(data.get("StorageEncrypted") or data.get("storage_encrypted")),
            publicly_accessible=bool(data.get("PubliclyAccessible") or data.get("publicly_accessible")),
            multi_az=bool(data.get("MultiAZ") or data.get("multi_az")),
            engine_version=str(data.get("EngineVersion") or data.get("engine_version") or ""),
            db_subnet_group_name=str(
                subnet_group.get("DBSubnetGroupName")
                or subnet_group.get("db_subnet_group_name")
                or data.get("DBSubnetGroupName")
                or ""
            ),
            db_subnet_group_is_public=any(subnet.is_public for subnet in normalized_subnets),
        )


@dataclass
class RDSDBCluster:
    """Normalized AWS RDS cluster evidence."""

    db_cluster_identifier: str
    engine: str = "unknown"
    storage_encrypted: bool = False
    engine_mode: str = ""
    source: str = "db-cluster"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RDSDBCluster":
        return cls(
            db_cluster_identifier=str(
                data.get("DBClusterIdentifier")
                or data.get("db_cluster_identifier")
                or data.get("DBClusterArn")
                or "unknown"
            ),
            engine=str(data.get("Engine") or data.get("engine") or "unknown"),
            storage_encrypted=bool(data.get("StorageEncrypted") or data.get("storage_encrypted")),
            engine_mode=str(data.get("EngineMode") or data.get("engine_mode") or ""),
        )


@dataclass
class AWSRDSFinding:
    """A single AWS RDS posture finding."""

    check_id: str
    severity: AWSRDSSeverity
    resource_type: str
    resource_name: str
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class AWSRDSReport:
    """Aggregated AWS RDS analyzer result."""

    findings: list[AWSRDSFinding] = field(default_factory=list)
    db_instances_analyzed: int = 0
    db_clusters_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_check(self, check_id: str) -> list[AWSRDSFinding]:
        return [finding for finding in self.findings if finding.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "db_instances_analyzed": self.db_instances_analyzed,
            "db_clusters_analyzed": self.db_clusters_analyzed,
            "generated_at": self.generated_at,
            "findings": [finding.to_dict() for finding in self.findings],
        }


_CHECK_WEIGHTS = {
    "AWS-RDS-001": 45,
    "AWS-RDS-002": 50,
    "AWS-RDS-003": 25,
}


class AWSRDSAnalyzer:
    """Analyze offline AWS RDS exports for encryption and public access risk."""

    def analyze(
        self,
        db_instances: list[RDSDBInstance],
        db_clusters: list[RDSDBCluster] | None = None,
    ) -> AWSRDSReport:
        db_clusters = db_clusters or []
        findings: list[AWSRDSFinding] = []
        for db_instance in db_instances:
            findings.extend(self._check_unencrypted_instance(db_instance))
            findings.extend(self._check_public_instance(db_instance))
            findings.extend(self._check_public_subnet_group(db_instance))
        for db_cluster in db_clusters:
            findings.extend(self._check_unencrypted_cluster(db_cluster))

        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return AWSRDSReport(
            findings=findings,
            db_instances_analyzed=len(db_instances),
            db_clusters_analyzed=len(db_clusters),
            risk_score=risk_score,
        )

    def _check_unencrypted_instance(self, db_instance: RDSDBInstance) -> list[AWSRDSFinding]:
        if db_instance.storage_encrypted:
            return []
        return [
            AWSRDSFinding(
                check_id="AWS-RDS-001",
                severity=AWSRDSSeverity.HIGH,
                resource_type="db_instance",
                resource_name=db_instance.db_instance_identifier,
                title="RDS instance storage encryption is disabled",
                detail=(
                    f"RDS instance '{db_instance.db_instance_identifier}' ({db_instance.engine}) "
                    "does not report storage encryption."
                ),
                recommendation=(
                    "Use a KMS-backed encrypted instance or migrate data to a new encrypted "
                    "instance because RDS storage encryption cannot be enabled in place."
                ),
            )
        ]

    def _check_public_instance(self, db_instance: RDSDBInstance) -> list[AWSRDSFinding]:
        if not db_instance.publicly_accessible:
            return []
        return [
            AWSRDSFinding(
                check_id="AWS-RDS-002",
                severity=AWSRDSSeverity.CRITICAL,
                resource_type="db_instance",
                resource_name=db_instance.db_instance_identifier,
                title="RDS instance is publicly accessible",
                detail=(
                    f"RDS instance '{db_instance.db_instance_identifier}' ({db_instance.engine}) "
                    "is marked publicly accessible and may expose a database endpoint to the internet."
                ),
                recommendation=(
                    "Disable public accessibility, keep the instance in private subnets, and "
                    "restrict access through application tiers or approved bastion paths."
                ),
            )
        ]

    def _check_public_subnet_group(self, db_instance: RDSDBInstance) -> list[AWSRDSFinding]:
        if not db_instance.db_subnet_group_is_public:
            return []
        subnet_group_name = db_instance.db_subnet_group_name or "unknown-subnet-group"
        return [
            AWSRDSFinding(
                check_id="AWS-RDS-003",
                severity=AWSRDSSeverity.MEDIUM,
                resource_type="db_instance",
                resource_name=db_instance.db_instance_identifier,
                title="RDS instance uses a public DB subnet group",
                detail=(
                    f"RDS instance '{db_instance.db_instance_identifier}' uses DB subnet group "
                    f"'{subnet_group_name}' with at least one subnet marked public."
                ),
                recommendation=(
                    "Keep database subnet groups private-only so accidental public-access "
                    "changes do not create an externally routable database path."
                ),
            )
        ]

    def _check_unencrypted_cluster(self, db_cluster: RDSDBCluster) -> list[AWSRDSFinding]:
        if db_cluster.storage_encrypted:
            return []
        return [
            AWSRDSFinding(
                check_id="AWS-RDS-001",
                severity=AWSRDSSeverity.HIGH,
                resource_type="db_cluster",
                resource_name=db_cluster.db_cluster_identifier,
                title="RDS cluster storage encryption is disabled",
                detail=(
                    f"RDS cluster '{db_cluster.db_cluster_identifier}' ({db_cluster.engine}) "
                    "does not report storage encryption."
                ),
                recommendation=(
                    "Use a KMS-backed encrypted cluster and restore or migrate workloads into "
                    "that encrypted deployment."
                ),
            )
        ]


def load_aws_rds_from_export(path: str | Path) -> tuple[list[RDSDBInstance], list[RDSDBCluster]]:
    """Load AWS RDS DB instances and clusters from an offline JSON export."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_aws_rds_from_export_dict(payload)


def load_aws_rds_from_export_dict(payload: Any) -> tuple[list[RDSDBInstance], list[RDSDBCluster]]:
    """Normalize a few common offline RDS export shapes."""
    db_instances_raw = _extract_entries(
        payload,
        keys=("DBInstances", "db_instances", "instances"),
        singular_keys=("DBInstance", "db_instance"),
    )
    db_clusters_raw = _extract_entries(
        payload,
        keys=("DBClusters", "db_clusters", "clusters"),
        singular_keys=("DBCluster", "db_cluster"),
    )
    db_instances = [
        RDSDBInstance.from_dict(item)
        for item in db_instances_raw
        if isinstance(item, dict)
    ]
    db_clusters = [
        RDSDBCluster.from_dict(item)
        for item in db_clusters_raw
        if isinstance(item, dict)
    ]
    return db_instances, db_clusters


def _extract_entries(
    payload: Any,
    *,
    keys: tuple[str, ...],
    singular_keys: tuple[str, ...],
) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    for key in singular_keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return [value]
    nested_collections = (
        payload.get("describe_db_instances_response"),
        payload.get("describe_db_clusters_response"),
        payload.get("results"),
        payload.get("data"),
    )
    for nested in nested_collections:
        if isinstance(nested, dict):
            extracted = _extract_entries(nested, keys=keys, singular_keys=singular_keys)
            if extracted:
                return extracted
    return []
