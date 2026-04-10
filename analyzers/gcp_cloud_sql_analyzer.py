"""
Offline GCP Cloud SQL posture analyzer.

Reviews approved Cloud SQL instance JSON exports for public network exposure,
weak authorized-network ranges, and missing SSL enforcement without requiring
live GCP credentials.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class GCPCloudSQLSeverity(str, Enum):
    """Severity levels for GCP Cloud SQL findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CloudSQLAuthorizedNetwork:
    """Normalized authorized network evidence for one Cloud SQL instance."""

    name: str
    value: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CloudSQLAuthorizedNetwork":
        return cls(
            name=str(data.get("name") or data.get("label") or "unnamed-network"),
            value=str(data.get("value") or data.get("cidr") or ""),
        )

    def is_publicly_broad(self) -> bool:
        return self.value in {"0.0.0.0/0", "::/0"}


@dataclass
class CloudSQLInstance:
    """Normalized GCP Cloud SQL instance evidence."""

    instance_name: str
    database_version: str = ""
    region: str = ""
    ipv4_enabled: bool = False
    require_ssl: bool = True
    ssl_mode: str = ""
    public_ip_addresses: list[str] = field(default_factory=list)
    authorized_networks: list[CloudSQLAuthorizedNetwork] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CloudSQLInstance":
        settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}
        ip_configuration = (
            settings.get("ipConfiguration")
            if isinstance(settings.get("ipConfiguration"), dict)
            else {}
        )
        authorized_networks = (
            ip_configuration.get("authorizedNetworks")
            if isinstance(ip_configuration.get("authorizedNetworks"), list)
            else []
        )
        ip_addresses_raw = data.get("ipAddresses") if isinstance(data.get("ipAddresses"), list) else []
        public_ip_addresses = [
            str(item.get("ipAddress") or item.get("ip_address") or "")
            for item in ip_addresses_raw
            if isinstance(item, dict) and str(item.get("type") or "").upper() in {"PRIMARY", "OUTGOING", "PUBLIC"}
        ]

        ssl_mode = str(
            ip_configuration.get("sslMode")
            or ip_configuration.get("ssl_mode")
            or ""
        )
        require_ssl = _coerce_ssl_requirement(
            ip_configuration.get("requireSsl")
            if "requireSsl" in ip_configuration
            else ip_configuration.get("require_ssl"),
            ssl_mode=ssl_mode,
        )

        return cls(
            instance_name=str(
                data.get("name")
                or data.get("instance_name")
                or data.get("instance")
                or "unknown"
            ),
            database_version=str(data.get("databaseVersion") or data.get("database_version") or ""),
            region=str(data.get("region") or ""),
            ipv4_enabled=_coerce_bool(
                ip_configuration.get("ipv4Enabled")
                if "ipv4Enabled" in ip_configuration
                else ip_configuration.get("ipv4_enabled")
            ),
            require_ssl=require_ssl,
            ssl_mode=ssl_mode,
            public_ip_addresses=[address for address in public_ip_addresses if address],
            authorized_networks=[
                CloudSQLAuthorizedNetwork.from_dict(item)
                for item in authorized_networks
                if isinstance(item, dict)
            ],
        )


@dataclass
class GCPCloudSQLFinding:
    """A single GCP Cloud SQL posture finding."""

    check_id: str
    severity: GCPCloudSQLSeverity
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
class GCPCloudSQLReport:
    """Aggregated GCP Cloud SQL analyzer result."""

    findings: list[GCPCloudSQLFinding] = field(default_factory=list)
    instances_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_check(self, check_id: str) -> list[GCPCloudSQLFinding]:
        return [finding for finding in self.findings if finding.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "instances_analyzed": self.instances_analyzed,
            "generated_at": self.generated_at,
            "findings": [finding.to_dict() for finding in self.findings],
        }


_CHECK_WEIGHTS = {
    "GCP-SQL-001": 50,
    "GCP-SQL-002": 45,
    "GCP-SQL-003": 20,
}


class GCPCloudSQLAnalyzer:
    """Analyze offline GCP Cloud SQL exports for public exposure and TLS posture."""

    def analyze(self, instances: list[CloudSQLInstance]) -> GCPCloudSQLReport:
        findings: list[GCPCloudSQLFinding] = []
        for instance in instances:
            findings.extend(self._check_public_ip(instance))
            findings.extend(self._check_ssl_requirement(instance))
            findings.extend(self._check_authorized_networks(instance))

        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return GCPCloudSQLReport(
            findings=findings,
            instances_analyzed=len(instances),
            risk_score=risk_score,
        )

    def _check_public_ip(self, instance: CloudSQLInstance) -> list[GCPCloudSQLFinding]:
        if not instance.ipv4_enabled and not instance.public_ip_addresses:
            return []
        ip_detail = ""
        if instance.public_ip_addresses:
            ip_detail = f" Public addresses present in the export: {', '.join(instance.public_ip_addresses)}."
        return [
            GCPCloudSQLFinding(
                check_id="GCP-SQL-001",
                severity=GCPCloudSQLSeverity.CRITICAL,
                resource_type="cloud_sql_instance",
                resource_name=instance.instance_name,
                title="GCP Cloud SQL instance has public IPv4 exposure enabled",
                detail=(
                    f"Cloud SQL instance '{instance.instance_name}' ({instance.database_version or 'unknown-engine'}) "
                    "allows public IPv4 connectivity through the instance IP configuration."
                    f"{ip_detail}"
                ),
                recommendation=(
                    "Disable public IPv4 access, use private IP connectivity, and restrict administration "
                    "to approved internal network paths."
                ),
            )
        ]

    def _check_ssl_requirement(self, instance: CloudSQLInstance) -> list[GCPCloudSQLFinding]:
        if instance.require_ssl:
            return []
        ssl_mode_detail = f" Reported sslMode='{instance.ssl_mode}'." if instance.ssl_mode else ""
        return [
            GCPCloudSQLFinding(
                check_id="GCP-SQL-002",
                severity=GCPCloudSQLSeverity.HIGH,
                resource_type="cloud_sql_instance",
                resource_name=instance.instance_name,
                title="GCP Cloud SQL instance does not enforce SSL/TLS",
                detail=(
                    f"Cloud SQL instance '{instance.instance_name}' does not require SSL/TLS for client "
                    f"connections in the exported IP configuration.{ssl_mode_detail}"
                ),
                recommendation=(
                    "Set Cloud SQL to require encrypted client connections and migrate clients to "
                    "TLS-capable connection settings before disabling plaintext access."
                ),
            )
        ]

    def _check_authorized_networks(self, instance: CloudSQLInstance) -> list[GCPCloudSQLFinding]:
        findings: list[GCPCloudSQLFinding] = []
        for network in instance.authorized_networks:
            if not network.is_publicly_broad():
                continue
            findings.append(
                GCPCloudSQLFinding(
                    check_id="GCP-SQL-003",
                    severity=GCPCloudSQLSeverity.MEDIUM,
                    resource_type="cloud_sql_authorized_network",
                    resource_name=f"{instance.instance_name}:{network.name}",
                    title="GCP Cloud SQL authorized network allows all public IPs",
                    detail=(
                        f"Authorized network '{network.name}' on Cloud SQL instance "
                        f"'{instance.instance_name}' allows {network.value}, exposing the database "
                        "to any public source when public IP remains enabled."
                    ),
                    recommendation=(
                        "Replace broad authorized networks with the smallest approved CIDR ranges or "
                        "remove public IPv4 connectivity entirely."
                    ),
                )
            )
        return findings


def load_gcp_cloud_sql_from_export(path: str | Path) -> list[CloudSQLInstance]:
    """Load Cloud SQL instances from an offline JSON export file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_gcp_cloud_sql_from_export_dict(payload)


def load_gcp_cloud_sql_from_export_dict(payload: Any) -> list[CloudSQLInstance]:
    """Normalize common Cloud SQL export shapes into instance records."""
    instances_raw = _extract_entries(payload)
    return [CloudSQLInstance.from_dict(item) for item in instances_raw if isinstance(item, dict)]


def _extract_entries(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("items", "instances", "results", "data", "value"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            extracted = _extract_entries(value)
            if extracted:
                return extracted
    return [payload] if "settings" in payload or "databaseVersion" in payload else []


def _coerce_bool(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "enabled", "on", "yes"}:
        return True
    if text in {"false", "0", "disabled", "off", "no"}:
        return False
    return bool(value)


def _coerce_ssl_requirement(value: Any, *, ssl_mode: str) -> bool:
    if value is not None:
        return _coerce_bool(value)
    mode = ssl_mode.strip().upper()
    if not mode:
        return False
    return mode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}
