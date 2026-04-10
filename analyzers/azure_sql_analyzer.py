"""
Offline Azure SQL posture analyzer.

Reviews approved Azure SQL server and database JSON exports for encryption and
network exposure risk without requiring live Azure credentials.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class AzureSQLSeverity(str, Enum):
    """Severity levels for Azure SQL findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AzureSQLFirewallRule:
    """Normalized Azure SQL firewall rule evidence."""

    name: str
    start_ip_address: str
    end_ip_address: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AzureSQLFirewallRule":
        properties = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        return cls(
            name=str(data.get("name") or data.get("rule_name") or "unknown"),
            start_ip_address=str(
                data.get("startIpAddress")
                or data.get("start_ip_address")
                or properties.get("startIpAddress")
                or "0.0.0.0"
            ),
            end_ip_address=str(
                data.get("endIpAddress")
                or data.get("end_ip_address")
                or properties.get("endIpAddress")
                or "0.0.0.0"
            ),
        )

    def is_azure_services_rule(self) -> bool:
        return self.start_ip_address == "0.0.0.0" and self.end_ip_address == "0.0.0.0"

    def range_size(self) -> int | None:
        try:
            start = int(ipaddress.ip_address(self.start_ip_address))
            end = int(ipaddress.ip_address(self.end_ip_address))
        except ValueError:
            return None
        if end < start:
            return None
        return (end - start) + 1


@dataclass
class AzureSQLServer:
    """Normalized Azure SQL logical server evidence."""

    server_name: str
    resource_id: str = ""
    public_network_access: bool = True
    minimal_tls_version: str = ""
    firewall_rules: list[AzureSQLFirewallRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AzureSQLServer":
        properties = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        firewall_items = (
            data.get("firewall_rules")
            or data.get("firewallRules")
            or properties.get("firewallRules")
            or []
        )
        public_network_access = (
            data.get("publicNetworkAccess")
            or data.get("public_network_access")
            or properties.get("publicNetworkAccess")
        )
        return cls(
            server_name=str(
                data.get("name")
                or data.get("server_name")
                or data.get("serverName")
                or properties.get("fullyQualifiedDomainName")
                or "unknown"
            ),
            resource_id=str(data.get("id") or data.get("resource_id") or ""),
            public_network_access=_coerce_public_network_access(public_network_access),
            minimal_tls_version=str(
                data.get("minimalTlsVersion")
                or data.get("minimal_tls_version")
                or properties.get("minimalTlsVersion")
                or ""
            ),
            firewall_rules=[
                AzureSQLFirewallRule.from_dict(item)
                for item in firewall_items
                if isinstance(item, dict)
            ],
        )


@dataclass
class AzureSQLDatabase:
    """Normalized Azure SQL database evidence."""

    database_name: str
    server_name: str
    transparent_data_encryption_enabled: bool = True
    status: str = ""
    sku_name: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AzureSQLDatabase":
        properties = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        tde_status = (
            data.get("transparentDataEncryptionStatus")
            or data.get("transparent_data_encryption_status")
            or properties.get("transparentDataEncryptionStatus")
        )
        if tde_status is None:
            tde = data.get("transparentDataEncryption") or properties.get("transparentDataEncryption")
            if isinstance(tde, dict):
                tde_status = tde.get("state") or tde.get("status")
        return cls(
            database_name=str(data.get("name") or data.get("database_name") or "unknown"),
            server_name=str(
                data.get("serverName")
                or data.get("server_name")
                or properties.get("serverName")
                or _server_name_from_resource_id(str(data.get("id") or ""))
                or "unknown"
            ),
            transparent_data_encryption_enabled=_coerce_tde_enabled(tde_status),
            status=str(data.get("status") or properties.get("status") or ""),
            sku_name=str(
                data.get("sku_name")
                or (data.get("sku") or {}).get("name")
                or (properties.get("sku") or {}).get("name")
                or ""
            ),
        )


@dataclass
class AzureSQLFinding:
    """A single Azure SQL posture finding."""

    check_id: str
    severity: AzureSQLSeverity
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
class AzureSQLReport:
    """Aggregated Azure SQL analyzer result."""

    findings: list[AzureSQLFinding] = field(default_factory=list)
    servers_analyzed: int = 0
    databases_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_check(self, check_id: str) -> list[AzureSQLFinding]:
        return [finding for finding in self.findings if finding.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "servers_analyzed": self.servers_analyzed,
            "databases_analyzed": self.databases_analyzed,
            "generated_at": self.generated_at,
            "findings": [finding.to_dict() for finding in self.findings],
        }


_CHECK_WEIGHTS = {
    "AZ-SQL-001": 45,
    "AZ-SQL-002": 50,
    "AZ-SQL-003": 20,
    "AZ-SQL-004": 40,
}


class AzureSQLAnalyzer:
    """Analyze offline Azure SQL exports for encryption and firewall risk."""

    def analyze(
        self,
        servers: list[AzureSQLServer],
        databases: list[AzureSQLDatabase],
    ) -> AzureSQLReport:
        findings: list[AzureSQLFinding] = []
        server_names = {server.server_name for server in servers}
        for server in servers:
            findings.extend(self._check_public_network_access(server))
            findings.extend(self._check_firewall_rules(server))
        for database in databases:
            findings.extend(self._check_tde(database, database.server_name in server_names))

        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return AzureSQLReport(
            findings=findings,
            servers_analyzed=len(servers),
            databases_analyzed=len(databases),
            risk_score=risk_score,
        )

    def _check_tde(
        self,
        database: AzureSQLDatabase,
        known_server: bool,
    ) -> list[AzureSQLFinding]:
        if database.transparent_data_encryption_enabled:
            return []
        resource_name = f"{database.server_name}/{database.database_name}"
        detail = (
            f"Azure SQL database '{database.database_name}' on server '{database.server_name}' "
            "does not report Transparent Data Encryption as enabled."
        )
        if not known_server:
            detail += " The export did not include a matching server object, so verify the server inventory."
        return [
            AzureSQLFinding(
                check_id="AZ-SQL-001",
                severity=AzureSQLSeverity.HIGH,
                resource_type="sql_database",
                resource_name=resource_name,
                title="Azure SQL database encryption at rest is disabled",
                detail=detail,
                recommendation=(
                    "Enable Transparent Data Encryption for the database and review any "
                    "customer-managed key policy requirements before production rollout."
                ),
            )
        ]

    def _check_public_network_access(self, server: AzureSQLServer) -> list[AzureSQLFinding]:
        if not server.public_network_access:
            return []
        return [
            AzureSQLFinding(
                check_id="AZ-SQL-002",
                severity=AzureSQLSeverity.CRITICAL,
                resource_type="sql_server",
                resource_name=server.server_name,
                title="Azure SQL server allows public network access",
                detail=(
                    f"Azure SQL server '{server.server_name}' reports public network access as enabled, "
                    "which allows database connectivity from public IP ranges when firewall rules permit it."
                ),
                recommendation=(
                    "Disable public network access and move application connectivity to approved private "
                    "endpoints or tightly controlled network paths."
                ),
            )
        ]

    def _check_firewall_rules(self, server: AzureSQLServer) -> list[AzureSQLFinding]:
        findings: list[AzureSQLFinding] = []
        for rule in server.firewall_rules:
            if rule.is_azure_services_rule():
                findings.append(
                    AzureSQLFinding(
                        check_id="AZ-SQL-003",
                        severity=AzureSQLSeverity.MEDIUM,
                        resource_type="sql_firewall_rule",
                        resource_name=f"{server.server_name}:{rule.name}",
                        title="Azure SQL server allows connections from all Azure services",
                        detail=(
                            f"Firewall rule '{rule.name}' on server '{server.server_name}' uses "
                            "0.0.0.0-0.0.0.0, which permits traffic from Azure services outside your tenant."
                        ),
                        recommendation=(
                            "Remove the broad Azure-services firewall rule and replace it with "
                            "private endpoints or explicit source ranges for approved workloads."
                        ),
                    )
                )
                continue
            range_size = rule.range_size()
            if range_size is None:
                continue
            if range_size >= 65536 or rule.start_ip_address == "0.0.0.0":
                findings.append(
                    AzureSQLFinding(
                        check_id="AZ-SQL-004",
                        severity=AzureSQLSeverity.HIGH,
                        resource_type="sql_firewall_rule",
                        resource_name=f"{server.server_name}:{rule.name}",
                        title="Azure SQL firewall rule allows a broad public IP range",
                        detail=(
                            f"Firewall rule '{rule.name}' on server '{server.server_name}' allows "
                            f"{rule.start_ip_address}-{rule.end_ip_address}, a broad public range that "
                            "substantially increases internet exposure."
                        ),
                        recommendation=(
                            "Restrict the firewall rule to the smallest approved IP ranges or replace "
                            "public ingress with private endpoints."
                        ),
                    )
                )
        return findings


def load_azure_sql_from_export(path: str | Path) -> tuple[list[AzureSQLServer], list[AzureSQLDatabase]]:
    """Load Azure SQL servers and databases from a JSON export file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_azure_sql_from_export_dict(payload)


def load_azure_sql_from_export_dict(
    payload: dict[str, Any],
) -> tuple[list[AzureSQLServer], list[AzureSQLDatabase]]:
    """Load Azure SQL servers and databases from a parsed export dictionary."""
    normalized = _unwrap_payload(payload)
    servers_raw = normalized.get("servers")
    databases_raw = normalized.get("databases")
    if not isinstance(servers_raw, list):
        servers_raw = []
    if not isinstance(databases_raw, list):
        databases_raw = []
    servers = [AzureSQLServer.from_dict(item) for item in servers_raw if isinstance(item, dict)]
    databases = [AzureSQLDatabase.from_dict(item) for item in databases_raw if isinstance(item, dict)]
    return servers, databases


def _unwrap_payload(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("results", "data", "value", "payload"):
        nested = payload.get(key)
        if isinstance(nested, dict) and ("servers" in nested or "databases" in nested):
            return nested
    return payload


def _coerce_public_network_access(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip().lower()
    if text in {"disabled", "false", "0", "none", "private"}:
        return False
    if text in {"enabled", "true", "1", "public"}:
        return True
    return bool(value)


def _coerce_tde_enabled(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip().lower()
    if text in {"enabled", "true", "1", "on"}:
        return True
    if text in {"disabled", "false", "0", "off"}:
        return False
    return bool(value)


def _server_name_from_resource_id(resource_id: str) -> str:
    marker = "/servers/"
    if marker not in resource_id:
        return ""
    tail = resource_id.split(marker, 1)[1]
    return tail.split("/", 1)[0]
