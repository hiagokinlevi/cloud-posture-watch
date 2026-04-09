"""
Network Exposure Analyzer
===========================
Analyzes cloud network security controls to detect overly permissive
inbound/outbound rules that expose services to the public internet.

Currently supported:
  - AWS Security Groups (via SecurityGroupPosture from providers/aws/network_collector)
  - Generic cross-provider interface (SecurityRulePosture protocol)

Risk model:
  - CRITICAL: Port 22 (SSH) or 3389 (RDP) open to 0.0.0.0/0 or ::/0
  - HIGH:     Any port open to 0.0.0.0/0 that is not a standard web port
  - HIGH:     Admin database ports (1433, 3306, 5432, 27017) open to 0.0.0.0/0
  - MEDIUM:   Standard web ports (80, 443) open to 0.0.0.0/0 (exposure, not misconfiguration)
  - LOW:      All-protocol open rule (-1 / all traffic) to 0.0.0.0/0
  - INFO:     Outbound 0.0.0.0/0 — common but worth documenting

Usage:
    from providers.aws.network_collector import collect_security_groups
    from analyzers.network_exposure import analyze_network_exposure

    postures = collect_security_groups(session)  # Returns SecurityGroupPosture list
    findings = analyze_network_exposure(postures, provider="aws")
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from providers.aws.network_collector import SecurityGroupPosture


@dataclass
class NetworkFinding:
    """A single network exposure finding."""

    provider: str
    resource_type: str       # e.g. "security_group"
    resource_id: str
    resource_name: str
    severity: str            # "critical", "high", "medium", "low", "info"
    rule_id: str             # e.g. "NET001"
    title: str
    detail: str              # Specific rule detail (port, protocol, source)
    recommendation: str


# ---------------------------------------------------------------------------
# CIDR constants for public exposure detection
# ---------------------------------------------------------------------------

_PUBLIC_IPV4 = "0.0.0.0/0"
_PUBLIC_IPV6 = "::/0"
_PUBLIC_CIDRS = {_PUBLIC_IPV4, _PUBLIC_IPV6}

# Ports that indicate remote administration — CRITICAL if open to public
_ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP (Windows Remote Desktop)",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}

# Database ports — HIGH if open to public internet
_DATABASE_PORTS = {
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch HTTP",
    27017: "MongoDB",
}

# Standard web ports — MEDIUM if open to public (expected for web servers but worth noting)
_WEB_PORTS = {80, 443, 8080, 8443}


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_network_exposure(
    postures: list[Any],
    provider: str = "aws",
    resource_type: str = "security_group",
) -> list[NetworkFinding]:
    """
    Analyze network security posture objects for public exposure risks.

    Each posture object must have:
      - resource_id (str)
      - resource_name (str)
      - inbound_rules (list[dict]) — each with keys: protocol, from_port, to_port, cidr_ranges
      - outbound_rules (list[dict]) — same format

    Args:
        postures:      List of network security posture objects.
        provider:      Cloud provider name for finding labels ("aws", "azure", "gcp").
        resource_type: Resource type label for findings ("security_group", "nsg", "firewall_rule").

    Returns:
        List of NetworkFinding objects sorted by severity (critical first).
    """
    findings: list[NetworkFinding] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for posture in postures:
        rid = getattr(posture, "resource_id", "unknown")
        rname = getattr(posture, "resource_name", rid)

        for rule in getattr(posture, "inbound_rules", []):
            findings.extend(_check_inbound_rule(rule, provider, resource_type, rid, rname))

        for rule in getattr(posture, "outbound_rules", []):
            findings.extend(_check_outbound_rule(rule, provider, resource_type, rid, rname))

    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings


def _is_public(cidr_ranges: list[str]) -> bool:
    """Return True if any CIDR in the list allows public internet access."""
    return any(cidr in _PUBLIC_CIDRS for cidr in cidr_ranges)


def _port_range_includes(from_port: int, to_port: int, target_port: int) -> bool:
    """Return True if the port range from_port..to_port includes target_port."""
    if from_port == -1 or to_port == -1:  # All traffic
        return True
    return from_port <= target_port <= to_port


def _check_inbound_rule(
    rule: Any,
    provider: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
) -> list[NetworkFinding]:
    """Analyze a single inbound rule and return any findings."""
    findings: list[NetworkFinding] = []
    protocol = str(_rule_value(rule, "protocol", "tcp")).lower()
    from_port = int(_rule_value(rule, "from_port", 0))
    to_port = int(_rule_value(rule, "to_port", 65535))
    cidr_ranges = list(_rule_value(rule, "cidr_ranges", []))

    if not _is_public(cidr_ranges):
        return findings  # Not public — not a network exposure finding

    public_cidrs = [c for c in cidr_ranges if c in _PUBLIC_CIDRS]
    cidr_str = ", ".join(public_cidrs)

    # All-traffic rule (protocol -1 or "all")
    if protocol in ("-1", "all"):
        findings.append(NetworkFinding(
            provider=provider,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            severity="low",
            rule_id="NET001",
            title="All-traffic inbound rule open to public internet",
            detail=f"protocol=ALL from {cidr_str}",
            recommendation=(
                "Replace the all-traffic rule with explicit port-specific rules. "
                "Allow only the minimum required protocols and ports."
            ),
        ))
        return findings  # NET001 subsumes all other checks for this rule

    # Admin ports — CRITICAL
    for port, port_name in _ADMIN_PORTS.items():
        if _port_range_includes(from_port, to_port, port):
            findings.append(NetworkFinding(
                provider=provider,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                severity="critical",
                rule_id="NET002",
                title=f"Remote administration port {port} ({port_name}) open to public internet",
                detail=f"port={port} protocol={protocol} from {cidr_str}",
                recommendation=(
                    f"Restrict inbound {port_name} access to known IP ranges (office/VPN CIDRs). "
                    f"Do not allow {port_name} from 0.0.0.0/0 or ::/0."
                ),
            ))

    # Database ports — HIGH
    for port, port_name in _DATABASE_PORTS.items():
        if _port_range_includes(from_port, to_port, port):
            findings.append(NetworkFinding(
                provider=provider,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                severity="high",
                rule_id="NET003",
                title=f"Database port {port} ({port_name}) open to public internet",
                detail=f"port={port} protocol={protocol} from {cidr_str}",
                recommendation=(
                    f"Database ports must not be exposed to the public internet. "
                    f"Restrict inbound {port_name} to application server CIDRs only, "
                    "or use a VPC/private network topology."
                ),
            ))

    # Wide port range (more than 1000 ports) open to public — HIGH
    if to_port != -1 and from_port != -1 and (to_port - from_port) > 999:
        findings.append(NetworkFinding(
            provider=provider,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            severity="high",
            rule_id="NET004",
            title=f"Wide port range ({from_port}–{to_port}) open to public internet",
            detail=f"ports={from_port}-{to_port} protocol={protocol} from {cidr_str}",
            recommendation=(
                "Narrow the inbound rule to specific required ports instead of a wide range. "
                "Wide ranges increase the attack surface significantly."
            ),
        ))

    # Web ports — MEDIUM
    for port in _WEB_PORTS:
        if _port_range_includes(from_port, to_port, port) and not _is_admin_or_db(port):
            findings.append(NetworkFinding(
                provider=provider,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                severity="medium",
                rule_id="NET005",
                title=f"Web port {port} open to public internet",
                detail=f"port={port} protocol={protocol} from {cidr_str}",
                recommendation=(
                    f"Port {port} is open to 0.0.0.0/0. Confirm this is intentional for a web-facing "
                    "service. If this is an internal service, restrict access to private CIDRs."
                ),
            ))

    return findings


def _check_outbound_rule(
    rule: Any,
    provider: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
) -> list[NetworkFinding]:
    """Analyze outbound rules — unrestricted egress is informational."""
    cidr_ranges = list(_rule_value(rule, "cidr_ranges", []))
    if not _is_public(cidr_ranges):
        return []

    protocol = str(_rule_value(rule, "protocol", "tcp")).lower()
    if protocol in ("-1", "all"):
        return [NetworkFinding(
            provider=provider,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            severity="info",
            rule_id="NET006",
            title="Unrestricted outbound traffic to public internet",
            detail=f"protocol=ALL to {', '.join(c for c in cidr_ranges if c in _PUBLIC_CIDRS)}",
            recommendation=(
                "Unrestricted egress is common but allows compromised instances to communicate "
                "freely with attacker infrastructure. Consider restricting outbound to known "
                "endpoints or using a NAT gateway with egress filtering."
            ),
        )]

    return []


def _is_admin_or_db(port: int) -> bool:
    """True if the port is already covered by admin or database checks."""
    return port in _ADMIN_PORTS or port in _DATABASE_PORTS


def _rule_value(rule: Any, key: str, default: Any) -> Any:
    """Read a rule attribute from either a mapping or a dataclass-like object."""
    if isinstance(rule, dict):
        return rule.get(key, default)
    return getattr(rule, key, default)
