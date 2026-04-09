"""
Azure NSG Exposure Analyzer
============================
Analyzes Azure Network Security Group (NSG) rules for network exposure risk.
Mirrors the AWS Security Group analysis in analyzers/network_exposure.py.

Risk model:
  - NET-AZ-001 CRITICAL: Admin ports (22/SSH, 3389/RDP, 5900/VNC) open
                         to Internet or * source with Allow/Inbound
  - NET-AZ-002 HIGH:     Database ports (1433/MSSQL, 3306/MySQL, 5432/PostgreSQL,
                         27017/MongoDB, 6379/Redis) open to Internet/*
  - NET-AZ-003 HIGH:     Wide port range (>1000 ports) open to Internet/*
  - NET-AZ-004 MEDIUM:   Web ports (80/443/8080/8443) open to Internet
  - NET-AZ-005 LOW:      All-traffic rule (*) inbound from Internet/*
  - NET-AZ-006 INFO:     Any Allow-inbound rule from Internet/0.0.0.0/0

Usage:
    from providers.azure.network_collector import collect_nsgs
    from analyzers.nsg_exposure import analyze_nsg_exposure

    nsgs = collect_nsgs(subscription_id)
    findings = analyze_nsg_exposure(nsgs)
    for f in findings:
        print(f"[{f.severity.upper()}] {f.rule_id}: {f.title}")
"""
from __future__ import annotations

from dataclasses import dataclass

from providers.azure.network_collector import NSGPosture, NSGRulePosture


@dataclass
class NSGFinding:
    """A single network exposure finding from NSG analysis."""

    provider: str = "azure"
    resource_type: str = "network_security_group"
    resource_id: str = ""         # NSG name
    resource_name: str = ""
    rule_name: str = ""
    severity: str = ""            # "critical", "high", "medium", "low", "info"
    rule_id: str = ""             # e.g. "NET-AZ-001"
    title: str = ""
    detail: str = ""
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Public source address prefixes
# ---------------------------------------------------------------------------

_PUBLIC_SOURCES = {"*", "Internet", "0.0.0.0/0", "::/0", "Any"}

# Ports considered admin/privileged — open to the public is critical
_ADMIN_PORTS = {22, 3389, 5900}

# Database ports — should never be public-facing
_DATABASE_PORTS = {1433, 3306, 5432, 27017, 6379, 5984, 9200}

# Standard web ports — exposure is lower risk but still worth noting
_WEB_PORTS = {80, 443, 8080, 8443}


def _is_public_source(source: str) -> bool:
    """Return True if the source address prefix indicates any public internet traffic."""
    return source.strip() in _PUBLIC_SOURCES


def _parse_port_ranges(port_ranges: list[str]) -> list[tuple[int, int]]:
    """
    Convert port range strings to (start, end) integer tuples.

    Handles:
      - "*"      → (0, 65535)
      - "80"     → (80, 80)
      - "80-443" → (80, 443)
    """
    result: list[tuple[int, int]] = []
    for pr in port_ranges:
        pr = pr.strip()
        if pr == "*":
            result.append((0, 65535))
        elif "-" in pr:
            parts = pr.split("-", 1)
            try:
                result.append((int(parts[0]), int(parts[1])))
            except ValueError:
                pass
        else:
            try:
                p = int(pr)
                result.append((p, p))
            except ValueError:
                pass
    return result


def _port_in_ranges(port: int, ranges: list[tuple[int, int]]) -> bool:
    """Return True if the given port falls within any of the ranges."""
    return any(start <= port <= end for start, end in ranges)


def _range_width(ranges: list[tuple[int, int]]) -> int:
    """Return the total number of ports covered by all ranges."""
    return sum(end - start + 1 for start, end in ranges)


def _analyze_rule(nsg: NSGPosture, rule: NSGRulePosture) -> list[NSGFinding]:
    """Check a single NSG rule for exposure issues."""
    findings: list[NSGFinding] = []

    # Only analyze Allow + Inbound rules from public sources
    if rule.access.lower() != "allow":
        return findings
    if rule.direction.lower() != "inbound":
        return findings
    if not _is_public_source(rule.source_address_prefix):
        return findings

    port_ranges = _parse_port_ranges(rule.destination_port_ranges)
    source = rule.source_address_prefix

    # --- NET-AZ-001: Admin ports open to internet ---
    for admin_port in _ADMIN_PORTS:
        if _port_in_ranges(admin_port, port_ranges):
            port_name = {22: "SSH", 3389: "RDP", 5900: "VNC"}.get(admin_port, str(admin_port))
            findings.append(NSGFinding(
                resource_id=nsg.name,
                resource_name=nsg.name,
                rule_name=rule.name,
                severity="critical",
                rule_id="NET-AZ-001",
                title=(
                    f"NSG '{nsg.name}' allows {port_name} (port {admin_port}) "
                    f"from '{source}' — admin port exposed to internet"
                ),
                detail=(
                    f"Rule '{rule.name}' (priority {rule.priority}): "
                    f"Allow Inbound {rule.protocol} from {source} to port {admin_port}"
                ),
                recommendation=(
                    f"Restrict the source address prefix of rule '{rule.name}' from "
                    f"'{source}' to specific authorized IP ranges. "
                    f"{port_name} access should never be open to the public internet. "
                    "Consider using Azure Bastion or VPN for remote admin access."
                ),
            ))

    # --- NET-AZ-002: Database ports open to internet ---
    for db_port in _DATABASE_PORTS:
        if _port_in_ranges(db_port, port_ranges):
            port_name = {
                1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                27017: "MongoDB", 6379: "Redis", 5984: "CouchDB", 9200: "Elasticsearch",
            }.get(db_port, f"DB:{db_port}")
            findings.append(NSGFinding(
                resource_id=nsg.name,
                resource_name=nsg.name,
                rule_name=rule.name,
                severity="high",
                rule_id="NET-AZ-002",
                title=(
                    f"NSG '{nsg.name}' allows {port_name} (port {db_port}) "
                    f"from '{source}' — database port exposed to internet"
                ),
                detail=(
                    f"Rule '{rule.name}' (priority {rule.priority}): "
                    f"Allow Inbound {rule.protocol} from {source} to port {db_port}"
                ),
                recommendation=(
                    f"Restrict access to {port_name} (port {db_port}) to private IP ranges. "
                    "Database ports should never be reachable from the public internet. "
                    "Use private endpoints or VNet service endpoints instead."
                ),
            ))

    # --- NET-AZ-003: Wide port range open to internet ---
    width = _range_width(port_ranges)
    if width > 1000:
        findings.append(NSGFinding(
            resource_id=nsg.name,
            resource_name=nsg.name,
            rule_name=rule.name,
            severity="high",
            rule_id="NET-AZ-003",
            title=(
                f"NSG '{nsg.name}' rule '{rule.name}' opens {width} ports "
                f"from '{source}' — overly broad port range"
            ),
            detail=(
                f"Rule '{rule.name}' (priority {rule.priority}): "
                f"Allow Inbound {rule.protocol} from {source}, "
                f"ports: {rule.destination_port_ranges}"
            ),
            recommendation=(
                f"Narrow the port range in rule '{rule.name}' to only the specific "
                "ports required by your application. Broad port ranges increase the "
                "attack surface and violate the principle of least privilege."
            ),
        ))

    # --- NET-AZ-004: Web ports open to internet ---
    web_exposed = [p for p in _WEB_PORTS if _port_in_ranges(p, port_ranges)]
    if web_exposed and width <= 1000:
        findings.append(NSGFinding(
            resource_id=nsg.name,
            resource_name=nsg.name,
            rule_name=rule.name,
            severity="medium",
            rule_id="NET-AZ-004",
            title=(
                f"NSG '{nsg.name}' exposes web port(s) {web_exposed} "
                f"from '{source}' — intended for internet-facing services"
            ),
            detail=(
                f"Rule '{rule.name}' (priority {rule.priority}): "
                f"Allow Inbound {rule.protocol} from {source} to ports {web_exposed}"
            ),
            recommendation=(
                "Verify this rule is intentional for an internet-facing service. "
                "If possible, place a WAF or Application Gateway in front of web services "
                "rather than exposing them directly via NSG rules."
            ),
        ))

    # --- NET-AZ-005: All-traffic inbound from internet ---
    if _range_width(port_ranges) > 60000 and rule.protocol in ("*", "Any"):
        findings.append(NSGFinding(
            resource_id=nsg.name,
            resource_name=nsg.name,
            rule_name=rule.name,
            severity="low",
            rule_id="NET-AZ-005",
            title=(
                f"NSG '{nsg.name}' has all-traffic inbound rule from '{source}'"
            ),
            detail=(
                f"Rule '{rule.name}' (priority {rule.priority}): "
                f"Allow Inbound {rule.protocol} from {source} to all ports"
            ),
            recommendation=(
                "Replace all-traffic inbound rules with specific port and protocol rules. "
                "Even on internal/dev environments, all-traffic rules broaden the attack surface."
            ),
        ))

    return findings


def analyze_nsg_exposure(nsgs: list[NSGPosture]) -> list[NSGFinding]:
    """
    Analyze a list of Azure NSG postures for network exposure risk.

    All rules with access=Deny are skipped — Deny rules restrict access
    and do not represent exposure. Only Allow+Inbound rules from public
    source prefixes are evaluated.

    Args:
        nsgs: NSGPosture objects from providers/azure/network_collector.

    Returns:
        List of NSGFinding objects sorted by severity (critical first).
    """
    all_findings: list[NSGFinding] = []

    for nsg in nsgs:
        for rule in nsg.rules:
            all_findings.extend(_analyze_rule(nsg, rule))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return all_findings
