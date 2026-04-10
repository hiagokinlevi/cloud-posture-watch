"""
GCP Firewall Rule Collector
===========================
Collects GCP VPC firewall rules and converts them to the generic network
exposure shape used by the cross-cloud analyzer.

The offline loader accepts `gcloud compute firewall-rules list --format=json`
exports, single firewall objects, or wrapper objects with an `items` list.
Live collection uses the optional google-cloud-compute package when available.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from google.cloud import compute_v1

    _GCP_COMPUTE_AVAILABLE = True
except ImportError:
    _GCP_COMPUTE_AVAILABLE = False


@dataclass
class GCPFirewallNetworkRule:
    """A normalized ingress or egress rule block."""

    protocol: str
    from_port: int
    to_port: int
    cidr_ranges: list[str]


@dataclass
class GCPFirewallRulePosture:
    """Posture data for a single GCP VPC firewall rule."""

    resource_id: str
    resource_name: str
    description: str = ""
    network: str = "unknown"
    priority: int = 1000
    disabled: bool = False
    inbound_rules: list[GCPFirewallNetworkRule] = field(default_factory=list)
    outbound_rules: list[GCPFirewallNetworkRule] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)


def _records_from_export(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        records = data["items"]
    elif isinstance(data, dict) and isinstance(data.get("value"), list):
        records = data["value"]
    elif isinstance(data, dict):
        records = [data]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("GCP firewall export must be a JSON object or list")
    return [record for record in records if isinstance(record, dict)]


def _port_range_to_tuple(port: str | int) -> tuple[int, int]:
    text = str(port).strip()
    if not text:
        return (0, 65535)
    if "-" in text:
        start, end = text.split("-", 1)
        return (int(start), int(end))
    value = int(text)
    return (value, value)


def _ports_to_ranges(ports: list[Any] | None) -> list[tuple[int, int]]:
    if not ports:
        return [(0, 65535)]

    ranges: list[tuple[int, int]] = []
    for port in ports:
        try:
            ranges.append(_port_range_to_tuple(port))
        except (TypeError, ValueError):
            continue
    return ranges or [(0, 65535)]


def _normalize_protocol(protocol: Any) -> str:
    value = str(protocol or "all").lower()
    if value in ("all", "*"):
        return "all"
    return value


def _network_rules_from_blocks(
    blocks: list[dict[str, Any]] | None,
    cidr_ranges: list[str],
) -> list[GCPFirewallNetworkRule]:
    rules: list[GCPFirewallNetworkRule] = []
    for block in blocks or []:
        protocol = _normalize_protocol(block.get("IPProtocol") or block.get("ipProtocol"))
        for start, end in _ports_to_ranges(block.get("ports")):
            rules.append(GCPFirewallNetworkRule(
                protocol=protocol,
                from_port=start,
                to_port=end,
                cidr_ranges=cidr_ranges,
            ))
    return rules


def _posture_from_record(record: dict[str, Any]) -> GCPFirewallRulePosture:
    direction = str(record.get("direction") or "INGRESS").upper()
    disabled = bool(record.get("disabled", False))
    source_ranges = list(record.get("sourceRanges") or ["0.0.0.0/0"])
    destination_ranges = list(record.get("destinationRanges") or ["0.0.0.0/0"])
    allowed = record.get("allowed") or []

    inbound_rules: list[GCPFirewallNetworkRule] = []
    outbound_rules: list[GCPFirewallNetworkRule] = []
    if not disabled and allowed:
        if direction == "EGRESS":
            outbound_rules = _network_rules_from_blocks(allowed, destination_ranges)
        else:
            inbound_rules = _network_rules_from_blocks(allowed, source_ranges)

    return GCPFirewallRulePosture(
        resource_id=str(record.get("id") or record.get("selfLink") or record.get("name") or "unknown"),
        resource_name=str(record.get("name") or "unnamed"),
        description=str(record.get("description") or ""),
        network=str(record.get("network") or "unknown"),
        priority=int(record.get("priority") or 1000),
        disabled=disabled,
        inbound_rules=inbound_rules,
        outbound_rules=outbound_rules,
        labels=dict(record.get("labels") or {}),
    )


def load_firewall_rules_from_export(path: str | Path) -> list[GCPFirewallRulePosture]:
    """
    Load GCP firewall posture from an offline gcloud JSON export.

    Deny rules and disabled rules are preserved as posture records but do not
    generate exposure rule blocks because they do not create allowed access.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [_posture_from_record(record) for record in _records_from_export(data)]


def collect_firewall_rules(project_id: str) -> list[GCPFirewallRulePosture]:
    """
    Collect GCP firewall rules for a project using read-only Compute API calls.

    Requires the optional `google-cloud-compute` package and credentials with
    `compute.firewalls.list` permission, such as the Compute Network Viewer role.
    """
    if not _GCP_COMPUTE_AVAILABLE:
        raise ImportError(
            "google-cloud-compute is required for live GCP firewall collection: "
            "pip install google-cloud-compute"
        )

    client = compute_v1.FirewallsClient()
    postures: list[GCPFirewallRulePosture] = []
    for firewall in client.list(project=project_id):
        record = type(firewall).to_dict(firewall)
        postures.append(_posture_from_record(record))
    return postures
