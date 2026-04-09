"""
Azure Network Security Group (NSG) Collector
=============================================
Collects Azure NSG inbound/outbound rules to assess network exposure.

An NSG is Azure's equivalent of an AWS Security Group — it controls which
traffic is allowed into and out of attached subnets or VM network interfaces.

Permissions required (read-only):
  - Reader role on the target subscription, or at minimum:
    Microsoft.Network/networkSecurityGroups/read
    Microsoft.Network/networkSecurityGroups/securityRules/read

Use only on subscriptions you are authorised to assess.

Data collected per rule:
  - name, description, protocol (Tcp/Udp/*)
  - source/destination address prefix (CIDR, service tag, or *)
  - source/destination port range(s)
  - access (Allow/Deny) and direction (Inbound/Outbound)
  - priority (lower = higher priority, 100–65500)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    _AZURE_AVAILABLE = True
except ImportError:
    _AZURE_AVAILABLE = False


@dataclass
class NSGRulePosture:
    """Normalized representation of a single NSG security rule."""

    name: str
    description: str
    protocol: str                 # "Tcp", "Udp", "Icmp", or "*" (all)
    direction: str                # "Inbound" or "Outbound"
    access: str                   # "Allow" or "Deny"
    priority: int                 # 100–65500; lower = processed first
    source_address_prefix: str    # CIDR, service tag (e.g. "Internet"), or "*"
    destination_port_ranges: list[str]  # List of port strings, e.g. ["22", "80-8080"]


@dataclass
class NSGPosture:
    """Posture data for a single Azure Network Security Group."""

    name: str
    resource_group: str
    location: str
    rules: list[NSGRulePosture] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)


def _build_credential(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
):
    """
    Build an Azure credential.

    Falls back to DefaultAzureCredential when service principal fields are absent.
    """
    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    return DefaultAzureCredential()


def _normalize_port_ranges(
    port_range: Optional[str],
    port_ranges: Optional[list[str]],
) -> list[str]:
    """
    Normalize a rule's port specification to a flat list of strings.

    The Azure SDK may return either `destination_port_range` (single) or
    `destination_port_ranges` (multi), depending on how the rule was created.
    We consolidate both into one list.
    """
    result: list[str] = []
    if port_ranges:
        result.extend(str(p) for p in port_ranges if p)
    if port_range and port_range not in result:
        result.append(str(port_range))
    return result or ["*"]


def collect_nsgs(
    subscription_id: str,
    resource_group: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> list[NSGPosture]:
    """
    Collect all NSGs in a subscription (or a specific resource group).

    All API calls are read-only — no modifications are made to any NSG.

    Args:
        subscription_id: Azure subscription ID to scan.
        resource_group:  If provided, only collect NSGs from this resource group.
                         If None, collect from all resource groups.
        tenant_id:       Azure AD tenant ID (for service principal auth).
        client_id:       Service principal application (client) ID.
        client_secret:   Service principal secret.

    Returns:
        List of NSGPosture objects, one per NSG.

    Raises:
        ImportError: If the azure-mgmt-network package is not installed.
        azure.core.exceptions.AzureError: On API access failure.
    """
    if not _AZURE_AVAILABLE:
        raise ImportError(
            "azure-mgmt-network and azure-identity are required: "
            "pip install azure-mgmt-network azure-identity"
        )

    credential = _build_credential(tenant_id, client_id, client_secret)
    client = NetworkManagementClient(credential, subscription_id)

    postures: list[NSGPosture] = []

    # Use resource-group-scoped list if a group is specified, otherwise list all
    if resource_group:
        nsg_iter = client.network_security_groups.list(resource_group)
    else:
        nsg_iter = client.network_security_groups.list_all()

    for nsg in nsg_iter:
        # Parse resource group from the NSG's resource ID
        nsg_rg = resource_group or (nsg.id or "").split("/")[4] if nsg.id else "unknown"

        rules: list[NSGRulePosture] = []
        for rule in (nsg.security_rules or []):
            rules.append(NSGRulePosture(
                name=rule.name or "unnamed",
                description=rule.description or "",
                protocol=rule.protocol or "*",
                direction=rule.direction or "Inbound",
                access=rule.access or "Allow",
                priority=rule.priority or 65500,
                source_address_prefix=rule.source_address_prefix or "*",
                destination_port_ranges=_normalize_port_ranges(
                    rule.destination_port_range,
                    rule.destination_port_ranges,
                ),
            ))

        posture = NSGPosture(
            name=nsg.name or "unnamed",
            resource_group=nsg_rg,
            location=nsg.location or "unknown",
            rules=rules,
        )
        postures.append(posture)

    return postures
