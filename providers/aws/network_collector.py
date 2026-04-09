"""
AWS Security Group Collector
==============================
Collects AWS EC2 Security Group configurations and converts them to a
normalized SecurityGroupPosture format suitable for the network exposure analyzer.

No active probing is performed — only read-only AWS API calls are made.

Permissions required:
  - ec2:DescribeSecurityGroups
  - ec2:DescribeVpcs (optional, for VPC name resolution)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class NetworkRule:
    """A single inbound or outbound security group rule."""

    protocol: str            # "tcp", "udp", "icmp", "-1" (all)
    from_port: int           # -1 means all ports
    to_port: int             # -1 means all ports
    cidr_ranges: list[str]   # IPv4 and IPv6 CIDR blocks


@dataclass
class SecurityGroupPosture:
    """Normalized security group posture for cross-analyzer consumption."""

    resource_id: str          # Security group ID (e.g. sg-0abc123)
    resource_name: str        # Security group name
    description: str
    vpc_id: Optional[str]
    inbound_rules: list[NetworkRule] = field(default_factory=list)
    outbound_rules: list[NetworkRule] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


def collect_security_groups(
    session,  # boto3.Session — typed as Any to avoid hard dependency in tests
    region: Optional[str] = None,
    filters: Optional[list[dict]] = None,
) -> list[SecurityGroupPosture]:
    """
    Collect all EC2 Security Groups in an AWS account/region.

    Args:
        session:  A boto3 Session object with ec2:DescribeSecurityGroups permissions.
        region:   AWS region to query. If None, uses the session's default region.
        filters:  Optional list of EC2 describe filters (e.g. filter by VPC).

    Returns:
        List of SecurityGroupPosture objects, one per security group.
    """
    ec2 = session.client("ec2", region_name=region)
    postures: list[SecurityGroupPosture] = []

    kwargs: dict = {}
    if filters:
        kwargs["Filters"] = filters

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(**kwargs):
        for sg in page.get("SecurityGroups", []):
            sg_id = sg.get("GroupId", "unknown")
            sg_name = sg.get("GroupName", sg_id)

            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

            inbound = [
                _normalize_rule(rule)
                for rule in sg.get("IpPermissions", [])
            ]
            outbound = [
                _normalize_rule(rule)
                for rule in sg.get("IpPermissionsEgress", [])
            ]

            postures.append(SecurityGroupPosture(
                resource_id=sg_id,
                resource_name=sg_name,
                description=sg.get("Description", ""),
                vpc_id=sg.get("VpcId"),
                inbound_rules=inbound,
                outbound_rules=outbound,
                tags=tags,
            ))

    log.info(f"Collected {len(postures)} security groups")
    return postures


def _normalize_rule(ip_permission: dict) -> NetworkRule:
    """
    Convert an AWS IpPermission dict to a normalized NetworkRule.

    AWS uses -1 as IpProtocol for all-traffic rules and may omit
    FromPort/ToPort for ICMP/all-protocol rules.
    """
    protocol = str(ip_permission.get("IpProtocol", "-1"))

    # AWS uses -1 to mean "all protocols"
    from_port: int = ip_permission.get("FromPort", -1)
    to_port: int = ip_permission.get("ToPort", -1)

    cidrs: list[str] = []
    # IPv4 CIDR ranges
    for ip_range in ip_permission.get("IpRanges", []):
        cidr = ip_range.get("CidrIp")
        if cidr:
            cidrs.append(cidr)

    # IPv6 CIDR ranges
    for ip6_range in ip_permission.get("Ipv6Ranges", []):
        cidr6 = ip6_range.get("CidrIpv6")
        if cidr6:
            cidrs.append(cidr6)

    return NetworkRule(
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_ranges=cidrs,
    )
