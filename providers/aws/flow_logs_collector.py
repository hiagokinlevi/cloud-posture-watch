"""
AWS VPC Flow Logs Collector
===========================
Collects AWS VPC Flow Logs posture so assessments can verify whether
network telemetry is enabled with enough fidelity for investigation.

Permissions required:
  - ec2:DescribeVpcs
  - ec2:DescribeFlowLogs
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class VpcFlowLogPosture:
    """Normalized VPC Flow Logs posture for defensive telemetry checks."""

    resource_id: str
    resource_name: str
    region: Optional[str]
    flow_logs_enabled: bool
    destinations: list[str] = field(default_factory=list)
    destination_types: list[str] = field(default_factory=list)
    traffic_types: list[str] = field(default_factory=list)
    max_aggregation_interval: Optional[int] = None
    flow_log_ids: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


def collect_vpc_flow_log_postures(
    session,
    region: Optional[str] = None,
    filters: Optional[list[dict]] = None,
) -> list[VpcFlowLogPosture]:
    """
    Collect VPC posture enriched with VPC Flow Logs coverage details.

    Args:
        session: boto3.Session-compatible object.
        region: AWS region to query. If None, uses the session default region.
        filters: Optional VPC filters for describe_vpcs().

    Returns:
        One posture object per discovered VPC.
    """
    ec2 = session.client("ec2", region_name=region)
    kwargs: dict[str, object] = {}
    if filters:
        kwargs["Filters"] = filters

    vpcs: list[dict] = []
    paginator = ec2.get_paginator("describe_vpcs")
    for page in paginator.paginate(**kwargs):
        vpcs.extend(page.get("Vpcs", []))

    vpc_ids = [vpc.get("VpcId", "") for vpc in vpcs if vpc.get("VpcId")]
    flow_logs_by_vpc: dict[str, list[dict]] = {vpc_id: [] for vpc_id in vpc_ids}

    if vpc_ids:
        for chunk_start in range(0, len(vpc_ids), 200):
            chunk = vpc_ids[chunk_start:chunk_start + 200]
            flow_paginator = ec2.get_paginator("describe_flow_logs")
            for page in flow_paginator.paginate(
                Filter=[
                    {"Name": "resource-id", "Values": chunk},
                    {"Name": "resource-type", "Values": ["VPC"]},
                ]
            ):
                for flow_log in page.get("FlowLogs", []):
                    resource_id = flow_log.get("ResourceId")
                    if resource_id in flow_logs_by_vpc:
                        flow_logs_by_vpc[resource_id].append(flow_log)

    postures: list[VpcFlowLogPosture] = []
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "unknown")
        tags = {tag["Key"]: tag["Value"] for tag in vpc.get("Tags", [])}
        name = tags.get("Name", vpc_id)
        flow_logs = [
            log_entry
            for log_entry in flow_logs_by_vpc.get(vpc_id, [])
            if str(log_entry.get("FlowLogStatus", "")).upper() in {"ACTIVE", "PENDING"}
        ]

        postures.append(
            VpcFlowLogPosture(
                resource_id=vpc_id,
                resource_name=name,
                region=region or session.region_name,
                flow_logs_enabled=bool(flow_logs),
                destinations=[
                    destination
                    for destination in (
                        log_entry.get("LogDestination") or log_entry.get("LogGroupName")
                        for log_entry in flow_logs
                    )
                    if destination
                ],
                destination_types=[
                    str(log_entry.get("LogDestinationType", "cloud-watch-logs"))
                    for log_entry in flow_logs
                ],
                traffic_types=[
                    str(log_entry.get("TrafficType", "ALL")).upper()
                    for log_entry in flow_logs
                ],
                max_aggregation_interval=_smallest_interval(flow_logs),
                flow_log_ids=[
                    str(log_entry.get("FlowLogId"))
                    for log_entry in flow_logs
                    if log_entry.get("FlowLogId")
                ],
                tags=tags,
            )
        )

    log.info("Collected %s VPC flow-log posture object(s)", len(postures))
    return postures


def _smallest_interval(flow_logs: list[dict]) -> Optional[int]:
    """Return the smallest aggregation interval across active flow logs."""
    intervals = [
        int(flow_log["MaxAggregationInterval"])
        for flow_log in flow_logs
        if flow_log.get("MaxAggregationInterval") is not None
    ]
    return min(intervals) if intervals else None
