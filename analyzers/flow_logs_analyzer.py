"""
AWS VPC Flow Logs Analyzer
==========================
Evaluates whether AWS VPC Flow Logs provide enough network telemetry for
detection engineering and post-incident reconstruction.
"""
from __future__ import annotations

from dataclasses import dataclass

from providers.aws.flow_logs_collector import VpcFlowLogPosture


@dataclass
class FlowLogFinding:
    """A single VPC Flow Logs coverage finding."""

    provider: str
    resource_type: str
    resource_id: str
    resource_name: str
    severity: str
    rule_id: str
    title: str
    detail: str
    recommendation: str


def analyze_vpc_flow_logs(
    postures: list[VpcFlowLogPosture],
    provider: str = "aws",
    resource_type: str = "vpc",
) -> list[FlowLogFinding]:
    """Analyze VPC Flow Logs posture for logging gaps and weak telemetry settings."""
    findings: list[FlowLogFinding] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for posture in postures:
        if not posture.flow_logs_enabled:
            findings.append(
                FlowLogFinding(
                    provider=provider,
                    resource_type=resource_type,
                    resource_id=posture.resource_id,
                    resource_name=posture.resource_name,
                    severity="high",
                    rule_id="FLOW-001",
                    title="VPC has no active Flow Logs",
                    detail="No active VPC Flow Logs were detected for this network boundary.",
                    recommendation=(
                        "Enable VPC Flow Logs for the VPC and deliver them to CloudWatch Logs or S3 "
                        "so security teams can investigate inbound, lateral, and exfiltration traffic."
                    ),
                )
            )
            continue

        traffic_types = {traffic_type.upper() for traffic_type in posture.traffic_types}
        if "REJECT" not in traffic_types and "ALL" not in traffic_types:
            findings.append(
                FlowLogFinding(
                    provider=provider,
                    resource_type=resource_type,
                    resource_id=posture.resource_id,
                    resource_name=posture.resource_name,
                    severity="medium",
                    rule_id="FLOW-002",
                    title="VPC Flow Logs do not capture rejected traffic",
                    detail=(
                        "Observed traffic types: "
                        + ", ".join(sorted(traffic_types or {"unknown"}))
                    ),
                    recommendation=(
                        "Capture REJECT or ALL traffic in VPC Flow Logs so denied scans, blocked "
                        "ingress, and policy violations remain visible during investigations."
                    ),
                )
            )

        if posture.max_aggregation_interval and posture.max_aggregation_interval > 60:
            findings.append(
                FlowLogFinding(
                    provider=provider,
                    resource_type=resource_type,
                    resource_id=posture.resource_id,
                    resource_name=posture.resource_name,
                    severity="low",
                    rule_id="FLOW-003",
                    title="VPC Flow Logs use a coarse aggregation interval",
                    detail=(
                        f"Smallest active aggregation interval is "
                        f"{posture.max_aggregation_interval} seconds."
                    ),
                    recommendation=(
                        "Reduce the Flow Logs aggregation interval to 60 seconds where supported "
                        "to improve incident timelines and short-lived connection visibility."
                    ),
                )
            )

    findings.sort(key=lambda finding: severity_order.get(finding.severity, 99))
    return findings
