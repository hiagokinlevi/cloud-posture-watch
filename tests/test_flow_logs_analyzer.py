"""Tests for analyzers/flow_logs_analyzer.py."""
from analyzers.flow_logs_analyzer import analyze_vpc_flow_logs
from providers.aws.flow_logs_collector import VpcFlowLogPosture


def _posture(
    vpc_id: str = "vpc-001",
    name: str = "prod-vpc",
    enabled: bool = True,
    traffic_types: list[str] | None = None,
    interval: int | None = 60,
    destinations: list[str] | None = None,
) -> VpcFlowLogPosture:
    destination_values = (
        destinations
        if destinations is not None
        else ["arn:aws:logs:us-east-1:123456789012:log-group:vpc-flow-logs"]
    )
    return VpcFlowLogPosture(
        resource_id=vpc_id,
        resource_name=name,
        region="us-east-1",
        flow_logs_enabled=enabled,
        destinations=destination_values,
        destination_types=["cloud-watch-logs"],
        traffic_types=traffic_types or ["ALL"],
        max_aggregation_interval=interval,
        flow_log_ids=["fl-001"] if enabled else [],
        tags={"Name": name},
    )


def test_missing_flow_logs_is_high():
    findings = analyze_vpc_flow_logs([_posture(enabled=False, traffic_types=[], interval=None)])
    assert len(findings) == 1
    assert findings[0].rule_id == "FLOW-001"
    assert findings[0].severity == "high"


def test_accept_only_logs_trigger_reject_gap():
    findings = analyze_vpc_flow_logs([_posture(traffic_types=["ACCEPT"])])
    assert any(f.rule_id == "FLOW-002" and f.severity == "medium" for f in findings)


def test_all_traffic_logs_do_not_trigger_reject_gap():
    findings = analyze_vpc_flow_logs([_posture(traffic_types=["ALL"])])
    assert not any(f.rule_id == "FLOW-002" for f in findings)


def test_enabled_flow_logs_without_destination_are_medium():
    findings = analyze_vpc_flow_logs([_posture(destinations=[])])
    assert any(f.rule_id == "FLOW-004" and f.severity == "medium" for f in findings)


def test_coarse_aggregation_interval_is_low():
    findings = analyze_vpc_flow_logs([_posture(interval=600)])
    assert any(f.rule_id == "FLOW-003" and f.severity == "low" for f in findings)


def test_well_configured_vpc_has_no_findings():
    findings = analyze_vpc_flow_logs([_posture()])
    assert findings == []


def test_findings_sorted_by_severity():
    findings = analyze_vpc_flow_logs(
        [
            _posture(enabled=False, traffic_types=[], interval=None),
            _posture(traffic_types=["ACCEPT"], interval=600),
        ]
    )
    severities = [finding.severity for finding in findings]
    assert severities == sorted(severities, key={"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get)
