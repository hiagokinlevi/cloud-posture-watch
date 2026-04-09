"""Unit tests for the network exposure analyzer."""
import pytest

from analyzers.network_exposure import (
    NetworkFinding,
    SecurityGroupPosture as _Posture,
    analyze_network_exposure,
)
from providers.aws.network_collector import NetworkRule, SecurityGroupPosture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sg(
    sg_id: str = "sg-001",
    name: str = "test-sg",
    inbound: list[NetworkRule] | None = None,
    outbound: list[NetworkRule] | None = None,
) -> SecurityGroupPosture:
    return SecurityGroupPosture(
        resource_id=sg_id,
        resource_name=name,
        description="test",
        vpc_id="vpc-001",
        inbound_rules=inbound or [],
        outbound_rules=outbound or [],
    )


def _rule(protocol="tcp", from_port=80, to_port=80, cidrs=None) -> NetworkRule:
    return NetworkRule(
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_ranges=cidrs or ["0.0.0.0/0"],
    )


def _finding_ids(findings: list[NetworkFinding]) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# Clean SG — no public exposure
# ---------------------------------------------------------------------------


def test_private_sg_no_findings():
    sg = _sg(inbound=[_rule(cidrs=["10.0.0.0/8"])])
    findings = analyze_network_exposure([sg])
    assert findings == []


# ---------------------------------------------------------------------------
# Admin port checks
# ---------------------------------------------------------------------------


def test_ssh_open_to_internet_is_critical():
    sg = _sg(inbound=[_rule(from_port=22, to_port=22)])
    findings = analyze_network_exposure([sg])
    ssh_findings = [f for f in findings if f.rule_id == "NET002" and "22" in f.detail]
    assert ssh_findings
    assert ssh_findings[0].severity == "critical"


def test_rdp_open_to_internet_is_critical():
    sg = _sg(inbound=[_rule(from_port=3389, to_port=3389)])
    findings = analyze_network_exposure([sg])
    rdp = [f for f in findings if "3389" in f.detail]
    assert rdp
    assert rdp[0].severity == "critical"


def test_ssh_restricted_to_vpn_no_critical():
    sg = _sg(inbound=[_rule(from_port=22, to_port=22, cidrs=["192.168.1.0/24"])])
    findings = analyze_network_exposure([sg])
    assert not any(f.severity == "critical" for f in findings)


# ---------------------------------------------------------------------------
# Database port checks
# ---------------------------------------------------------------------------


def test_postgres_public_is_high():
    sg = _sg(inbound=[_rule(from_port=5432, to_port=5432)])
    findings = analyze_network_exposure([sg])
    db_findings = [f for f in findings if f.rule_id == "NET003"]
    assert db_findings
    assert db_findings[0].severity == "high"


def test_mysql_public_is_high():
    sg = _sg(inbound=[_rule(from_port=3306, to_port=3306)])
    findings = analyze_network_exposure([sg])
    assert any(f.rule_id == "NET003" and "3306" in f.detail for f in findings)


def test_redis_public_is_high():
    sg = _sg(inbound=[_rule(from_port=6379, to_port=6379)])
    findings = analyze_network_exposure([sg])
    assert any(f.rule_id == "NET003" for f in findings)


# ---------------------------------------------------------------------------
# Wide port range
# ---------------------------------------------------------------------------


def test_wide_port_range_is_high():
    sg = _sg(inbound=[_rule(from_port=1024, to_port=65535)])
    findings = analyze_network_exposure([sg])
    assert any(f.rule_id == "NET004" for f in findings)


def test_narrow_range_no_net004():
    sg = _sg(inbound=[_rule(from_port=80, to_port=85)])  # 6 ports — not wide
    findings = analyze_network_exposure([sg])
    assert not any(f.rule_id == "NET004" for f in findings)


# ---------------------------------------------------------------------------
# Web port check (MEDIUM)
# ---------------------------------------------------------------------------


def test_http_public_is_medium():
    sg = _sg(inbound=[_rule(from_port=80, to_port=80)])
    findings = analyze_network_exposure([sg])
    http = [f for f in findings if f.rule_id == "NET005" and "80" in f.detail]
    assert http
    assert http[0].severity == "medium"


def test_https_public_is_medium():
    sg = _sg(inbound=[_rule(from_port=443, to_port=443)])
    findings = analyze_network_exposure([sg])
    https = [f for f in findings if f.rule_id == "NET005" and "443" in f.detail]
    assert https


# ---------------------------------------------------------------------------
# All-traffic rule
# ---------------------------------------------------------------------------


def test_all_traffic_inbound_is_low():
    sg = _sg(inbound=[_rule(protocol="-1", from_port=-1, to_port=-1)])
    findings = analyze_network_exposure([sg])
    all_traffic = [f for f in findings if f.rule_id == "NET001"]
    assert all_traffic
    assert all_traffic[0].severity == "low"


def test_all_traffic_egress_is_info():
    sg = _sg(outbound=[_rule(protocol="-1", from_port=-1, to_port=-1)])
    findings = analyze_network_exposure([sg])
    egress = [f for f in findings if f.rule_id == "NET006"]
    assert egress
    assert egress[0].severity == "info"


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------


def test_findings_sorted_by_severity():
    sg = _sg(inbound=[
        _rule(from_port=443, to_port=443),   # MEDIUM (NET005)
        _rule(from_port=22, to_port=22),     # CRITICAL (NET002)
        _rule(from_port=5432, to_port=5432), # HIGH (NET003)
    ])
    findings = analyze_network_exposure([sg])
    severities = [f.severity for f in findings]
    # critical should come before high, high before medium
    first_critical = next((i for i, s in enumerate(severities) if s == "critical"), None)
    first_medium = next((i for i, s in enumerate(severities) if s == "medium"), None)
    if first_critical is not None and first_medium is not None:
        assert first_critical < first_medium


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


def test_ipv6_public_cidr_detected():
    sg = _sg(inbound=[_rule(from_port=22, to_port=22, cidrs=["::/0"])])
    findings = analyze_network_exposure([sg])
    critical = [f for f in findings if f.severity == "critical"]
    assert critical
