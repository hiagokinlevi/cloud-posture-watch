"""
Unit tests for analyzers/nsg_exposure.py

Tests cover:
  - Public source detection (_is_public_source)
  - Port range parsing (_parse_port_ranges)
  - Admin port exposure (NET-AZ-001 CRITICAL)
  - Database port exposure (NET-AZ-002 HIGH)
  - Wide port range (NET-AZ-003 HIGH)
  - Web port exposure (NET-AZ-004 MEDIUM)
  - All-traffic rule (NET-AZ-005 LOW)
  - Deny rules are ignored
  - Outbound rules are ignored
  - Findings sorted by severity
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.nsg_exposure import (
    NSGFinding,
    analyze_nsg_exposure,
    _is_public_source,
    _parse_port_ranges,
)
from providers.azure.network_collector import NSGPosture, NSGRulePosture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nsg(name: str = "test-nsg", rules: list[NSGRulePosture] = None) -> NSGPosture:
    return NSGPosture(
        name=name,
        resource_group="rg-test",
        location="eastus",
        rules=rules or [],
    )


def _allow_inbound(
    name: str = "rule",
    protocol: str = "Tcp",
    source: str = "Internet",
    ports: list[str] = None,
    priority: int = 100,
) -> NSGRulePosture:
    return NSGRulePosture(
        name=name,
        description="",
        protocol=protocol,
        direction="Inbound",
        access="Allow",
        priority=priority,
        source_address_prefix=source,
        destination_port_ranges=ports or ["80"],
    )


def _deny_inbound(source: str = "Internet", ports: list[str] = None) -> NSGRulePosture:
    return NSGRulePosture(
        name="deny-rule",
        description="",
        protocol="Tcp",
        direction="Inbound",
        access="Deny",
        priority=200,
        source_address_prefix=source,
        destination_port_ranges=ports or ["22"],
    )


def _allow_outbound(ports: list[str] = None) -> NSGRulePosture:
    return NSGRulePosture(
        name="outbound-rule",
        description="",
        protocol="Tcp",
        direction="Outbound",
        access="Allow",
        priority=100,
        source_address_prefix="*",
        destination_port_ranges=ports or ["*"],
    )


def _findings_by_rule(findings: list[NSGFinding], rule_id: str) -> list[NSGFinding]:
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# _is_public_source
# ---------------------------------------------------------------------------


class TestIsPublicSource(unittest.TestCase):

    def test_internet_is_public(self):
        self.assertTrue(_is_public_source("Internet"))

    def test_wildcard_is_public(self):
        self.assertTrue(_is_public_source("*"))

    def test_any_is_public(self):
        self.assertTrue(_is_public_source("Any"))

    def test_ipv4_any_is_public(self):
        self.assertTrue(_is_public_source("0.0.0.0/0"))

    def test_ipv6_any_is_public(self):
        self.assertTrue(_is_public_source("::/0"))

    def test_specific_cidr_is_not_public(self):
        self.assertFalse(_is_public_source("10.0.0.0/8"))

    def test_virtual_network_tag_not_public(self):
        self.assertFalse(_is_public_source("VirtualNetwork"))

    def test_azure_load_balancer_not_public(self):
        self.assertFalse(_is_public_source("AzureLoadBalancer"))


# ---------------------------------------------------------------------------
# _parse_port_ranges
# ---------------------------------------------------------------------------


class TestParsePortRanges(unittest.TestCase):

    def test_wildcard_returns_full_range(self):
        ranges = _parse_port_ranges(["*"])
        self.assertEqual(ranges, [(0, 65535)])

    def test_single_port(self):
        ranges = _parse_port_ranges(["22"])
        self.assertEqual(ranges, [(22, 22)])

    def test_port_range(self):
        ranges = _parse_port_ranges(["80-443"])
        self.assertEqual(ranges, [(80, 443)])

    def test_multiple_ports(self):
        ranges = _parse_port_ranges(["22", "3389", "80"])
        self.assertIn((22, 22), ranges)
        self.assertIn((3389, 3389), ranges)
        self.assertIn((80, 80), ranges)

    def test_invalid_port_ignored(self):
        ranges = _parse_port_ranges(["abc"])
        self.assertEqual(ranges, [])


# ---------------------------------------------------------------------------
# NET-AZ-001: Admin ports
# ---------------------------------------------------------------------------


class TestAdminPortExposure(unittest.TestCase):

    def test_ssh_from_internet_is_critical(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["22"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        net_az_001 = _findings_by_rule(findings, "NET-AZ-001")
        self.assertTrue(net_az_001)
        self.assertEqual(net_az_001[0].severity, "critical")

    def test_rdp_from_wildcard_is_critical(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["3389"], source="*")])
        findings = analyze_nsg_exposure([nsg])
        net_az_001 = _findings_by_rule(findings, "NET-AZ-001")
        self.assertTrue(net_az_001)

    def test_vnc_port_is_critical(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["5900"], source="0.0.0.0/0")])
        findings = analyze_nsg_exposure([nsg])
        net_az_001 = _findings_by_rule(findings, "NET-AZ-001")
        self.assertTrue(net_az_001)

    def test_ssh_from_private_range_not_flagged(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["22"], source="10.0.0.0/8")])
        findings = analyze_nsg_exposure([nsg])
        self.assertFalse(_findings_by_rule(findings, "NET-AZ-001"))

    def test_deny_ssh_from_internet_not_flagged(self):
        nsg = _nsg(rules=[_deny_inbound(source="Internet", ports=["22"])])
        findings = analyze_nsg_exposure([nsg])
        self.assertFalse(_findings_by_rule(findings, "NET-AZ-001"))


# ---------------------------------------------------------------------------
# NET-AZ-002: Database ports
# ---------------------------------------------------------------------------


class TestDatabasePortExposure(unittest.TestCase):

    def test_mysql_from_internet_is_high(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["3306"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        net_az_002 = _findings_by_rule(findings, "NET-AZ-002")
        self.assertTrue(net_az_002)
        self.assertEqual(net_az_002[0].severity, "high")

    def test_postgres_from_wildcard_is_high(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["5432"], source="*")])
        findings = analyze_nsg_exposure([nsg])
        self.assertTrue(_findings_by_rule(findings, "NET-AZ-002"))

    def test_redis_from_internet_is_high(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["6379"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        self.assertTrue(_findings_by_rule(findings, "NET-AZ-002"))

    def test_db_port_from_private_not_flagged(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["5432"], source="10.0.0.0/8")])
        findings = analyze_nsg_exposure([nsg])
        self.assertFalse(_findings_by_rule(findings, "NET-AZ-002"))


# ---------------------------------------------------------------------------
# NET-AZ-003: Wide port range
# ---------------------------------------------------------------------------


class TestWidePortRange(unittest.TestCase):

    def test_all_ports_wildcard_is_high(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["*"], source="Internet", protocol="Tcp")])
        findings = analyze_nsg_exposure([nsg])
        self.assertTrue(_findings_by_rule(findings, "NET-AZ-003"))

    def test_large_range_is_high(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["1000-9999"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        net_az_003 = _findings_by_rule(findings, "NET-AZ-003")
        self.assertTrue(net_az_003)
        self.assertEqual(net_az_003[0].severity, "high")

    def test_small_range_not_flagged_for_003(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["80-443"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        self.assertFalse(_findings_by_rule(findings, "NET-AZ-003"))


# ---------------------------------------------------------------------------
# NET-AZ-004: Web ports
# ---------------------------------------------------------------------------


class TestWebPortExposure(unittest.TestCase):

    def test_http_from_internet_is_medium(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["80"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        net_az_004 = _findings_by_rule(findings, "NET-AZ-004")
        self.assertTrue(net_az_004)
        self.assertEqual(net_az_004[0].severity, "medium")

    def test_https_from_internet_is_medium(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["443"], source="Internet")])
        findings = analyze_nsg_exposure([nsg])
        self.assertTrue(_findings_by_rule(findings, "NET-AZ-004"))

    def test_web_from_private_not_flagged(self):
        nsg = _nsg(rules=[_allow_inbound(ports=["80"], source="VirtualNetwork")])
        findings = analyze_nsg_exposure([nsg])
        self.assertFalse(_findings_by_rule(findings, "NET-AZ-004"))


# ---------------------------------------------------------------------------
# Outbound rules ignored
# ---------------------------------------------------------------------------


class TestOutboundRulesIgnored(unittest.TestCase):

    def test_outbound_all_traffic_not_flagged(self):
        nsg = _nsg(rules=[_allow_outbound(ports=["*"])])
        findings = analyze_nsg_exposure([nsg])
        # No critical/high findings for outbound all-traffic
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        self.assertFalse(critical_high)


# ---------------------------------------------------------------------------
# Findings sorted by severity
# ---------------------------------------------------------------------------


class TestFindingsSorting(unittest.TestCase):

    def test_critical_before_high_before_medium(self):
        nsg = _nsg(rules=[
            _allow_inbound(name="web", ports=["80"], source="Internet"),    # MEDIUM
            _allow_inbound(name="ssh", ports=["22"], source="Internet"),    # CRITICAL
            _allow_inbound(name="mysql", ports=["3306"], source="Internet"),# HIGH
        ])
        findings = analyze_nsg_exposure([nsg])
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [severity_rank[f.severity] for f in findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_empty_nsg_list_returns_empty(self):
        self.assertEqual(analyze_nsg_exposure([]), [])

    def test_nsg_with_no_rules_returns_empty(self):
        nsg = _nsg(rules=[])
        self.assertEqual(analyze_nsg_exposure([nsg]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
