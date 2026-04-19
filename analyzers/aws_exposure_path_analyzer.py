from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from typing import Any, Dict, List, Optional, Set, Tuple


INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass
class ExposurePathFinding:
    target_id: str
    target_type: str
    target_subnet_id: Optional[str]
    reachable_ports: List[str]
    internet_via: str
    route_table_id: Optional[str]
    security_group_ids: List[str]
    path: List[str]
    severity: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "target_subnet_id": self.target_subnet_id,
            "reachable_ports": self.reachable_ports,
            "internet_via": self.internet_via,
            "route_table_id": self.route_table_id,
            "security_group_ids": self.security_group_ids,
            "path": self.path,
            "severity": self.severity,
        }


def _is_world_source(cidr: Optional[str], cidr_v6: Optional[str]) -> bool:
    return (cidr in INTERNET_CIDRS) or (cidr_v6 in INTERNET_CIDRS)


def _extract_open_ports(ip_permissions: List[Dict[str, Any]]) -> List[str]:
    open_ports: Set[str] = set()
    for perm in ip_permissions or []:
        ranges_v4 = perm.get("IpRanges", [])
        ranges_v6 = perm.get("Ipv6Ranges", [])
        world = any(_is_world_source(r.get("CidrIp"), None) for r in ranges_v4) or any(
            _is_world_source(None, r.get("CidrIpv6")) for r in ranges_v6
        )
        if not world:
            continue

        proto = perm.get("IpProtocol", "-1")
        if proto == "-1":
            open_ports.add("all")
            continue

        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if from_port is None or to_port is None:
            open_ports.add(f"{proto}:all")
        elif from_port == to_port:
            open_ports.add(f"{proto}:{from_port}")
        else:
            open_ports.add(f"{proto}:{from_port}-{to_port}")

    return sorted(open_ports)


def _subnet_is_public(subnet_id: str, route_tables: List[Dict[str, Any]], associations: Dict[str, str]) -> Tuple[bool, Optional[str], Optional[str]]:
    rt_id = associations.get(subnet_id)
    if not rt_id:
        return False, None, None

    table = next((t for t in route_tables if t.get("RouteTableId") == rt_id), None)
    if not table:
        return False, rt_id, None

    for route in table.get("Routes", []):
        dest_v4 = route.get("DestinationCidrBlock")
        dest_v6 = route.get("DestinationIpv6CidrBlock")
        is_default = dest_v4 == "0.0.0.0/0" or dest_v6 == "::/0"
        if not is_default:
            continue

        gateway_id = route.get("GatewayId") or route.get("EgressOnlyInternetGatewayId")
        transit = route.get("TransitGatewayId")
        nat = route.get("NatGatewayId")
        if gateway_id and str(gateway_id).startswith("igw-"):
            return True, rt_id, gateway_id
        if transit or nat:
            continue

    return False, rt_id, None


def analyze_aws_exposure_paths(evidence: Dict[str, Any]) -> Dict[str, Any]:
    security_groups = evidence.get("security_groups", [])
    subnets = evidence.get("subnets", [])
    route_tables = evidence.get("route_tables", [])
    enis = evidence.get("network_interfaces", [])
    load_balancers = evidence.get("load_balancers", [])

    sg_open_ports: Dict[str, List[str]] = {
        sg.get("GroupId"): _extract_open_ports(sg.get("IpPermissions", []))
        for sg in security_groups
        if sg.get("GroupId")
    }

    subnet_to_rt: Dict[str, str] = {}
    main_rt_by_vpc: Dict[str, str] = {}
    for rt in route_tables:
        rt_id = rt.get("RouteTableId")
        if not rt_id:
            continue
        for assoc in rt.get("Associations", []):
            if assoc.get("Main") and rt.get("VpcId"):
                main_rt_by_vpc[rt["VpcId"]] = rt_id
            subnet_id = assoc.get("SubnetId")
            if subnet_id:
                subnet_to_rt[subnet_id] = rt_id

    for subnet in subnets:
        sid = subnet.get("SubnetId")
        vpc_id = subnet.get("VpcId")
        if sid and sid not in subnet_to_rt and vpc_id in main_rt_by_vpc:
            subnet_to_rt[sid] = main_rt_by_vpc[vpc_id]

    findings: List[ExposurePathFinding] = []

    for eni in enis:
        eni_id = eni.get("NetworkInterfaceId")
        subnet_id = eni.get("SubnetId")
        sg_ids = [g.get("GroupId") for g in eni.get("Groups", []) if g.get("GroupId")]
        if not eni_id or not subnet_id or not sg_ids:
            continue

        open_ports = sorted({p for sgid in sg_ids for p in sg_open_ports.get(sgid, [])})
        if not open_ports:
            continue

        is_public, rt_id, via = _subnet_is_public(subnet_id, route_tables, subnet_to_rt)
        if not is_public:
            continue

        findings.append(
            ExposurePathFinding(
                target_id=eni_id,
                target_type="network-interface",
                target_subnet_id=subnet_id,
                reachable_ports=open_ports,
                internet_via=via or "igw",
                route_table_id=rt_id,
                security_group_ids=sg_ids,
                path=["internet", via or "igw", rt_id or "route-table", subnet_id, eni_id],
            )
        )

    for lb in load_balancers:
        lb_id = lb.get("LoadBalancerArn") or lb.get("LoadBalancerName")
        scheme = (lb.get("Scheme") or "").lower()
        if not lb_id or scheme != "internet-facing":
            continue

        sg_ids = lb.get("SecurityGroups", []) or []
        open_ports = sorted({p for sgid in sg_ids for p in sg_open_ports.get(sgid, [])})
        if not open_ports:
            continue

        subnet_ids = lb.get("AvailabilityZones", [])
        normalized_subnets = []
        for az in subnet_ids:
            if isinstance(az, dict):
                sid = az.get("SubnetId")
                if sid:
                    normalized_subnets.append(sid)
            elif isinstance(az, str):
                normalized_subnets.append(az)

        for subnet_id in normalized_subnets:
            is_public, rt_id, via = _subnet_is_public(subnet_id, route_tables, subnet_to_rt)
            if not is_public:
                continue
            findings.append(
                ExposurePathFinding(
                    target_id=lb_id,
                    target_type="load-balancer",
                    target_subnet_id=subnet_id,
                    reachable_ports=open_ports,
                    internet_via=via or "igw",
                    route_table_id=rt_id,
                    security_group_ids=sg_ids,
                    path=["internet", via or "igw", rt_id or "route-table", subnet_id, lb_id],
                )
            )

    return {
        "analyzer": "aws_exposure_path_analyzer",
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_paths": len(findings),
            "internet_reachable_internal_services": len(findings),
        },
    }
