from typing import Any, Dict, List

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _finding(resource_id: str, resource_type: str, issue: str, severity: str) -> Dict[str, Any]:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "issue": issue,
        "severity": severity,
    }


def _check_s3(buckets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    for b in buckets:
        name = b.get("name") or b.get("id")

        acl = str(b.get("acl", "")).lower()
        public_flag = b.get("public") or b.get("public_access")

        if public_flag or "public" in acl or "allusers" in acl:
            findings.append(
                _finding(
                    name,
                    "aws_s3_bucket",
                    "S3 bucket appears publicly accessible via ACL or configuration",
                    "medium",
                )
            )

    return findings


def _check_security_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    for sg in groups:
        sg_id = sg.get("group_id") or sg.get("id") or sg.get("name")
        rules = sg.get("ingress") or sg.get("ingress_rules") or []

        for r in rules:
            cidrs = r.get("cidrs") or r.get("cidr_blocks") or []
            port = r.get("port") or r.get("from_port")

            if not isinstance(cidrs, list):
                cidrs = [cidrs]

            if any(c in WORLD_CIDRS for c in cidrs):
                severity = "high" if port in [22, 3389] else "medium"

                findings.append(
                    _finding(
                        sg_id,
                        "aws_security_group",
                        f"Security group allows ingress from the internet on port {port}",
                        severity,
                    )
                )

    return findings


def _check_load_balancers(lbs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    for lb in lbs:
        lb_id = lb.get("name") or lb.get("id")
        scheme = str(lb.get("scheme", "")).lower()
        public_flag = lb.get("public") or lb.get("internet_facing")

        if public_flag or scheme == "internet-facing":
            findings.append(
                _finding(
                    lb_id,
                    "load_balancer",
                    "Load balancer is publicly accessible",
                    "medium",
                )
            )

    return findings


def _check_rds(instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    for db in instances:
        db_id = db.get("id") or db.get("db_instance_identifier") or db.get("name")

        if db.get("publicly_accessible") or db.get("public"):
            findings.append(
                _finding(
                    db_id,
                    "aws_rds_instance",
                    "RDS instance is publicly accessible",
                    "high",
                )
            )

    return findings


def analyze_public_exposure(assets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze collected cloud assets and detect publicly exposed resources.

    Expected asset structure is flexible but typically resembles:

    {
        "aws": {
            "s3_buckets": [...],
            "security_groups": [...],
            "load_balancers": [...],
            "rds_instances": [...]
        }
    }
    """

    findings: List[Dict[str, Any]] = []

    aws = assets.get("aws", {})

    findings.extend(_check_s3(aws.get("s3_buckets", [])))
    findings.extend(_check_security_groups(aws.get("security_groups", [])))
    findings.extend(_check_load_balancers(aws.get("load_balancers", [])))
    findings.extend(_check_rds(aws.get("rds_instances", [])))

    return findings
