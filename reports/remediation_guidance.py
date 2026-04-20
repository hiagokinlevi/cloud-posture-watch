"""Remediation guidance generator.

Adds actionable remediation instructions to findings with:
- AWS CLI examples
- Console navigation hints
- Infrastructure-as-code (Terraform / CloudFormation) fix snippets

This module is intentionally lightweight and safe-by-default: if no specific
mapping exists for a finding, it returns a generic hardening recommendation.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _normalize(v: str) -> str:
    return (v or "").strip().lower().replace("-", "_").replace(" ", "_")


def _generic_guidance(finding: Dict[str, Any]) -> Dict[str, Any]:
    resource = finding.get("resource", "resource")
    return {
        "summary": "Review and remediate the insecure configuration.",
        "aws_cli": [
            f"# Inspect current configuration for {resource}",
            "aws resourcegroupstaggingapi get-resources --output table",
        ],
        "console": [
            "Open AWS Console",
            "Search for the impacted service/resource",
            "Update the flagged setting to align with your baseline",
        ],
        "iac": [
            "# Terraform: codify the secure setting in the resource definition",
            "# CloudFormation: set secure property values and deploy stack update",
        ],
    }


def _aws_s3_public_access_guidance() -> Dict[str, Any]:
    return {
        "summary": "Block public access and remove public bucket policy/ACL exposure.",
        "aws_cli": [
            "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "aws s3api put-bucket-acl --bucket <bucket-name> --acl private",
        ],
        "console": [
            "S3 > Buckets > <bucket-name> > Permissions",
            "Enable 'Block all public access'",
            "Review Bucket policy and ACL; remove public principals (e.g., '*')",
        ],
        "iac": [
            "# Terraform: aws_s3_bucket_public_access_block with all booleans = true",
            "# CloudFormation: AWS::S3::Bucket PublicAccessBlockConfiguration",
        ],
    }


def _aws_security_group_open_guidance() -> Dict[str, Any]:
    return {
        "summary": "Restrict world-open ingress rules (0.0.0.0/0, ::/0) on sensitive ports.",
        "aws_cli": [
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <trusted-cidr>",
        ],
        "console": [
            "EC2 > Security Groups > <sg-id> > Inbound rules",
            "Remove 0.0.0.0/0 or ::/0 from SSH/RDP/admin ports",
            "Add trusted corporate CIDRs or use SSM Session Manager",
        ],
        "iac": [
            "# Terraform: replace cidr_blocks = [\"0.0.0.0/0\"] with approved ranges",
            "# CloudFormation: tighten SecurityGroupIngress CidrIp/CidrIpv6",
        ],
    }


def _aws_cloudtrail_disabled_guidance() -> Dict[str, Any]:
    return {
        "summary": "Enable CloudTrail logging with validation and multi-region coverage.",
        "aws_cli": [
            "aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail --enable-log-file-validation",
            "aws cloudtrail start-logging --name <trail-name>",
        ],
        "console": [
            "CloudTrail > Trails > <trail-name>",
            "Enable logging, multi-region trail, and log file validation",
            "Ensure management events are enabled for read/write as required",
        ],
        "iac": [
            "# Terraform: aws_cloudtrail with enable_logging=true, is_multi_region_trail=true, enable_log_file_validation=true",
            "# CloudFormation: AWS::CloudTrail::Trail with IsLogging, IsMultiRegionTrail, EnableLogFileValidation",
        ],
    }


def _aws_vpc_flow_logs_missing_guidance() -> Dict[str, Any]:
    return {
        "summary": "Enable VPC Flow Logs and include rejected traffic to a durable destination.",
        "aws_cli": [
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name <log-group> --deliver-logs-permission-arn <iam-role-arn>",
        ],
        "console": [
            "VPC Console > Your VPCs > <vpc-id> > Flow logs > Create flow log",
            "Set Traffic type = ALL (or include REJECT), choose CloudWatch Logs or S3 destination",
        ],
        "iac": [
            "# Terraform: aws_flow_log with traffic_type = \"ALL\" and destination configured",
            "# CloudFormation: AWS::EC2::FlowLog with TrafficType and LogDestination",
        ],
    }


_GUIDANCE_MAP = {
    "aws_s3_public": _aws_s3_public_access_guidance,
    "s3_public": _aws_s3_public_access_guidance,
    "aws_security_group_world_open": _aws_security_group_open_guidance,
    "security_group_open": _aws_security_group_open_guidance,
    "aws_cloudtrail_disabled": _aws_cloudtrail_disabled_guidance,
    "cloudtrail_disabled": _aws_cloudtrail_disabled_guidance,
    "aws_vpc_flow_logs_missing": _aws_vpc_flow_logs_missing_guidance,
    "vpc_flow_logs_missing": _aws_vpc_flow_logs_missing_guidance,
}


def generate_remediation_guidance(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return remediation guidance for a single finding.

    Expected finding keys vary by analyzer; we attempt to map by common fields
    (`check_id`, `rule_id`, `finding_type`, `id`, `title`).
    """
    keys = [
        finding.get("check_id"),
        finding.get("rule_id"),
        finding.get("finding_type"),
        finding.get("id"),
        finding.get("title"),
    ]
    normalized = [_normalize(str(k)) for k in keys if k]

    for k in normalized:
        if k in _GUIDANCE_MAP:
            return _GUIDANCE_MAP[k]()

    return _generic_guidance(finding)


def attach_remediation_guidance(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach remediation guidance to every finding and return updated list."""
    enriched: List[Dict[str, Any]] = []
    for f in findings:
        item = dict(f)
        item["remediation"] = generate_remediation_guidance(item)
        enriched.append(item)
    return enriched
