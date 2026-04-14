import json
import sqlite3
import datetime
from typing import Dict, List, Any

import boto3

ASSET_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    account_id TEXT,
    region TEXT,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_type TEXT,
    name TEXT,
    data JSON,
    collected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_provider_service
ON assets(provider, service);

CREATE INDEX IF NOT EXISTS idx_assets_resource_id
ON assets(resource_id);
"""


class AWSInventoryCollector:
    """
    Collects AWS resource metadata using AssumeRole and stores normalized
    asset records in a SQLite datastore.
    """

    def __init__(self, role_arn: str, db_path: str = "cloud_posture_watch.db", regions: List[str] = None):
        self.role_arn = role_arn
        self.db_path = db_path
        self.regions = regions or ["us-east-1"]

        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(ASSET_SCHEMA_SQL)
        self.conn.commit()

        self.session = self._assume_role_session()
        self.account_id = self._get_account_id()

    def _assume_role_session(self):
        sts = boto3.client("sts")
        resp = sts.assume_role(RoleArn=self.role_arn, RoleSessionName="cloud-posture-watch")

        creds = resp["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def _get_account_id(self) -> str:
        sts = self.session.client("sts")
        return sts.get_caller_identity()["Account"]

    def _store_asset(self, region: str, service: str, resource_id: str, resource_type: str, name: str, data: Dict[str, Any]):
        self.conn.execute(
            """
            INSERT INTO assets(provider, account_id, region, service, resource_id, resource_type, name, data, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "aws",
                self.account_id,
                region,
                service,
                resource_id,
                resource_type,
                name,
                json.dumps(data),
                datetime.datetime.utcnow().isoformat(),
            ),
        )

    def collect(self):
        for region in self.regions:
            self._collect_ec2(region)
            self._collect_security_groups(region)
            self._collect_vpcs(region)
            self._collect_rds(region)
            self._collect_lambda(region)
            self._collect_s3(region)

        self._collect_iam()
        self.conn.commit()

    def _collect_ec2(self, region: str):
        client = self.session.client("ec2", region_name=region)
        paginator = client.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    instance_id = inst.get("InstanceId")
                    name = None
                    for tag in inst.get("Tags", []):
                        if tag.get("Key") == "Name":
                            name = tag.get("Value")

                    self._store_asset(
                        region,
                        "ec2",
                        instance_id,
                        "instance",
                        name,
                        inst,
                    )

    def _collect_security_groups(self, region: str):
        client = self.session.client("ec2", region_name=region)
        resp = client.describe_security_groups()

        for sg in resp.get("SecurityGroups", []):
            self._store_asset(
                region,
                "ec2",
                sg.get("GroupId"),
                "security_group",
                sg.get("GroupName"),
                sg,
            )

    def _collect_vpcs(self, region: str):
        client = self.session.client("ec2", region_name=region)
        resp = client.describe_vpcs()

        for vpc in resp.get("Vpcs", []):
            self._store_asset(
                region,
                "ec2",
                vpc.get("VpcId"),
                "vpc",
                vpc.get("VpcId"),
                vpc,
            )

    def _collect_rds(self, region: str):
        client = self.session.client("rds", region_name=region)
        paginator = client.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                self._store_asset(
                    region,
                    "rds",
                    db.get("DBInstanceIdentifier"),
                    "db_instance",
                    db.get("DBInstanceIdentifier"),
                    db,
                )

    def _collect_lambda(self, region: str):
        client = self.session.client("lambda", region_name=region)
        paginator = client.get_paginator("list_functions")

        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                self._store_asset(
                    region,
                    "lambda",
                    fn.get("FunctionArn"),
                    "function",
                    fn.get("FunctionName"),
                    fn,
                )

    def _collect_s3(self, region: str):
        client = self.session.client("s3")
        resp = client.list_buckets()

        for bucket in resp.get("Buckets", []):
            name = bucket.get("Name")
            self._store_asset(
                region,
                "s3",
                name,
                "bucket",
                name,
                bucket,
            )

    def _collect_iam(self):
        client = self.session.client("iam")

        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                self._store_asset(
                    "global",
                    "iam",
                    user.get("UserName"),
                    "user",
                    user.get("UserName"),
                    user,
                )

        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                self._store_asset(
                    "global",
                    "iam",
                    role.get("RoleName"),
                    "role",
                    role.get("RoleName"),
                    role,
                )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AWS Resource Inventory Collector")
    parser.add_argument("--role-arn", required=True, help="Role ARN to assume for collection")
    parser.add_argument("--db", default="cloud_posture_watch.db", help="SQLite DB path")
    parser.add_argument("--regions", nargs="+", default=["us-east-1"], help="AWS regions")

    args = parser.parse_args()

    collector = AWSInventoryCollector(
        role_arn=args.role_arn,
        db_path=args.db,
        regions=args.regions,
    )

    collector.collect()

    print("Inventory collection complete.")
