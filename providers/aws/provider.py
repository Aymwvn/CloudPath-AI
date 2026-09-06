"""
Phase 1 (discovery) + Phase 2 (normalization/structural relationships)
for AWS.

AWSProvider is the only place that knows AWS's raw shapes. Everything it
hands back to the rest of the system is a plain Asset / Relationship
(engine/models.py) — the graph, IAM, network, and attack-path engines
never see a raw boto3 dict.
"""
from __future__ import annotations

import logging

import boto3

from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from providers.aws import collectors
from providers.base import CloudProvider

logger = logging.getLogger(__name__)


class AWSProvider(CloudProvider):
    def __init__(self, session: boto3.Session | None = None, region: str = "us-east-1"):
        self.session = session or boto3.Session(region_name=region)
        self.region = region

    # ------------------------------------------------------------------
    # Phase 1: discovery
    # ------------------------------------------------------------------
    def discover_assets(self) -> ScanResult:
        identity = collectors.get_caller_identity(self.session)
        account_id = identity["Account"]

        scan = ScanResult(account_id=account_id, provider="aws")

        for collect_fn, label in (
            (collectors.collect_iam, "iam"),
            (collectors.collect_ec2, "ec2"),
            (collectors.collect_s3, "s3"),
        ):
            try:
                raw = collect_fn(self.session)
                self._normalize(raw, label, account_id, scan)
            except Exception as exc:  # noqa: BLE001 - partial-scan tolerance
                msg = f"Collector '{label}' failed: {exc}"
                logger.warning(msg)
                scan.errors.append(msg)

        return scan

    def _normalize(self, raw: dict, label: str, account_id: str, scan: ScanResult) -> None:
        if label == "iam":
            self._normalize_iam(raw, account_id, scan)
        elif label == "ec2":
            self._normalize_ec2(raw, account_id, scan)
        elif label == "s3":
            self._normalize_s3(raw, account_id, scan)

    def _normalize_iam(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for role in raw["roles"]:
            asset_id = f"aws:iam:role/{role['RoleName']}"
            scan.assets.append(
                Asset(
                    id=asset_id,
                    type=NodeType.ROLE,
                    account_id=account_id,
                    arn=role["Arn"],
                    name=role["RoleName"],
                    raw_metadata={
                        "assume_role_policy": role.get("AssumeRolePolicyDocument"),
                        "policies": raw["policies"].get(role["RoleName"], {}),
                    },
                )
            )

        for user in raw["users"]:
            scan.assets.append(
                Asset(
                    id=f"aws:iam:user/{user['UserName']}",
                    type=NodeType.USER,
                    account_id=account_id,
                    arn=user["Arn"],
                    name=user["UserName"],
                )
            )

        for group in raw["groups"]:
            scan.assets.append(
                Asset(
                    id=f"aws:iam:group/{group['GroupName']}",
                    type=NodeType.GROUP,
                    account_id=account_id,
                    arn=group["Arn"],
                    name=group["GroupName"],
                )
            )

    def _normalize_ec2(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for vpc in raw["vpcs"]:
            scan.assets.append(
                Asset(
                    id=f"aws:vpc/{vpc['VpcId']}",
                    type=NodeType.VPC,
                    account_id=account_id,
                    region=self.region,
                    name=vpc["VpcId"],
                    raw_metadata={"cidr": vpc.get("CidrBlock")},
                )
            )

        for subnet in raw["subnets"]:
            is_public = subnet.get("MapPublicIpOnLaunch", False)
            scan.assets.append(
                Asset(
                    id=f"aws:subnet/{subnet['SubnetId']}",
                    type=NodeType.SUBNET,
                    account_id=account_id,
                    region=self.region,
                    name=subnet["SubnetId"],
                    public=is_public,
                    raw_metadata={"vpc_id": subnet["VpcId"], "cidr": subnet.get("CidrBlock")},
                )
            )
            scan.relationships.append(
                Relationship(
                    source_id=f"aws:vpc/{subnet['VpcId']}",
                    target_id=f"aws:subnet/{subnet['SubnetId']}",
                    type=EdgeType.CONTAINS,
                    evidence={"subnet_id": subnet["SubnetId"]},
                )
            )

        for sg in raw["security_groups"]:
            scan.assets.append(
                Asset(
                    id=f"aws:sg/{sg['GroupId']}",
                    type=NodeType.SECURITY_GROUP,
                    account_id=account_id,
                    region=self.region,
                    name=sg.get("GroupName", sg["GroupId"]),
                    raw_metadata={
                        "vpc_id": sg.get("VpcId"),
                        "ip_permissions": sg.get("IpPermissions", []),
                        "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
                    },
                )
            )

        for instance in raw["instances"]:
            instance_id = instance["InstanceId"]
            public_ip = instance.get("PublicIpAddress")
            asset_id = f"aws:ec2/{instance_id}"

            scan.assets.append(
                Asset(
                    id=asset_id,
                    type=NodeType.EC2,
                    account_id=account_id,
                    region=self.region,
                    name=instance_id,
                    public=bool(public_ip),
                    raw_metadata={
                        "public_ip": public_ip,
                        "subnet_id": instance.get("SubnetId"),
                        "vpc_id": instance.get("VpcId"),
                        "security_groups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
                        "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
                    },
                )
            )

            # structural edges: containment + network attachment
            if instance.get("SubnetId"):
                scan.relationships.append(
                    Relationship(
                        source_id=f"aws:subnet/{instance['SubnetId']}",
                        target_id=asset_id,
                        type=EdgeType.CONTAINS,
                        evidence={"instance_id": instance_id},
                    )
                )
            for sg in instance.get("SecurityGroups", []):
                scan.relationships.append(
                    Relationship(
                        source_id=asset_id,
                        target_id=f"aws:sg/{sg['GroupId']}",
                        type=EdgeType.USES,
                        evidence={"security_group": sg["GroupId"]},
                    )
                )
            if public_ip:
                scan.relationships.append(
                    Relationship(
                        source_id="aws:internet",
                        target_id=asset_id,
                        type=EdgeType.EXPOSED_TO,
                        evidence={"public_ip": public_ip},
                    )
                )

            # RUNS_AS edge: instance profile -> role name (best-effort parse of the ARN)
            profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")
            if profile_arn:
                # instance profile name often matches role name in simple setups;
                # exact role resolution happens via iam:list_instance_profiles_for_role
                # in a later phase. For now we record the profile as evidence.
                scan.relationships.append(
                    Relationship(
                        source_id=asset_id,
                        target_id=f"aws:iam:instance-profile/{profile_arn.split('/')[-1]}",
                        type=EdgeType.RUNS_AS,
                        evidence={"iam_instance_profile": profile_arn},
                        confidence=0.8,  # not yet resolved to an exact role, see Phase 2 notes
                    )
                )

        # ensure a single INTERNET node exists if we created any EXPOSED_TO edges
        if any(r.source_id == "aws:internet" for r in scan.relationships):
            scan.assets.append(
                Asset(
                    id="aws:internet",
                    type=NodeType.INTERNET,
                    account_id=account_id,
                    name="Internet",
                )
            )

    def _normalize_s3(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for bucket in raw["buckets"]:
            name = bucket["Name"]
            pab = bucket.get("PublicAccessBlock") or {}
            # A bucket is treated as potentially public if public access block
            # is not fully enabled AND it has a policy or public-grant ACL.
            # Full public-ness determination (policy statement parsing) is
            # handled by engine.network in Phase 4 — this is a coarse flag only.
            block_all = all(
                pab.get(k, False)
                for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
            )

            scan.assets.append(
                Asset(
                    id=f"aws:s3/{name}",
                    type=NodeType.S3,
                    account_id=account_id,
                    name=name,
                    public=not block_all,
                    raw_metadata={
                        "policy": bucket.get("Policy"),
                        "acl": bucket.get("ACL"),
                        "public_access_block": pab,
                    },
                )
            )

    # ------------------------------------------------------------------
    # Phase 2: structural relationships already added during normalization
    # above (CONTAINS, USES, EXPOSED_TO, RUNS_AS). This hook exists for any
    # cross-collector relationships that need all assets present first.
    # ------------------------------------------------------------------
    def discover_relationships(self, scan: ScanResult) -> ScanResult:
        # de-duplicate relationships that may have been added more than once
        seen = set()
        deduped: list[Relationship] = []
        for rel in scan.relationships:
            if rel.key() not in seen:
                seen.add(rel.key())
                deduped.append(rel)
        scan.relationships = deduped
        return scan
