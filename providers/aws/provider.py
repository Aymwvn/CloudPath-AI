"""
AWSProvider — the only place that knows AWS's raw shapes. Everything it
hands back to the rest of the system is a plain Asset / Relationship.
"""
from __future__ import annotations

import json
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

    def discover_assets(self) -> ScanResult:
        identity = collectors.get_caller_identity(self.session)
        account_id = identity["Account"]

        scan = ScanResult(account_id=account_id, provider="aws")

        for collect_fn, label in (
            (collectors.collect_iam, "iam"),
            (collectors.collect_ec2, "ec2"),
            (collectors.collect_s3, "s3"),
            (collectors.collect_lambda, "lambda"),
            (collectors.collect_rds, "rds"),
            (collectors.collect_secrets_manager, "secrets_manager"),
            (collectors.collect_kms, "kms"),
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
        {
            "iam": self._normalize_iam,
            "ec2": self._normalize_ec2,
            "s3": self._normalize_s3,
            "lambda": self._normalize_lambda,
            "rds": self._normalize_rds,
            "secrets_manager": self._normalize_secrets_manager,
            "kms": self._normalize_kms,
        }[label](raw, account_id, scan)

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
                Asset(id=f"aws:iam:user/{user['UserName']}", type=NodeType.USER, account_id=account_id,
                      arn=user["Arn"], name=user["UserName"])
            )
        for group in raw["groups"]:
            scan.assets.append(
                Asset(id=f"aws:iam:group/{group['GroupName']}", type=NodeType.GROUP, account_id=account_id,
                      arn=group["Arn"], name=group["GroupName"])
            )

    def _normalize_ec2(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for vpc in raw["vpcs"]:
            scan.assets.append(
                Asset(id=f"aws:vpc/{vpc['VpcId']}", type=NodeType.VPC, account_id=account_id, region=self.region,
                      name=vpc["VpcId"], raw_metadata={"cidr": vpc.get("CidrBlock")})
            )
        for subnet in raw["subnets"]:
            is_public = subnet.get("MapPublicIpOnLaunch", False)
            scan.assets.append(
                Asset(id=f"aws:subnet/{subnet['SubnetId']}", type=NodeType.SUBNET, account_id=account_id,
                      region=self.region, name=subnet["SubnetId"], public=is_public,
                      raw_metadata={"vpc_id": subnet["VpcId"], "cidr": subnet.get("CidrBlock")})
            )
            scan.relationships.append(
                Relationship(source_id=f"aws:vpc/{subnet['VpcId']}", target_id=f"aws:subnet/{subnet['SubnetId']}",
                             type=EdgeType.CONTAINS, evidence={"subnet_id": subnet["SubnetId"]})
            )
        for sg in raw["security_groups"]:
            scan.assets.append(
                Asset(id=f"aws:sg/{sg['GroupId']}", type=NodeType.SECURITY_GROUP, account_id=account_id,
                      region=self.region, name=sg.get("GroupName", sg["GroupId"]),
                      raw_metadata={"vpc_id": sg.get("VpcId"), "ip_permissions": sg.get("IpPermissions", []),
                                    "ip_permissions_egress": sg.get("IpPermissionsEgress", [])})
            )
        for instance in raw["instances"]:
            instance_id = instance["InstanceId"]
            public_ip = instance.get("PublicIpAddress")
            asset_id = f"aws:ec2/{instance_id}"
            scan.assets.append(
                Asset(id=asset_id, type=NodeType.EC2, account_id=account_id, region=self.region, name=instance_id,
                      public=bool(public_ip),
                      raw_metadata={"public_ip": public_ip, "subnet_id": instance.get("SubnetId"),
                                    "vpc_id": instance.get("VpcId"),
                                    "security_groups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
                                    "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn")})
            )
            if instance.get("SubnetId"):
                scan.relationships.append(
                    Relationship(source_id=f"aws:subnet/{instance['SubnetId']}", target_id=asset_id,
                                 type=EdgeType.CONTAINS, evidence={"instance_id": instance_id})
                )
            for sg in instance.get("SecurityGroups", []):
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:sg/{sg['GroupId']}", type=EdgeType.USES,
                                 evidence={"security_group": sg["GroupId"]})
                )
            if public_ip:
                scan.relationships.append(
                    Relationship(source_id="aws:internet", target_id=asset_id, type=EdgeType.EXPOSED_TO,
                                 evidence={"public_ip": public_ip})
                )
            profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")
            if profile_arn:
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:iam:instance-profile/{profile_arn.split('/')[-1]}",
                                 type=EdgeType.RUNS_AS, evidence={"iam_instance_profile": profile_arn}, confidence=0.8)
                )
        if any(r.source_id == "aws:internet" for r in scan.relationships):
            scan.assets.append(Asset(id="aws:internet", type=NodeType.INTERNET, account_id=account_id, name="Internet"))

    def _normalize_s3(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for bucket in raw["buckets"]:
            name = bucket["Name"]
            pab = bucket.get("PublicAccessBlock") or {}
            block_all = all(pab.get(k, False) for k in
                             ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"))
            asset_id = f"aws:s3/{name}"
            scan.assets.append(
                Asset(id=asset_id, type=NodeType.S3, account_id=account_id, name=name, public=not block_all,
                      raw_metadata={"policy": bucket.get("Policy"), "acl": bucket.get("ACL"),
                                    "public_access_block": pab, "encryption": bucket.get("Encryption")})
            )

            kms_key_id = self._extract_kms_key_from_s3_encryption(bucket.get("Encryption"))
            if kms_key_id:
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:kms/{kms_key_id}", type=EdgeType.ENCRYPTED_BY,
                                 evidence={"sse_algorithm": "aws:kms"}, confidence=1.0)
                )

    @staticmethod
    def _extract_kms_key_from_s3_encryption(encryption_config: dict | None) -> str | None:
        if not encryption_config:
            return None
        for rule in encryption_config.get("Rules", []):
            default = rule.get("ApplyServerSideEncryptionByDefault", {})
            if default.get("SSEAlgorithm") == "aws:kms":
                key_ref = default.get("KMSMasterKeyID")
                if key_ref:
                    return AWSProvider._normalize_kms_key_ref(key_ref)
        return None

    @staticmethod
    def _normalize_kms_key_ref(kms_key_ref: str) -> str:
        """KMS key references show up as either a bare key id or a full
        ARN (arn:aws:kms:region:account:key/key-id) depending on the API
        and even the specific field — normalize to just the key id so it
        matches the `aws:kms/{key_id}` asset id format KMS assets use."""
        return kms_key_ref.split("/")[-1] if "/" in kms_key_ref else kms_key_ref

    # -------------------------------------------------------------
    # New normalization for Lambda / RDS / Secrets Manager / KMS
    # -------------------------------------------------------------
    def _normalize_lambda(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        internet_needed = False
        for fn in raw["functions"]:
            name = fn["FunctionName"]
            asset_id = f"aws:lambda/{name}"
            resource_policy = fn.get("ResourcePolicy")
            is_public = False
            if resource_policy:
                try:
                    doc = json.loads(resource_policy)
                    for stmt in doc.get("Statement", []):
                        principal = stmt.get("Principal")
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            is_public = True
                except (json.JSONDecodeError, TypeError):
                    pass

            scan.assets.append(
                Asset(
                    id=asset_id,
                    type=NodeType.LAMBDA,
                    account_id=account_id,
                    region=self.region,
                    arn=fn.get("FunctionArn"),
                    name=name,
                    public=is_public,
                    raw_metadata={"role": fn.get("Role"), "resource_policy": resource_policy},
                )
            )
            role_arn = fn.get("Role")
            if role_arn:
                role_name = role_arn.split("/")[-1]
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:iam:role/{role_name}",
                                 type=EdgeType.RUNS_AS, evidence={"execution_role": role_arn}, confidence=1.0)
                )
            if is_public:
                scan.relationships.append(
                    Relationship(source_id="aws:internet", target_id=asset_id, type=EdgeType.EXPOSED_TO,
                                 evidence={"resource_policy": "public invoke permission"})
                )
                internet_needed = True

        if internet_needed and not any(a.id == "aws:internet" for a in scan.assets):
            scan.assets.append(Asset(id="aws:internet", type=NodeType.INTERNET, account_id=account_id, name="Internet"))

    def _normalize_rds(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        internet_needed = False
        for instance in raw["instances"]:
            db_id = instance["DBInstanceIdentifier"]
            asset_id = f"aws:rds/{db_id}"
            publicly_accessible = instance.get("PubliclyAccessible", False)

            scan.assets.append(
                Asset(
                    id=asset_id,
                    type=NodeType.RDS,
                    account_id=account_id,
                    region=self.region,
                    arn=instance.get("DBInstanceArn"),
                    name=db_id,
                    public=publicly_accessible,
                    raw_metadata={
                        "engine": instance.get("Engine"),
                        "vpc_security_groups": [g["VpcSecurityGroupId"] for g in instance.get("VpcSecurityGroups", [])],
                    },
                )
            )
            for sg in instance.get("VpcSecurityGroups", []):
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:sg/{sg['VpcSecurityGroupId']}",
                                 type=EdgeType.USES, evidence={"security_group": sg["VpcSecurityGroupId"]})
                )
            kms_key_id = instance.get("KmsKeyId")
            if kms_key_id:
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:kms/{self._normalize_kms_key_ref(kms_key_id)}",
                                 type=EdgeType.ENCRYPTED_BY, evidence={"storage_encrypted": True}, confidence=1.0)
                )
            if publicly_accessible:
                scan.relationships.append(
                    Relationship(source_id="aws:internet", target_id=asset_id, type=EdgeType.EXPOSED_TO,
                                 evidence={"publicly_accessible": True})
                )
                internet_needed = True

        if internet_needed and not any(a.id == "aws:internet" for a in scan.assets):
            scan.assets.append(Asset(id="aws:internet", type=NodeType.INTERNET, account_id=account_id, name="Internet"))

    def _normalize_secrets_manager(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for secret in raw["secrets"]:
            name = secret["Name"]
            asset_id = f"aws:secret/{name}"
            scan.assets.append(
                Asset(
                    id=asset_id,
                    type=NodeType.SECRET,
                    account_id=account_id,
                    region=self.region,
                    arn=secret.get("ARN"),
                    name=name,
                    raw_metadata={"resource_policy": secret.get("ResourcePolicy")},
                )
            )
            kms_key_id = secret.get("KmsKeyId")
            if kms_key_id:
                scan.relationships.append(
                    Relationship(source_id=asset_id, target_id=f"aws:kms/{self._normalize_kms_key_ref(kms_key_id)}",
                                 type=EdgeType.ENCRYPTED_BY, evidence={"kms_key_id": kms_key_id}, confidence=1.0)
                )
            # NOTE: we never fetch or store the secret VALUE — only
            # metadata (name, ARN, resource policy, KMS key). CAN_READ
            # edges from roles with secretsmanager:GetSecretValue are
            # derived by engine/iam/analyzer.py from IAM policy analysis,
            # not here.

    def _normalize_kms(self, raw: dict, account_id: str, scan: ScanResult) -> None:
        for key in raw["keys"]:
            key_id = key["KeyId"]
            scan.assets.append(
                Asset(
                    id=f"aws:kms/{key_id}",
                    type=NodeType.KMS_KEY,
                    account_id=account_id,
                    region=self.region,
                    arn=key.get("Arn"),
                    name=key.get("Description") or key_id,
                    raw_metadata={"key_manager": key.get("KeyManager"), "policy": key.get("Policy")},
                )
            )

    def discover_relationships(self, scan: ScanResult) -> ScanResult:
        seen = set()
        deduped: list[Relationship] = []
        for rel in scan.relationships:
            if rel.key() not in seen:
                seen.add(rel.key())
                deduped.append(rel)
        scan.relationships = deduped
        return scan
