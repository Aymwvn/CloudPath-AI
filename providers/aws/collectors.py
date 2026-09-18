"""
AWS collectors — read-only only (Describe/List/Get calls). Never mutates
cloud state. Each returns raw boto3 response dicts; normalization into
Asset objects happens in providers/aws/provider.py.
"""
from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def collect_iam(session: boto3.Session) -> dict[str, Any]:
    iam = session.client("iam")
    data: dict[str, Any] = {"users": [], "roles": [], "groups": [], "policies": {}}

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        data["users"].extend(page["Users"])

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        data["roles"].extend(page["Roles"])

    paginator = iam.get_paginator("list_groups")
    for page in paginator.paginate():
        data["groups"].extend(page["Groups"])

    for role in data["roles"]:
        name = role["RoleName"]
        attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        inline_names = iam.list_role_policies(RoleName=name)["PolicyNames"]
        inline_docs = []
        for pname in inline_names:
            doc = iam.get_role_policy(RoleName=name, PolicyName=pname)
            inline_docs.append({"name": pname, "document": doc["PolicyDocument"]})

        resolved_attached = []
        for pol in attached:
            version = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=pol["PolicyArn"], VersionId=version)
            resolved_attached.append(
                {"name": pol["PolicyName"], "arn": pol["PolicyArn"], "document": doc["PolicyVersion"]["Document"]}
            )

        data["policies"][name] = {"attached": resolved_attached, "inline": inline_docs}

    return data


def collect_ec2(session: boto3.Session) -> dict[str, Any]:
    ec2 = session.client("ec2")
    data: dict[str, Any] = {"instances": [], "vpcs": [], "subnets": [], "security_groups": []}

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            data["instances"].extend(reservation["Instances"])

    data["vpcs"] = ec2.describe_vpcs()["Vpcs"]
    data["subnets"] = ec2.describe_subnets()["Subnets"]
    data["security_groups"] = ec2.describe_security_groups()["SecurityGroups"]

    return data


def collect_s3(session: boto3.Session) -> dict[str, Any]:
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    enriched = []

    for bucket in buckets:
        name = bucket["Name"]
        entry: dict[str, Any] = {"Name": name, "CreationDate": bucket["CreationDate"]}

        try:
            entry["Location"] = s3.get_bucket_location(Bucket=name)["LocationConstraint"]
        except ClientError:
            entry["Location"] = None
        try:
            entry["Policy"] = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError:
            entry["Policy"] = None
        try:
            entry["ACL"] = s3.get_bucket_acl(Bucket=name)
        except ClientError:
            entry["ACL"] = None
        try:
            entry["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError:
            entry["PublicAccessBlock"] = None
        try:
            entry["Encryption"] = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]
        except ClientError:
            entry["Encryption"] = None  # no default encryption configured

        enriched.append(entry)

    return {"buckets": enriched}


def collect_instance_profiles(session: boto3.Session) -> dict[str, str]:
    iam = session.client("iam")
    mapping: dict[str, str] = {}
    paginator = iam.get_paginator("list_instance_profiles")
    for page in paginator.paginate():
        for profile in page["InstanceProfiles"]:
            roles = profile.get("Roles", [])
            if roles:
                mapping[profile["InstanceProfileName"]] = roles[0]["RoleName"]
    return mapping


# ---------------------------------------------------------------------
# New: Lambda / RDS / Secrets Manager / KMS collectors.
#
# These use exactly the permissions already documented in
# docs/ARCHITECTURE.md Section 10 (lambda:ListFunctions/GetFunction/
# GetPolicy, rds:Describe*, secretsmanager:ListSecrets, kms:ListKeys/
# DescribeKey/GetKeyPolicy) — no new IAM permissions are required beyond
# what was already scoped for the platform from the start.
# ---------------------------------------------------------------------
def collect_lambda(session: boto3.Session) -> dict[str, Any]:
    """Collect Lambda functions, their execution role, resource policy,
    VPC config (security groups, for SG-to-SG correlation), and KMS key
    (for environment-variable encryption)."""
    lam = session.client("lambda")
    functions = []

    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        functions.extend(page["Functions"])

    for fn in functions:
        try:
            policy = lam.get_policy(FunctionName=fn["FunctionName"])["Policy"]
        except ClientError:
            policy = None
        fn["ResourcePolicy"] = policy

    return {"functions": functions}


def collect_ebs_volumes(session: boto3.Session) -> dict[str, Any]:
    """Collect EBS volumes — encryption status/KMS key and which
    instance(s) each is attached to, so encryption can be attributed
    back to the EC2 instance in the graph."""
    ec2 = session.client("ec2")
    volumes = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        volumes.extend(page["Volumes"])
    return {"volumes": volumes}


def collect_rds(session: boto3.Session) -> dict[str, Any]:
    """Collect RDS instances, including public accessibility and the
    security groups attached to them."""
    rds = session.client("rds")
    instances = []

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        instances.extend(page["DBInstances"])

    return {"instances": instances}


def collect_secrets_manager(session: boto3.Session) -> dict[str, Any]:
    """Collect Secrets Manager secret METADATA only — never the secret
    value itself. This remains a read-only, non-exfiltrating scanner;
    GetSecretValue is deliberately never called."""
    sm = session.client("secretsmanager")
    secrets = []

    paginator = sm.get_paginator("list_secrets")
    for page in paginator.paginate():
        secrets.extend(page["SecretList"])

    for secret in secrets:
        try:
            policy_resp = sm.get_resource_policy(SecretId=secret["ARN"])
            secret["ResourcePolicy"] = policy_resp.get("ResourcePolicy")
        except ClientError:
            secret["ResourcePolicy"] = None

    return {"secrets": secrets}


def collect_kms(session: boto3.Session) -> dict[str, Any]:
    """Collect KMS keys and their key policy (reveals cross-account or
    overly-broad grants)."""
    kms = session.client("kms")
    keys = []

    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        keys.extend(page["Keys"])

    enriched = []
    for key in keys:
        key_id = key["KeyId"]
        try:
            description = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            continue  # e.g. AWS-managed keys the account can list but not fully describe
        try:
            policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        except ClientError:
            policy = None
        description["Policy"] = policy
        enriched.append(description)

    return {"keys": enriched}


def get_caller_identity(session: boto3.Session) -> dict[str, Any]:
    sts = session.client("sts")
    return sts.get_caller_identity()
