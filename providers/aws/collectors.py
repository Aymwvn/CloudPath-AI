"""
Phase 1 — AWS collectors.

Every function here is READ-ONLY (Describe/List/Get calls only — see
docs/aws-permissions.md). None of these functions ever mutate cloud state.
Each returns raw boto3 response dicts; normalization into Asset objects
happens in providers/aws/provider.py, keeping "talk to AWS" separate from
"turn AWS's shape into our shape".
"""
from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _safe_call(fn, *args, **kwargs) -> Any:
    """Call a boto3 method, log + swallow permission/throttling errors.

    A missing permission on one resource type should not abort the whole
    scan — it should be recorded and the scan should keep going with
    partial data (see ScanResult.errors).
    """
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        logger.warning("AWS call failed: %s", exc)
        raise


def collect_iam(session: boto3.Session) -> dict[str, Any]:
    """Collect users, roles, groups, and their attached/inline policies."""
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

    # attached + inline policies per role (needed for IAM engine, Phase 3)
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
    """Collect EC2 instances, VPCs, subnets, and security groups."""
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
    """Collect S3 buckets with their policy / ACL / public-access-block config."""
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

        enriched.append(entry)

    return {"buckets": enriched}


def get_caller_identity(session: boto3.Session) -> dict[str, Any]:
    """Used to resolve the current account id at scan start."""
    sts = session.client("sts")
    return sts.get_caller_identity()
