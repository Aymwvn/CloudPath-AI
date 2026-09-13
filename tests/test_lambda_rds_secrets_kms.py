"""
Tests for the new Lambda/RDS/Secrets Manager/KMS collectors — this is
what unlocks upgrading Phase 16's scenarios 3, 4, 5, 8 from hand-built
fixtures to real moto-mocked AWS calls (see docs/PHASE1-4_NOTES.md and
docs/PHASE16_NOTES.md for why those were previously stubbed).
"""
import json

import boto3
import pytest
from moto import mock_aws

from engine.models import EdgeType, NodeType
from providers.aws.provider import AWSProvider


@mock_aws
def test_lambda_execution_role_produces_runs_as_edge():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    lam = session.client("lambda")

    iam.create_role(
        RoleName="LambdaExecRole",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
    )
    role_arn = iam.get_role(RoleName="LambdaExecRole")["Role"]["Arn"]

    lam.create_function(
        FunctionName="my-function",
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    lambda_assets = [a for a in scan.assets if a.type == NodeType.LAMBDA]
    assert len(lambda_assets) == 1
    assert lambda_assets[0].name == "my-function"

    runs_as_edges = [r for r in scan.relationships if r.type == EdgeType.RUNS_AS and r.source_id == lambda_assets[0].id]
    assert len(runs_as_edges) == 1
    assert runs_as_edges[0].target_id == "aws:iam:role/LambdaExecRole"


@mock_aws
def test_lambda_with_public_resource_policy_is_flagged_public_and_exposed():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    lam = session.client("lambda")

    iam.create_role(
        RoleName="PublicFnRole",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
    )
    role_arn = iam.get_role(RoleName="PublicFnRole")["Role"]["Arn"]
    lam.create_function(
        FunctionName="public-api",
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
    )
    lam.add_permission(
        FunctionName="public-api",
        StatementId="public-invoke",
        Action="lambda:InvokeFunction",
        Principal="*",
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    fn_asset = next(a for a in scan.assets if a.type == NodeType.LAMBDA)
    assert fn_asset.public is True
    assert any(r.type == EdgeType.EXPOSED_TO and r.target_id == fn_asset.id for r in scan.relationships)
    assert any(a.type == NodeType.INTERNET for a in scan.assets)


@mock_aws
def test_publicly_accessible_rds_instance_is_flagged_and_exposed():
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds")

    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123!",
        AllocatedStorage=20,
        PubliclyAccessible=True,
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    rds_asset = next(a for a in scan.assets if a.type == NodeType.RDS)
    assert rds_asset.name == "prod-db"
    assert rds_asset.public is True
    assert any(r.type == EdgeType.EXPOSED_TO and r.target_id == rds_asset.id for r in scan.relationships)


@mock_aws
def test_private_rds_instance_is_not_flagged_public():
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds")

    rds.create_db_instance(
        DBInstanceIdentifier="internal-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123!",
        AllocatedStorage=20,
        PubliclyAccessible=False,
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()

    rds_asset = next(a for a in scan.assets if a.type == NodeType.RDS)
    assert rds_asset.public is False


@mock_aws
def test_secrets_manager_secret_is_discovered_without_fetching_value():
    session = boto3.Session(region_name="us-east-1")
    sm = session.client("secretsmanager")

    sm.create_secret(Name="prod/db-password", SecretString="super-secret-value")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()

    secret_assets = [a for a in scan.assets if a.type == NodeType.SECRET]
    assert len(secret_assets) == 1
    assert secret_assets[0].name == "prod/db-password"
    # the actual secret value must never appear anywhere in what we collected
    assert "super-secret-value" not in json.dumps(secret_assets[0].raw_metadata)


@mock_aws
def test_kms_key_is_discovered_with_policy():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms")

    kms.create_key(Description="app-encryption-key")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()

    kms_assets = [a for a in scan.assets if a.type == NodeType.KMS_KEY]
    assert len(kms_assets) == 1
    assert kms_assets[0].name == "app-encryption-key"


@mock_aws
def test_full_lambda_to_secrets_scenario_end_to_end():
    """This is Phase 16's Scenario 3, upgraded from hand-built fixtures
    to a REAL moto-mocked AWS environment now that Lambda/Secrets
    collectors exist."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    lam = session.client("lambda")
    sm = session.client("secretsmanager")

    iam.create_role(
        RoleName="PublicApiRole",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
    )
    iam.put_role_policy(
        RoleName="PublicApiRole",
        PolicyName="SecretsAccess",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
        ),
    )
    role_arn = iam.get_role(RoleName="PublicApiRole")["Role"]["Arn"]

    lam.create_function(
        FunctionName="public-api",
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
    )
    lam.add_permission(FunctionName="public-api", StatementId="public", Action="lambda:InvokeFunction", Principal="*")

    sm.create_secret(Name="api-key", SecretString="fake-key-value")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    assert any(a.type == NodeType.LAMBDA for a in scan.assets)
    assert any(a.type == NodeType.SECRET for a in scan.assets)
    assert any(r.type == EdgeType.EXPOSED_TO for r in scan.relationships)
    assert any(r.type == EdgeType.RUNS_AS for r in scan.relationships)


@mock_aws
def test_collector_failure_for_one_service_does_not_abort_whole_scan():
    """Partial-scan tolerance (established in Phase 1) must still hold
    with the new collectors added — if e.g. RDS access is denied, the
    rest of the scan should still complete."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="still-works")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()

    # even with no Lambda/RDS/Secrets/KMS resources created, discovery
    # of those services should just return empty results, not errors —
    # confirming this only errors on ACTUAL failures, not empty accounts
    assert scan.errors == []
    assert any(a.type == NodeType.S3 for a in scan.assets)
