"""
Tests for item #3: KMS ENCRYPTED_BY edges (S3/RDS/Secrets Manager) and
flagging secretsmanager:GetSecretValue as a dangerous action.
"""
import boto3
from moto import mock_aws

from engine.iam.analyzer import IAMAnalyzer
from engine.iam.policy_eval import DANGEROUS_ACTIONS, find_dangerous_actions, parse_statements
from engine.models import Asset, EdgeType, NodeType
from providers.aws.provider import AWSProvider


class TestSecretsManagerDangerousAction:
    def test_get_secret_value_is_in_dangerous_actions_set(self):
        assert "secretsmanager:getsecretvalue" in DANGEROUS_ACTIONS

    def test_iam_analyzer_flags_role_with_get_secret_value(self):
        role = Asset(
            id="aws:iam:role/SecretReaderRole",
            type=NodeType.ROLE,
            account_id="123456789012",
            name="SecretReaderRole",
            raw_metadata={
                "policies": {
                    "inline": [
                        {
                            "name": "ReadSecrets",
                            "document": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
                                ]
                            },
                        }
                    ],
                    "attached": [],
                }
            },
        )
        findings, _ = IAMAnalyzer().analyze([role])
        assert any(
            f.category == "dangerous_action" and f.evidence.get("action") == "secretsmanager:getsecretvalue"
            for f in findings
        )

    def test_find_dangerous_actions_matches_case_insensitively(self):
        """IAM actions are case-insensitive in practice — confirm the
        matcher doesn't accidentally require exact-case 'GetSecretValue'."""
        statement = parse_statements(
            {"Statement": [{"Effect": "Allow", "Action": "secretsmanager:getsecretvalue", "Resource": "*"}]}
        )[0]
        found = find_dangerous_actions(statement)
        assert "secretsmanager:getsecretvalue" in found


@mock_aws
def test_rds_kms_encryption_produces_encrypted_by_edge():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms")
    rds = session.client("rds")

    key_id = kms.create_key(Description="db-key")["KeyMetadata"]["KeyId"]
    rds.create_db_instance(
        DBInstanceIdentifier="encrypted-db", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="admin", MasterUserPassword="password123!", AllocatedStorage=20,
        StorageEncrypted=True, KmsKeyId=key_id,
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    rds_asset = next(a for a in scan.assets if a.type == NodeType.RDS)
    kms_asset = next(a for a in scan.assets if a.type == NodeType.KMS_KEY)

    encrypted_edges = [r for r in scan.relationships if r.type == EdgeType.ENCRYPTED_BY]
    assert len(encrypted_edges) == 1
    assert encrypted_edges[0].source_id == rds_asset.id
    assert encrypted_edges[0].target_id == kms_asset.id


@mock_aws
def test_secrets_manager_kms_encryption_produces_encrypted_by_edge():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms")
    sm = session.client("secretsmanager")

    key_id = kms.create_key(Description="secret-key")["KeyMetadata"]["KeyId"]
    sm.create_secret(Name="encrypted-secret", SecretString="x", KmsKeyId=key_id)

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    secret_asset = next(a for a in scan.assets if a.type == NodeType.SECRET)
    encrypted_edges = [r for r in scan.relationships if r.type == EdgeType.ENCRYPTED_BY and r.source_id == secret_asset.id]
    assert len(encrypted_edges) == 1


@mock_aws
def test_s3_kms_encryption_produces_encrypted_by_edge():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms")
    s3 = session.client("s3")

    key_id = kms.create_key(Description="bucket-key")["KeyMetadata"]["KeyId"]
    s3.create_bucket(Bucket="encrypted-bucket")
    s3.put_bucket_encryption(
        Bucket="encrypted-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_id}}]
        },
    )

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    bucket_asset = next(a for a in scan.assets if a.type == NodeType.S3)
    encrypted_edges = [r for r in scan.relationships if r.type == EdgeType.ENCRYPTED_BY and r.source_id == bucket_asset.id]
    assert len(encrypted_edges) == 1


@mock_aws
def test_unencrypted_resources_produce_no_encrypted_by_edge():
    """No KMS key configured -> no phantom ENCRYPTED_BY edge should be
    created — confirms the absence case is handled, not just the
    presence case."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds")
    s3 = session.client("s3")

    rds.create_db_instance(
        DBInstanceIdentifier="plain-db", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="admin", MasterUserPassword="password123!", AllocatedStorage=20,
        StorageEncrypted=False,
    )
    s3.create_bucket(Bucket="plain-bucket")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    assert not any(r.type == EdgeType.ENCRYPTED_BY for r in scan.relationships)
