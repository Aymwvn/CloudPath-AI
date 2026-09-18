"""
Tests for: Lambda VPC config -> SG correlation eligibility, EBS volume
encryption -> EC2 ENCRYPTED_BY edges, and egress-aware confidence on
SG-to-SG CONNECTED_TO edges.
"""
import json

import boto3
from moto import mock_aws

from engine.models import Asset, EdgeType, NodeType
from engine.network.analyzer import NetworkAnalyzer
from providers.aws.provider import AWSProvider

ACCOUNT = "123456789012"


@mock_aws
def test_lambda_vpc_config_makes_it_eligible_for_sg_correlation():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    lam = session.client("lambda")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    sg_lambda = ec2.create_security_group(GroupName="lambda-sg", Description="x", VpcId=vpc["VpcId"])
    sg_db = ec2.create_security_group(GroupName="db-sg", Description="x", VpcId=vpc["VpcId"])
    ec2.authorize_security_group_ingress(
        GroupId=sg_db["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                         "UserIdGroupPairs": [{"GroupId": sg_lambda["GroupId"]}]}],
    )

    iam.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    ))
    role_arn = iam.get_role(RoleName="r")["Role"]["Arn"]
    lam.create_function(
        FunctionName="db-accessing-fn", Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": b"x"}, VpcConfig={"SubnetIds": [subnet["SubnetId"]], "SecurityGroupIds": [sg_lambda["GroupId"]]},
    )
    db_instance = ec2.run_instances(ImageId="ami-1", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"],
                                     SecurityGroupIds=[sg_db["GroupId"]])["Instances"][0]

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    lambda_asset = next(a for a in scan.assets if a.type == NodeType.LAMBDA)
    assert lambda_asset.raw_metadata["security_groups"] == [sg_lambda["GroupId"]]

    _, net_rels = NetworkAnalyzer().analyze(scan.assets)
    connected = [r for r in net_rels if r.type == EdgeType.CONNECTED_TO]
    assert any(r.source_id == lambda_asset.id and r.target_id == f"aws:ec2/{db_instance['InstanceId']}" for r in connected)


@mock_aws
def test_encrypted_ebs_volume_produces_ec2_encrypted_by_edge():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    kms = session.client("kms")

    key_id = kms.create_key(Description="ebs-key")["KeyMetadata"]["KeyId"]
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    instance = ec2.run_instances(ImageId="ami-1", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"])["Instances"][0]

    volume = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True, KmsKeyId=key_id)
    ec2.attach_volume(VolumeId=volume["VolumeId"], InstanceId=instance["InstanceId"], Device="/dev/sdf")

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    ec2_asset_id = f"aws:ec2/{instance['InstanceId']}"
    kms_asset = next(a for a in scan.assets if a.type == NodeType.KMS_KEY)
    encrypted_edges = [r for r in scan.relationships if r.type == EdgeType.ENCRYPTED_BY and r.source_id == ec2_asset_id]
    assert len(encrypted_edges) == 1
    assert encrypted_edges[0].target_id == kms_asset.id


@mock_aws
def test_unattached_or_unencrypted_volumes_produce_no_edge():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    # unencrypted volume, never attached
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    assert not any(r.type == EdgeType.ENCRYPTED_BY for r in scan.relationships)


class TestEgressAwareConfidence:
    def test_no_egress_restrictions_keeps_full_confidence(self):
        """Matches prior behavior exactly when the source SG has no
        explicit egress rules (AWS default: unrestricted outbound)."""
        assets = [
            Asset(id="aws:ec2/web-1", type=NodeType.EC2, account_id=ACCOUNT, name="web-1",
                  raw_metadata={"security_groups": ["sg-web"]}),
            Asset(id="aws:sg/sg-web", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="web-sg",
                  raw_metadata={"ip_permissions": [], "ip_permissions_egress": []}),
            Asset(id="aws:rds/db-1", type=NodeType.RDS, account_id=ACCOUNT, name="db-1",
                  raw_metadata={"vpc_security_groups": ["sg-db"]}),
            Asset(id="aws:sg/sg-db", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="db-sg",
                  raw_metadata={"ip_permissions": [
                      {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-web"}]}
                  ]}),
        ]
        _, rels = NetworkAnalyzer().analyze(assets)
        edge = next(r for r in rels if r.type == EdgeType.CONNECTED_TO)
        assert edge.confidence == 1.0

    def test_restrictive_egress_that_permits_target_keeps_full_confidence(self):
        assets = [
            Asset(id="aws:ec2/web-1", type=NodeType.EC2, account_id=ACCOUNT, name="web-1",
                  raw_metadata={"security_groups": ["sg-web"]}),
            Asset(id="aws:sg/sg-web", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="web-sg",
                  raw_metadata={"ip_permissions": [], "ip_permissions_egress": [
                      {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-db"}]}
                  ]}),
            Asset(id="aws:rds/db-1", type=NodeType.RDS, account_id=ACCOUNT, name="db-1",
                  raw_metadata={"vpc_security_groups": ["sg-db"]}),
            Asset(id="aws:sg/sg-db", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="db-sg",
                  raw_metadata={"ip_permissions": [
                      {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-web"}]}
                  ]}),
        ]
        _, rels = NetworkAnalyzer().analyze(assets)
        edge = next(r for r in rels if r.type == EdgeType.CONNECTED_TO)
        assert edge.confidence == 1.0

    def test_restrictive_egress_that_does_not_cover_target_lowers_confidence(self):
        """Source SG has explicit egress rules, but none of them permit
        reaching the target SG — reduced confidence, not silently
        dropped (we don't have full network-path visibility to be sure
        no path exists)."""
        assets = [
            Asset(id="aws:ec2/web-1", type=NodeType.EC2, account_id=ACCOUNT, name="web-1",
                  raw_metadata={"security_groups": ["sg-web"]}),
            Asset(id="aws:sg/sg-web", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="web-sg",
                  raw_metadata={"ip_permissions": [], "ip_permissions_egress": [
                      {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "1.2.3.4/32"}]}
                  ]}),
            Asset(id="aws:rds/db-1", type=NodeType.RDS, account_id=ACCOUNT, name="db-1",
                  raw_metadata={"vpc_security_groups": ["sg-db"]}),
            Asset(id="aws:sg/sg-db", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="db-sg",
                  raw_metadata={"ip_permissions": [
                      {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-web"}]}
                  ]}),
        ]
        _, rels = NetworkAnalyzer().analyze(assets)
        edge = next(r for r in rels if r.type == EdgeType.CONNECTED_TO)
        assert edge.confidence == 0.5

    def test_allow_all_egress_rule_keeps_full_confidence(self):
        assets = [
            Asset(id="aws:ec2/web-1", type=NodeType.EC2, account_id=ACCOUNT, name="web-1",
                  raw_metadata={"security_groups": ["sg-web"]}),
            Asset(id="aws:sg/sg-web", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="web-sg",
                  raw_metadata={"ip_permissions": [], "ip_permissions_egress": [
                      {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                  ]}),
            Asset(id="aws:rds/db-1", type=NodeType.RDS, account_id=ACCOUNT, name="db-1",
                  raw_metadata={"vpc_security_groups": ["sg-db"]}),
            Asset(id="aws:sg/sg-db", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="db-sg",
                  raw_metadata={"ip_permissions": [
                      {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-web"}]}
                  ]}),
        ]
        _, rels = NetworkAnalyzer().analyze(assets)
        edge = next(r for r in rels if r.type == EdgeType.CONNECTED_TO)
        assert edge.confidence == 1.0
