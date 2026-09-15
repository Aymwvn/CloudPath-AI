"""
Tests for security-group-to-security-group correlation (deriving
CONNECTED_TO edges). Uses real moto-mocked AWS to confirm the exact
UserIdGroupPairs shape AWS actually returns is parsed correctly — not
just a hand-built fixture guessing at the shape.
"""
import boto3
from moto import mock_aws

from engine.attack_paths.engine import AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.network.analyzer import NetworkAnalyzer
from providers.aws.provider import AWSProvider

ACCOUNT = "123456789012"


@mock_aws
def test_sg_to_sg_rule_produces_connected_to_edge_from_real_aws_data():
    """Real moto AWS calls, not a hand-built fixture — confirms the
    UserIdGroupPairs shape is parsed correctly against what AWS actually
    returns (verified directly against moto before writing this test)."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    sg_web = ec2.create_security_group(GroupName="web-sg", Description="web", VpcId=vpc["VpcId"])
    sg_db = ec2.create_security_group(GroupName="db-sg", Description="db", VpcId=vpc["VpcId"])

    # db-sg allows inbound Postgres FROM web-sg (not from a CIDR) — the
    # exact pattern that was previously invisible to this platform
    ec2.authorize_security_group_ingress(
        GroupId=sg_db["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
            "UserIdGroupPairs": [{"GroupId": sg_web["GroupId"]}],
        }],
    )

    web_instance = ec2.run_instances(
        ImageId="ami-1", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"], SecurityGroupIds=[sg_web["GroupId"]]
    )["Instances"][0]
    # a resource must actually USE sg-db for a CONNECTED_TO edge to have
    # anywhere to point — a second EC2 instance stands in for "the DB tier"
    db_instance = ec2.run_instances(
        ImageId="ami-1", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"], SecurityGroupIds=[sg_db["GroupId"]]
    )["Instances"][0]

    provider = AWSProvider(session=session)
    scan = provider.discover_assets()
    scan = provider.discover_relationships(scan)

    net_findings, net_rels = NetworkAnalyzer().analyze(scan.assets)
    connected_edges = [r for r in net_rels if r.type == EdgeType.CONNECTED_TO]

    assert len(connected_edges) >= 1
    edge = connected_edges[0]
    assert edge.source_id == f"aws:ec2/{web_instance['InstanceId']}"
    assert edge.target_id == f"aws:ec2/{db_instance['InstanceId']}"
    assert edge.evidence["from_port"] == 5432


def test_sg_correlation_end_to_end_produces_traversable_attack_path():
    """This is the actual point of the feature: a resource behind a
    security group with NO public CIDR exposure at all should still be
    reachable in an attack path IF another resource that IS exposed can
    reach it via an SG-to-SG rule. Before this feature, this path would
    have been invisible."""
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/web-1", type=NodeType.EC2, account_id=ACCOUNT, name="web-1", public=True,
              raw_metadata={"security_groups": ["sg-web"]}),
        Asset(id="aws:sg/sg-web", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="web-sg",
              raw_metadata={"ip_permissions": []}),
        # db-1 has NO public exposure, NO 0.0.0.0/0 rule — only reachable
        # via the SG-to-SG rule below
        Asset(id="aws:rds/db-1", type=NodeType.RDS, account_id=ACCOUNT, name="db-1", public=False,
              raw_metadata={"vpc_security_groups": ["sg-db"]}),
        Asset(id="aws:sg/sg-db", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="db-sg",
              raw_metadata={"ip_permissions": [
                  {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                   "UserIdGroupPairs": [{"GroupId": "sg-web"}]}
              ]}),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/web-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
    ]

    net_findings, net_rels = NetworkAnalyzer().analyze(scan.assets)
    scan.relationships.extend(net_rels)

    graph = GraphEngine().build(scan)
    paths = AttackPathEngine().find_paths(graph, entry_points=["aws:internet"], targets=["aws:rds/db-1"])

    assert len(paths) == 1
    path = paths[0]
    assert path.hop_count == 2
    assert path.steps[-1].edge_type == "CONNECTED_TO"
    assert path.steps[-1].confidence == 1.0


def test_sg_rule_referencing_cidr_only_produces_no_connected_to_edge():
    """A plain CIDR-based rule (no UserIdGroupPairs) must NOT produce a
    CONNECTED_TO edge — that's what the existing open_security_group
    finding already covers; this feature is specifically for SG-to-SG
    references, not CIDR rules."""
    scan_assets = [
        Asset(id="aws:sg/sg-a", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="sg-a",
              raw_metadata={"ip_permissions": [
                  {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
              ]}),
    ]
    _, rels = NetworkAnalyzer().analyze(scan_assets)
    assert not any(r.type == EdgeType.CONNECTED_TO for r in rels)


def test_sg_to_sg_rule_with_no_resources_using_either_sg_produces_no_edges():
    """An SG-to-SG rule referencing security groups that no discovered
    resource actually uses shouldn't produce phantom edges between
    nonexistent resources."""
    scan_assets = [
        Asset(id="aws:sg/sg-orphan-target", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="orphan-target",
              raw_metadata={"ip_permissions": [
                  {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                   "UserIdGroupPairs": [{"GroupId": "sg-orphan-source"}]}
              ]}),
    ]
    _, rels = NetworkAnalyzer().analyze(scan_assets)
    assert not any(r.type == EdgeType.CONNECTED_TO for r in rels)


def test_self_referencing_sg_rule_does_not_create_self_loop():
    """A security group that allows traffic from itself (a common,
    legitimate pattern for clustered services) shouldn't produce a
    resource-to-itself CONNECTED_TO edge."""
    scan_assets = [
        Asset(id="aws:ec2/cluster-node-1", type=NodeType.EC2, account_id=ACCOUNT, name="cluster-node-1",
              raw_metadata={"security_groups": ["sg-cluster"]}),
        Asset(id="aws:sg/sg-cluster", type=NodeType.SECURITY_GROUP, account_id=ACCOUNT, name="cluster-sg",
              raw_metadata={"ip_permissions": [
                  {"IpProtocol": "tcp", "FromPort": 7000, "ToPort": 7000,
                   "UserIdGroupPairs": [{"GroupId": "sg-cluster"}]}
              ]}),
    ]
    _, rels = NetworkAnalyzer().analyze(scan_assets)
    self_loops = [r for r in rels if r.type == EdgeType.CONNECTED_TO and r.source_id == r.target_id]
    assert self_loops == []
