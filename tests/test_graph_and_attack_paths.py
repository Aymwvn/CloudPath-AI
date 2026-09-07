"""
Phase 5/6 unit tests — build a small deliberate graph by hand (public EC2
-> role -> S3, matching ARCHITECTURE.md's canonical example) and confirm
the engine finds the expected path.
"""
from engine.attack_paths.engine import AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult

ACCOUNT = "123456789012"


def _canonical_scenario() -> ScanResult:
    """Internet -> EC2 -> WebServerRole -> S3 (customer-data)."""
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(id="aws:iam:role/WebServerRole", type=NodeType.ROLE, account_id=ACCOUNT, name="WebServerRole"),
        Asset(id="aws:s3/customer-data", type=NodeType.S3, account_id=ACCOUNT, name="customer-data"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(
            source_id="aws:ec2/i-1", target_id="aws:iam:role/WebServerRole", type=EdgeType.RUNS_AS, confidence=1.0
        ),
        Relationship(
            source_id="aws:iam:role/WebServerRole",
            target_id="aws:s3/customer-data",
            type=EdgeType.CAN_READ,
            confidence=0.9,
        ),
    ]
    return scan


class TestGraphEngine:
    def test_builds_graph_with_all_nodes_and_edges(self):
        scan = _canonical_scenario()
        engine = GraphEngine()
        graph = engine.build(scan)

        assert graph.number_of_nodes() == 4
        assert graph.number_of_edges() == 3

    def test_resolves_instance_profile_placeholder_to_real_role(self):
        scan = ScanResult(account_id=ACCOUNT, provider="aws")
        scan.assets = [
            Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1"),
            Asset(id="aws:iam:role/RealRole", type=NodeType.ROLE, account_id=ACCOUNT, name="RealRole"),
        ]
        scan.relationships = [
            Relationship(
                source_id="aws:ec2/i-1",
                target_id="aws:iam:instance-profile/RealRoleProfile",
                type=EdgeType.RUNS_AS,
                confidence=0.8,
            )
        ]
        engine = GraphEngine()
        graph = engine.build(scan, instance_profile_to_role={"RealRoleProfile": "RealRole"})

        assert graph.has_edge("aws:ec2/i-1", "aws:iam:role/RealRole")
        edge = graph.get_edge_data("aws:ec2/i-1", "aws:iam:role/RealRole")
        assert edge["confidence"] == 1.0
        assert not graph.has_edge("aws:ec2/i-1", "aws:iam:instance-profile/RealRoleProfile")

    def test_entry_nodes_includes_internet_and_public_assets(self):
        scan = _canonical_scenario()
        engine = GraphEngine()
        engine.build(scan)
        entries = engine.entry_nodes()
        assert "aws:internet" in entries
        assert "aws:ec2/i-1" in entries  # public=True


class TestAttackPathEngine:
    def test_finds_canonical_internet_to_s3_path(self):
        scan = _canonical_scenario()
        graph_engine = GraphEngine()
        graph = graph_engine.build(scan)

        path_engine = AttackPathEngine()
        paths = path_engine.find_paths(graph, entry_points=["aws:internet"], targets=["aws:s3/customer-data"])

        assert len(paths) == 1
        path = paths[0]
        assert path.hop_count == 3
        assert path.node_sequence == [
            "aws:internet",
            "aws:ec2/i-1",
            "aws:iam:role/WebServerRole",
            "aws:s3/customer-data",
        ]
        assert path.status == "path"  # all edges >= default 0.5 confidence

    def test_no_path_when_target_unreachable(self):
        scan = _canonical_scenario()
        # add an isolated target with no incoming edges
        scan.assets.append(Asset(id="aws:s3/isolated", type=NodeType.S3, account_id=ACCOUNT, name="isolated"))
        graph_engine = GraphEngine()
        graph = graph_engine.build(scan)

        path_engine = AttackPathEngine()
        paths = path_engine.find_paths(graph, entry_points=["aws:internet"], targets=["aws:s3/isolated"])
        assert paths == []

    def test_low_confidence_edge_marks_path_as_potential(self):
        scan = _canonical_scenario()
        # weaken the last edge's confidence below the 0.5 threshold
        scan.relationships[-1].confidence = 0.3
        graph_engine = GraphEngine()
        graph = graph_engine.build(scan)

        path_engine = AttackPathEngine()
        paths = path_engine.find_paths(graph, entry_points=["aws:internet"], targets=["aws:s3/customer-data"])
        assert len(paths) == 1
        assert paths[0].status == "potential_path"

    def test_default_targets_includes_s3_and_excludes_ec2(self):
        scan = _canonical_scenario()
        graph_engine = GraphEngine()
        graph = graph_engine.build(scan)

        targets = AttackPathEngine().default_targets(graph)
        assert "aws:s3/customer-data" in targets
        assert "aws:ec2/i-1" not in targets
