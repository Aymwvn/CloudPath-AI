"""
Tests for backend/graph_export.py — the payload that feeds the new
interactive attack graph frontend page.
"""
from backend.graph_export import build_graph_payload
from backend.scan_service import ScanRecord
from engine.attack_paths.engine import AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.risk.engine import RiskEngine

ACCOUNT = "123456789012"


def _escalation_scan() -> ScanResult:
    """Internet -> EC2 -> RoleA --CAN_PASS_ROLE--> RoleB -> Secret, plus
    an unrelated safe asset with no attack path touching it — used to
    confirm severity annotation only touches what it should."""
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(id="aws:iam:role/RoleA", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleA"),
        Asset(id="aws:iam:role/RoleB", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleB"),
        Asset(id="aws:secret/prod-password", type=NodeType.SECRET, account_id=ACCOUNT, name="prod-password"),
        Asset(id="aws:s3/unrelated-bucket", type=NodeType.S3, account_id=ACCOUNT, name="unrelated-bucket"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(source_id="aws:ec2/i-1", target_id="aws:iam:role/RoleA", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(source_id="aws:iam:role/RoleA", target_id="aws:iam:role/RoleB", type=EdgeType.CAN_PASS_ROLE,
                     confidence=0.9, evidence={"action": "iam:PassRole"}),
        Relationship(source_id="aws:iam:role/RoleB", target_id="aws:secret/prod-password", type=EdgeType.CAN_READ, confidence=0.9),
    ]
    return scan


def _build_record(scan: ScanResult, targets: list[str]) -> ScanRecord:
    graph_engine = GraphEngine()
    graph = graph_engine.build(scan)
    paths = AttackPathEngine().find_paths(graph, entry_points=["aws:internet"], targets=targets)
    risk_engine = RiskEngine()
    scored = [(p, risk_engine.score(p, graph)) for p in paths]
    return ScanRecord(scan_id="test-scan", scan_result=scan, graph_engine=graph_engine, attack_paths=scored)


class TestGraphPayloadStructure:
    def test_edges_include_evidence_for_click_detail(self):
        """Edge evidence must be included in the payload — this is what
        the frontend's edge-click detail panel (ARCHITECTURE.md Section
        24: 'clicking an edge should show relationship/evidence/...')
        actually displays; without it the feature would have nothing
        real to show."""
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        pass_role_edge = next(e for e in payload["edges"] if e["type"] == "CAN_PASS_ROLE")
        assert "evidence" in pass_role_edge
        # confirms evidence actually flows through Relationship ->
        # GraphEngine -> build_graph_payload end to end, not just that
        # the key exists on the response shape
        assert pass_role_edge["evidence"] == {"action": "iam:PassRole"}


    def test_includes_every_node_and_edge_not_just_attack_path_ones(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        node_ids = {n["id"] for n in payload["nodes"]}
        # the unrelated bucket has NO attack path touching it, but must
        # still appear — an analyst needs to see the whole environment
        assert "aws:s3/unrelated-bucket" in node_ids
        assert len(payload["nodes"]) == 6  # all 6 assets, not just the 4 on the path

    def test_edge_count_matches_graph_edge_count(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)
        assert len(payload["edges"]) == record.graph_engine.graph.number_of_edges()


class TestSeverityAnnotation:
    def test_nodes_on_the_attack_path_are_flagged_with_severity(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        nodes_by_id = {n["id"]: n for n in payload["nodes"]}
        assert nodes_by_id["aws:ec2/i-1"]["on_attack_path"] is True
        assert nodes_by_id["aws:ec2/i-1"]["max_severity"] in {"HIGH", "CRITICAL", "MEDIUM"}

    def test_unrelated_node_is_not_flagged(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        nodes_by_id = {n["id"]: n for n in payload["nodes"]}
        assert nodes_by_id["aws:s3/unrelated-bucket"]["on_attack_path"] is False
        assert nodes_by_id["aws:s3/unrelated-bucket"]["max_severity"] is None

    def test_edges_on_the_attack_path_are_flagged(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        pass_role_edge = next(e for e in payload["edges"] if e["type"] == "CAN_PASS_ROLE")
        assert pass_role_edge["on_attack_path"] is True
        assert pass_role_edge["max_severity"] is not None

    def test_severity_takes_the_max_across_multiple_paths_touching_the_same_node(self):
        """If a node sits on both a LOW-risk path and a CRITICAL-risk
        path, it should be annotated CRITICAL, not the first one found or
        an average."""
        scan = _escalation_scan()
        # add a second, low-risk path that also touches RoleA (internal,
        # no internet exposure at that hop) so RoleA sits on two paths
        # with different severities
        scan.assets.append(Asset(id="aws:s3/logs", type=NodeType.S3, account_id=ACCOUNT, name="logs"))
        scan.relationships.append(
            Relationship(source_id="aws:iam:role/RoleA", target_id="aws:s3/logs", type=EdgeType.CAN_READ, confidence=1.0)
        )
        record = _build_record(scan, targets=["aws:secret/prod-password", "aws:s3/logs"])
        payload = build_graph_payload(record)

        nodes_by_id = {n["id"]: n for n in payload["nodes"]}
        severities_found = {sev for _, risk in record.attack_paths for sev in [risk.severity]}
        role_a_severity = nodes_by_id["aws:iam:role/RoleA"]["max_severity"]
        # RoleA's annotated severity must be the highest of any path touching it
        assert role_a_severity == max(severities_found, key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[s])

    def test_no_attack_paths_means_nothing_is_flagged(self):
        """A scan where nothing reaches any target should produce a
        graph payload with every node/edge unflagged, not an error."""
        scan = ScanResult(account_id=ACCOUNT, provider="aws")
        scan.assets = [Asset(id="aws:s3/isolated", type=NodeType.S3, account_id=ACCOUNT, name="isolated")]
        record = _build_record(scan, targets=[])
        payload = build_graph_payload(record)

        assert len(payload["nodes"]) == 1
        assert payload["nodes"][0]["on_attack_path"] is False
        assert payload["stats"]["attack_path_count"] == 0


class TestStatsSummary:
    def test_stats_reflect_actual_counts(self):
        scan = _escalation_scan()
        record = _build_record(scan, targets=["aws:secret/prod-password"])
        payload = build_graph_payload(record)

        assert payload["stats"]["node_count"] == len(payload["nodes"])
        assert payload["stats"]["edge_count"] == len(payload["edges"])
        assert payload["stats"]["attack_path_count"] == len(record.attack_paths)
