from engine.attack_paths.engine import AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.risk.engine import RiskEngine

ACCOUNT = "123456789012"


def _escalation_scenario() -> ScanResult:
    """Internet -> EC2 -> Role A --CAN_PASS_ROLE--> Role B -> Secret.

    Deliberately includes a privilege-escalation edge and a sensitive
    target so it should score HIGH/CRITICAL.
    """
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(id="aws:iam:role/RoleA", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleA"),
        Asset(id="aws:iam:role/RoleB", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleB"),
        Asset(id="aws:secret/prod-db-password", type=NodeType.SECRET, account_id=ACCOUNT, name="prod-db-password"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(source_id="aws:ec2/i-1", target_id="aws:iam:role/RoleA", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(
            source_id="aws:iam:role/RoleA",
            target_id="aws:iam:role/RoleB",
            type=EdgeType.CAN_PASS_ROLE,
            confidence=0.9,
        ),
        Relationship(
            source_id="aws:iam:role/RoleB",
            target_id="aws:secret/prod-db-password",
            type=EdgeType.CAN_READ,
            confidence=0.9,
        ),
    ]
    return scan


def _benign_scenario() -> ScanResult:
    """Same shape but no privilege escalation edge and no public entry."""
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-2", type=NodeType.EC2, account_id=ACCOUNT, name="i-2", public=False),
        Asset(id="aws:iam:role/ReadOnlyRole", type=NodeType.ROLE, account_id=ACCOUNT, name="ReadOnlyRole"),
        Asset(id="aws:s3/logs", type=NodeType.S3, account_id=ACCOUNT, name="logs"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:ec2/i-2", target_id="aws:iam:role/ReadOnlyRole", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(source_id="aws:iam:role/ReadOnlyRole", target_id="aws:s3/logs", type=EdgeType.CAN_READ, confidence=1.0),
    ]
    return scan


class TestRiskEngine:
    def test_escalation_path_scores_high_or_critical(self):
        scan = _escalation_scenario()
        graph = GraphEngine().build(scan)
        paths = AttackPathEngine().find_paths(
            graph, entry_points=["aws:internet"], targets=["aws:secret/prod-db-password"]
        )
        assert len(paths) == 1

        assessment = RiskEngine().score(paths[0], graph)
        assert assessment.severity in {"HIGH", "CRITICAL"}
        assert assessment.risk_score > 50

    def test_risk_and_confidence_are_independent_numbers(self):
        scan = _escalation_scenario()
        # weaken one edge's confidence without changing the risk factors at all
        scan.relationships[2].confidence = 0.55
        graph = GraphEngine().build(scan)
        paths = AttackPathEngine().find_paths(
            graph, entry_points=["aws:internet"], targets=["aws:secret/prod-db-password"]
        )
        assessment = RiskEngine().score(paths[0], graph)

        # risk score should be unaffected by confidence (they're separate factors)
        assert assessment.severity in {"HIGH", "CRITICAL"}
        # confidence should reflect the weakened edge
        assert assessment.confidence < 1.0

    def test_declared_crown_jewel_increases_score_over_undeclared(self):
        scan = _escalation_scenario()
        graph = GraphEngine().build(scan)
        paths = AttackPathEngine().find_paths(
            graph, entry_points=["aws:internet"], targets=["aws:secret/prod-db-password"]
        )

        undeclared = RiskEngine().score(paths[0], graph)
        declared = RiskEngine(crown_jewel_ids={"aws:secret/prod-db-password"}).score(paths[0], graph)

        assert declared.risk_score >= undeclared.risk_score

    def test_benign_internal_path_scores_lower_than_escalation_path(self):
        escalation_scan = _escalation_scenario()
        escalation_graph = GraphEngine().build(escalation_scan)
        escalation_paths = AttackPathEngine().find_paths(
            escalation_graph, entry_points=["aws:internet"], targets=["aws:secret/prod-db-password"]
        )
        escalation_score = RiskEngine().score(escalation_paths[0], escalation_graph).risk_score

        benign_scan = _benign_scenario()
        benign_graph = GraphEngine().build(benign_scan)
        benign_paths = AttackPathEngine().find_paths(
            benign_graph, entry_points=["aws:ec2/i-2"], targets=["aws:s3/logs"]
        )
        benign_score = RiskEngine().score(benign_paths[0], benign_graph).risk_score

        assert escalation_score > benign_score
