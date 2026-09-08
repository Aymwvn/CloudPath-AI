from engine.attack_paths.whatif import EdgeRemoval, WhatIfSimulator
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult

ACCOUNT = "123456789012"


def _canonical_scan() -> ScanResult:
    """Internet -> EC2 -> RoleA --CAN_PASS_ROLE--> RoleB -> Secret.

    Same shape as the risk engine's escalation scenario — removing the
    CAN_PASS_ROLE edge should block the path entirely.
    """
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(id="aws:iam:role/RoleA", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleA"),
        Asset(id="aws:iam:role/RoleB", type=NodeType.ROLE, account_id=ACCOUNT, name="RoleB"),
        Asset(id="aws:secret/prod-password", type=NodeType.SECRET, account_id=ACCOUNT, name="prod-password"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(source_id="aws:ec2/i-1", target_id="aws:iam:role/RoleA", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(source_id="aws:iam:role/RoleA", target_id="aws:iam:role/RoleB", type=EdgeType.CAN_PASS_ROLE, confidence=0.9),
        Relationship(source_id="aws:iam:role/RoleB", target_id="aws:secret/prod-password", type=EdgeType.CAN_READ, confidence=0.9),
    ]
    return scan


class TestWhatIfSimulator:
    def test_removing_the_escalation_edge_blocks_the_path(self):
        scan = _canonical_scan()
        result = WhatIfSimulator().simulate(
            scan,
            removals=[EdgeRemoval(source_id="aws:iam:role/RoleA", target_id="aws:iam:role/RoleB", edge_type="CAN_PASS_ROLE")],
            entry_points=["aws:internet"],
            targets=["aws:secret/prod-password"],
        )

        assert len(result.paths_before) == 1
        assert len(result.paths_after) == 0
        assert result.paths_blocked_count == 1

    def test_removing_an_unrelated_edge_does_not_block_the_path(self):
        scan = _canonical_scan()
        # add a decoy edge that does NOT create any new route to the
        # target — it just dangles off RoleA to an unrelated asset — so
        # removing it should have zero effect on the real path.
        scan.assets.append(Asset(id="aws:s3/unrelated-bucket", type=NodeType.S3, account_id=ACCOUNT, name="unrelated-bucket"))
        scan.relationships.append(
            Relationship(source_id="aws:iam:role/RoleA", target_id="aws:s3/unrelated-bucket", type=EdgeType.USES, confidence=1.0)
        )
        result = WhatIfSimulator().simulate(
            scan,
            removals=[EdgeRemoval(source_id="aws:iam:role/RoleA", target_id="aws:s3/unrelated-bucket", edge_type="USES")],
            entry_points=["aws:internet"],
            targets=["aws:secret/prod-password"],
        )
        assert result.paths_blocked_count == 0
        assert len(result.paths_after) == 1

    def test_removal_of_nonexistent_edge_is_a_no_op(self):
        scan = _canonical_scan()
        result = WhatIfSimulator().simulate(
            scan,
            removals=[EdgeRemoval(source_id="aws:does", target_id="aws:not-exist", edge_type="TRUSTS")],
            entry_points=["aws:internet"],
            targets=["aws:secret/prod-password"],
        )
        assert result.paths_blocked_count == 0
        assert len(result.paths_before) == len(result.paths_after) == 1

    def test_original_graph_is_not_mutated_by_simulation(self):
        """The simulator must operate on a COPY — running a what-if
        should never affect the real scan data or a subsequent real
        attack-path search."""
        scan = _canonical_scan()
        original_relationship_count = len(scan.relationships)

        WhatIfSimulator().simulate(
            scan,
            removals=[EdgeRemoval(source_id="aws:iam:role/RoleA", target_id="aws:iam:role/RoleB", edge_type="CAN_PASS_ROLE")],
            entry_points=["aws:internet"],
            targets=["aws:secret/prod-password"],
        )

        # scan_result itself is untouched, and a fresh graph build from it
        # should still show the original (unblocked) path
        assert len(scan.relationships) == original_relationship_count

        from engine.attack_paths.engine import AttackPathEngine
        from engine.graph.builder import GraphEngine

        fresh_graph = GraphEngine().build(scan)
        fresh_paths = AttackPathEngine().find_paths(fresh_graph, ["aws:internet"], ["aws:secret/prod-password"])
        assert len(fresh_paths) == 1

    def test_new_risk_score_computed_for_surviving_paths(self):
        scan = _canonical_scan()
        # add a second, unrelated safe target so at least one path survives
        scan.assets.append(Asset(id="aws:s3/logs", type=NodeType.S3, account_id=ACCOUNT, name="logs"))
        scan.relationships.append(
            Relationship(source_id="aws:iam:role/RoleA", target_id="aws:s3/logs", type=EdgeType.CAN_READ, confidence=1.0)
        )

        result = WhatIfSimulator().simulate(
            scan,
            removals=[EdgeRemoval(source_id="aws:iam:role/RoleA", target_id="aws:iam:role/RoleB", edge_type="CAN_PASS_ROLE")],
            entry_points=["aws:internet"],
            targets=["aws:secret/prod-password", "aws:s3/logs"],
        )
        assert len(result.paths_after) == 1  # only the S3 path survives
        assert len(result.new_risk_by_path_key) == 1
