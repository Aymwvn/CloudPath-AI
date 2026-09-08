import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.models import NodeType
from mitre.mapper import MitreMapper


class TestMitreMapperOffline:
    def test_exposed_to_edge_maps_to_public_facing_and_remote_services(self):
        path = AttackPath(
            entry="aws:internet",
            target="aws:ec2/i-1",
            steps=[AttackPathStep(source="aws:internet", target="aws:ec2/i-1", edge_type="EXPOSED_TO", evidence={"public_ip": "1.2.3.4"}, confidence=1.0)],
        )
        mappings = MitreMapper().map_path(path)
        ids = {m.technique_id for m in mappings}
        assert "T1190" in ids
        assert "T1133" in ids

    def test_can_pass_role_maps_to_account_manipulation(self):
        path = AttackPath(
            entry="aws:iam:role/A",
            target="aws:iam:role/B",
            steps=[AttackPathStep(source="aws:iam:role/A", target="aws:iam:role/B", edge_type="CAN_PASS_ROLE", evidence={}, confidence=0.9)],
        )
        mappings = MitreMapper().map_path(path)
        assert any(m.technique_id == "T1098.003" for m in mappings)

    def test_s3_target_adds_data_from_cloud_storage(self):
        path = AttackPath(
            entry="aws:ec2/i-1",
            target="aws:s3/bucket",
            steps=[AttackPathStep(source="aws:ec2/i-1", target="aws:s3/bucket", edge_type="CAN_READ", evidence={}, confidence=0.9)],
        )
        mappings = MitreMapper().map_path(path, target_node_type=NodeType.S3)
        assert any(m.technique_id == "T1530" for m in mappings)

    def test_no_matching_edge_type_produces_no_mapping_for_that_step(self):
        path = AttackPath(
            entry="a", target="b",
            steps=[AttackPathStep(source="a", target="b", edge_type="CONTAINS", evidence={}, confidence=1.0)],
        )
        mappings = MitreMapper().map_path(path)
        assert mappings == []

    def test_technique_not_duplicated_across_multiple_matching_steps(self):
        path = AttackPath(
            entry="aws:internet",
            target="aws:ec2/i-2",
            steps=[
                AttackPathStep(source="aws:internet", target="aws:ec2/i-1", edge_type="EXPOSED_TO", evidence={}, confidence=1.0),
                AttackPathStep(source="aws:ec2/i-1", target="aws:ec2/i-2", edge_type="EXPOSED_TO", evidence={}, confidence=1.0),
            ],
        )
        mappings = MitreMapper().map_path(path)
        t1190_count = sum(1 for m in mappings if m.technique_id == "T1190")
        assert t1190_count == 1

    def test_evidence_is_carried_from_the_matching_step(self):
        path = AttackPath(
            entry="aws:internet",
            target="aws:ec2/i-1",
            steps=[AttackPathStep(source="aws:internet", target="aws:ec2/i-1", edge_type="EXPOSED_TO", evidence={"public_ip": "9.9.9.9"}, confidence=1.0)],
        )
        mappings = MitreMapper().map_path(path)
        t1190 = next(m for m in mappings if m.technique_id == "T1190")
        assert t1190.evidence == {"public_ip": "9.9.9.9"}


# ---------------------------------------------------------------------
# Persisted round-trip — confirms store.py actually computes and saves
# mappings when a scan is saved, using the real Postgres test db.
# ---------------------------------------------------------------------
TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/cloudpath"
)


def _postgres_available() -> bool:
    try:
        engine = create_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _postgres_available(), reason="Postgres not reachable at TEST_DATABASE_URL")
class TestMitrePersistence:
    @pytest.fixture()
    def session_factory(self):
        from backend.db.models import Base

        engine = create_engine(TEST_DB_URL)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, future=True)
        yield factory
        with engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())

    def test_mitre_techniques_persisted_when_scan_is_saved(self, session_factory):
        from backend.db import models
        from backend.db.store import PostgresScanStore
        from backend.scan_service import ScanRecord
        from engine.graph.builder import GraphEngine
        from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
        from engine.risk.engine import RiskAssessment

        scan = ScanResult(account_id="123456789012", provider="aws")
        scan.assets = [
            Asset(id="aws:internet", type=NodeType.INTERNET, account_id="123456789012", name="Internet"),
            Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id="123456789012", name="i-1", public=True),
            Asset(id="aws:s3/bucket-1", type=NodeType.S3, account_id="123456789012", name="bucket-1"),
        ]
        scan.relationships = [
            Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
            Relationship(source_id="aws:ec2/i-1", target_id="aws:s3/bucket-1", type=EdgeType.CAN_READ, confidence=0.8),
        ]
        graph_engine = GraphEngine()
        graph_engine.build(scan)

        path = AttackPath(
            entry="aws:internet",
            target="aws:s3/bucket-1",
            steps=[
                AttackPathStep(source="aws:internet", target="aws:ec2/i-1", edge_type="EXPOSED_TO", evidence={}, confidence=1.0),
                AttackPathStep(source="aws:ec2/i-1", target="aws:s3/bucket-1", edge_type="CAN_READ", evidence={}, confidence=0.8),
            ],
        )
        risk = RiskAssessment(risk_score=72, severity="HIGH", confidence=0.9, status="path", factor_breakdown={})
        record = ScanRecord(scan_id="mitre-test-scan", scan_result=scan, graph_engine=graph_engine, attack_paths=[(path, risk)])

        store = PostgresScanStore(session_factory=session_factory)
        store.save(record)

        session = session_factory()
        try:
            path_row = session.query(models.AttackPathModel).filter_by(scan_job_id=record.scan_id).one()
            mitre_rows = session.query(models.MitreTechniqueModel).filter_by(attack_path_id=path_row.id).all()
            technique_ids = {r.technique_id for r in mitre_rows}
            assert "T1190" in technique_ids  # from the EXPOSED_TO step
            assert "T1530" in technique_ids  # from the S3 target
        finally:
            session.close()
