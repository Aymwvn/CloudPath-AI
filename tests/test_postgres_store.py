"""
Phase 9 integration test — runs against a REAL Postgres instance (not
mocked), confirming persist -> rehydrate round-trips correctly.

Requires DATABASE_URL pointing at a real (test) Postgres database.
Skips automatically if that database isn't reachable, so this test
doesn't break CI environments without a Postgres service configured —
see docker-compose.yml for the real service definition.
"""
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.db.models import Base
from backend.db.store import PostgresScanStore
from backend.scan_service import ScanRecord
from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.risk.engine import RiskAssessment

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


pytestmark = pytest.mark.skipif(not _postgres_available(), reason="Postgres not reachable at TEST_DATABASE_URL")


@pytest.fixture()
def store():
    engine = create_engine(TEST_DB_URL)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, future=True)
    yield PostgresScanStore(session_factory=session_factory)
    # clean up rows created by this test run (keep schema for speed)
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


def _sample_record() -> ScanRecord:
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
        status="path",
    )
    risk = RiskAssessment(risk_score=72, severity="HIGH", confidence=0.9, status="path", factor_breakdown={})

    return ScanRecord(
        scan_id="test-scan-001",
        scan_result=scan,
        graph_engine=graph_engine,
        attack_paths=[(path, risk)],
    )


class TestPostgresScanStore:
    def test_save_and_get_round_trips_assets(self, store: PostgresScanStore):
        record = _sample_record()
        store.save(record)

        fetched = store.get(record.scan_id)
        assert fetched is not None
        assert len(fetched.scan_result.assets) == 3
        asset_ids = {a.id for a in fetched.scan_result.assets}
        assert "aws:s3/bucket-1" in asset_ids

    def test_save_and_get_round_trips_attack_paths(self, store: PostgresScanStore):
        record = _sample_record()
        store.save(record)

        fetched = store.get(record.scan_id)
        assert len(fetched.attack_paths) == 1
        path, risk = fetched.attack_paths[0]
        assert risk.severity == "HIGH"
        assert risk.risk_score == 72
        assert path.hop_count == 2

    def test_latest_returns_most_recently_saved_scan(self, store: PostgresScanStore):
        first = _sample_record()
        first.scan_id = "scan-a"
        store.save(first)

        second = _sample_record()
        second.scan_id = "scan-b"
        store.save(second)

        latest = store.latest()
        assert latest.scan_id == "scan-b"

    def test_get_unknown_scan_returns_none(self, store: PostgresScanStore):
        assert store.get("does-not-exist") is None

    def test_rehydrated_graph_engine_is_usable(self, store: PostgresScanStore):
        """The rehydrated ScanRecord's GraphEngine should be a real,
        queryable graph — not just a data shell."""
        record = _sample_record()
        store.save(record)

        fetched = store.get(record.scan_id)
        stats = fetched.graph_engine.stats()
        assert stats["node_count"] == 3
        assert stats["edge_count"] == 2
