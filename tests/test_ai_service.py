"""
Phase 13 test — persist a scan to real Postgres (reusing the Phase 9
fixture pattern), then run AIAnalysisService against a real attack_path_id
with MockProvider injected (no network/API key needed).
"""
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.ai_service import AIAnalysisService, AttackPathNotFoundError, NoProviderConfiguredError
from backend.db import models
from backend.db.models import Base
from backend.db.store import PostgresScanStore
from ai.providers.mock import MockProvider
from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.risk.engine import RiskAssessment
from backend.scan_service import ScanRecord

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
def session_factory():
    engine = create_engine(TEST_DB_URL)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    yield factory
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


def _persist_sample_scan(session_factory) -> str:
    """Reuses the Phase 9 test fixture shape, returns the real attack_path_id."""
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

    record = ScanRecord(
        scan_id="phase13-test-scan",
        scan_result=scan,
        graph_engine=graph_engine,
        attack_paths=[(path, risk)],
    )
    store = PostgresScanStore(session_factory=session_factory)
    store.save(record)

    session = session_factory()
    try:
        row = session.query(models.AttackPathModel).filter_by(scan_job_id=record.scan_id).one()
        return row.id
    finally:
        session.close()


class TestAIAnalysisService:
    def test_analyze_persists_and_returns_valid_analysis(self, session_factory):
        path_id = _persist_sample_scan(session_factory)
        session = session_factory()
        try:
            service = AIAnalysisService(session=session, provider=MockProvider())
            analysis = service.analyze(path_id)
            assert analysis.classification == "potential_attack_path"

            row = session.query(models.AIAnalysisModel).filter_by(attack_path_id=path_id).one()
            assert row.model_used == "mock:test-model"
        finally:
            session.close()

    def test_get_existing_returns_none_before_analysis_run(self, session_factory):
        path_id = _persist_sample_scan(session_factory)
        session = session_factory()
        try:
            service = AIAnalysisService(session=session, provider=MockProvider())
            assert service.get_existing(path_id) is None
        finally:
            session.close()

    def test_get_existing_returns_prior_analysis_without_calling_provider_again(self, session_factory):
        path_id = _persist_sample_scan(session_factory)
        session = session_factory()
        try:
            provider = MockProvider()
            service = AIAnalysisService(session=session, provider=provider)
            service.analyze(path_id)
            assert provider.call_count == 1

            fetched = service.get_existing(path_id)
            assert fetched is not None
            assert provider.call_count == 1  # get_existing must not re-call the LLM
        finally:
            session.close()

    def test_unknown_path_id_raises_not_found(self, session_factory):
        session = session_factory()
        try:
            service = AIAnalysisService(session=session, provider=MockProvider())
            with pytest.raises(AttackPathNotFoundError):
                service.analyze("does-not-exist")
        finally:
            session.close()

    def test_re_analyzing_updates_existing_row_not_duplicates(self, session_factory):
        path_id = _persist_sample_scan(session_factory)
        session = session_factory()
        try:
            service = AIAnalysisService(session=session, provider=MockProvider())
            service.analyze(path_id)
            service.analyze(path_id)  # run again

            count = session.query(models.AIAnalysisModel).filter_by(attack_path_id=path_id).count()
            assert count == 1
        finally:
            session.close()

    def test_no_provider_configured_raises_clear_error(self, session_factory, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

        path_id = _persist_sample_scan(session_factory)
        session = session_factory()
        try:
            service = AIAnalysisService(session=session, provider=None)
            with pytest.raises(NoProviderConfiguredError):
                service.analyze(path_id)
        finally:
            session.close()
