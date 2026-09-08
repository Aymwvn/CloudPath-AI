"""
Phase 10 test — runs the Celery task in eager mode (synchronous, no
broker needed) against mocked AWS and a real Postgres test database.
Confirms the pending -> running -> completed status lifecycle actually
happens, which is the entire point of moving scans to a background task
(ARCHITECTURE.md Section 30).
"""
import os

import boto3
import pytest
from moto import mock_aws
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

os.environ["CELERY_TASK_ALWAYS_EAGER"] = "1"

from backend.db.models import Base  # noqa: E402
from backend.db.store import PostgresScanStore  # noqa: E402

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


def _seed_mocked_aws():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="async-test-bucket")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"])


class TestScanTaskLifecycle:
    @mock_aws
    def test_pending_job_transitions_to_completed(self, session_factory, monkeypatch):
        _seed_mocked_aws()

        # point the task's lazily-imported SessionLocal at our test db
        monkeypatch.setattr("backend.db.session.SessionLocal", session_factory)

        from backend.tasks.scan_tasks import run_scan_task

        store = PostgresScanStore(session_factory=session_factory)
        scan_id = "async-test-scan-001"
        store.create_pending_job(scan_id, account_hint="unknown")

        # eager mode runs this synchronously in-process, no worker needed
        result = run_scan_task.apply(args=(scan_id, "us-east-1", None)).get()
        assert result == scan_id

        record = store.get(scan_id)
        assert record is not None
        assert record.status == "completed"
        assert len(record.scan_result.assets) > 0

    @mock_aws
    def test_failed_scan_marks_job_failed_not_silently_lost(self, session_factory, monkeypatch):
        monkeypatch.setattr("backend.db.session.SessionLocal", session_factory)
        monkeypatch.setattr(
            "backend.tasks.scan_tasks.ScanService.run_scan",
            lambda self, **kwargs: (_ for _ in ()).throw(RuntimeError("simulated collector failure")),
        )

        from backend.tasks.scan_tasks import run_scan_task

        store = PostgresScanStore(session_factory=session_factory)
        scan_id = "async-test-scan-fail"
        store.create_pending_job(scan_id)

        with pytest.raises(RuntimeError):
            run_scan_task.apply(args=(scan_id, "us-east-1", None)).get()

        # the job row must reflect the failure, not just vanish
        import backend.db.models as models

        session = session_factory()
        job = session.get(models.ScanJobModel, scan_id)
        session.close()
        assert job.status == "failed"
        assert "simulated collector failure" in job.error
