"""
Phase 8 integration tests — exercises the full pipeline (phases 1-7)
through the FastAPI layer, using moto to mock AWS end to end.
Updated for Phase 18: every call now requires a bearer token.
"""
import boto3
import uuid
from fastapi.testclient import TestClient
from moto import mock_aws

from backend.auth import create_access_token
from backend.main import app, service
from backend.scan_service import InMemoryScanStore

client = TestClient(app)

# A unique username per test-process run (not a fixed literal) — the
# scan-creation rate limiter (Phase 18, backend/rate_limit.py) tracks
# usage in REAL Redis keyed by username. A fixed username like
# "test-analyst" across repeated pytest runs within the same hour
# accumulates count toward the same limit and eventually fails with 429
# for reasons that have nothing to do with the test itself. Confirmed by
# hitting exactly this failure mode while developing this test file.
_TEST_USERNAME = f"test-analyst-{uuid.uuid4().hex[:8]}"
ANALYST_HEADERS = {"Authorization": f"Bearer {create_access_token(_TEST_USERNAME, 'analyst')}"}


def _seed_mocked_aws():
    """Same canonical scenario as tests/test_aws_provider.py: public EC2
    with an instance role that can read an S3 bucket."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    s3 = session.client("s3")

    trust_policy = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName="WebServerRole", AssumeRolePolicyDocument=trust_policy)
    iam.put_role_policy(
        RoleName="WebServerRole",
        PolicyName="S3ReadAccess",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}',
    )
    iam.create_instance_profile(InstanceProfileName="WebServerProfile")
    iam.add_role_to_instance_profile(InstanceProfileName="WebServerProfile", RoleName="WebServerRole")

    s3.create_bucket(Bucket="customer-data-bucket")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"])


class TestScanAPI:
    def setup_method(self):
        # reset the module-level in-memory store between tests so results
        # from one test don't leak into another
        service.store = InMemoryScanStore()

    @mock_aws
    def test_health_check(self):
        # /health is intentionally unauthenticated (liveness probe)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    @mock_aws
    def test_create_scan_returns_summary(self):
        _seed_mocked_aws()
        resp = client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=ANALYST_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["asset_count"] > 0
        assert "scan_id" in body

    @mock_aws
    def test_create_scan_without_auth_is_rejected(self):
        _seed_mocked_aws()
        resp = client.post("/api/v1/scans", json={"region": "us-east-1"})
        assert resp.status_code == 401

    @mock_aws
    def test_create_scan_with_viewer_role_is_forbidden(self):
        """RBAC: viewer role can read but not trigger scans."""
        _seed_mocked_aws()
        viewer_headers = {"Authorization": f"Bearer {create_access_token('test-viewer', 'viewer')}"}
        resp = client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=viewer_headers)
        assert resp.status_code == 403

    @mock_aws
    def test_get_scan_by_id(self):
        _seed_mocked_aws()
        create_resp = client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=ANALYST_HEADERS)
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}", headers=ANALYST_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_get_unknown_scan_returns_404(self):
        resp = client.get("/api/v1/scans/does-not-exist", headers=ANALYST_HEADERS)
        assert resp.status_code == 404

    @mock_aws
    def test_list_assets_after_scan(self):
        _seed_mocked_aws()
        client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=ANALYST_HEADERS)
        resp = client.get("/api/v1/assets", headers=ANALYST_HEADERS)
        assert resp.status_code == 200
        assets = resp.json()
        assert any(a["type"] == "EC2" for a in assets)
        assert any(a["type"] == "S3" for a in assets)

    @mock_aws
    def test_list_assets_readable_by_viewer_role(self):
        """RBAC: viewer CAN read, just not trigger scans."""
        _seed_mocked_aws()
        client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=ANALYST_HEADERS)
        viewer_headers = {"Authorization": f"Bearer {create_access_token('test-viewer', 'viewer')}"}
        resp = client.get("/api/v1/assets", headers=viewer_headers)
        assert resp.status_code == 200

    def test_list_assets_with_no_scan_returns_404(self):
        resp = client.get("/api/v1/assets", headers=ANALYST_HEADERS)
        assert resp.status_code == 404

    @mock_aws
    def test_statistics_reflect_graph(self):
        _seed_mocked_aws()
        client.post("/api/v1/scans", json={"region": "us-east-1"}, headers=ANALYST_HEADERS)
        resp = client.get("/api/v1/statistics", headers=ANALYST_HEADERS)
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["node_count"] > 0
        assert "EC2" in stats["node_types"]
