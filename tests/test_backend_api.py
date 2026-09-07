"""
Phase 8 integration tests — exercises the full pipeline (phases 1-7)
through the FastAPI layer, using moto to mock AWS end to end.
"""
import boto3
from fastapi.testclient import TestClient
from moto import mock_aws

from backend.main import app, service
from backend.scan_service import InMemoryScanStore, ScanService

client = TestClient(app)


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
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    @mock_aws
    def test_create_scan_returns_summary(self):
        _seed_mocked_aws()
        resp = client.post("/api/v1/scans", json={"region": "us-east-1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["asset_count"] > 0
        assert "scan_id" in body

    @mock_aws
    def test_get_scan_by_id(self):
        _seed_mocked_aws()
        create_resp = client.post("/api/v1/scans", json={"region": "us-east-1"})
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_get_unknown_scan_returns_404(self):
        resp = client.get("/api/v1/scans/does-not-exist")
        assert resp.status_code == 404

    @mock_aws
    def test_list_assets_after_scan(self):
        _seed_mocked_aws()
        client.post("/api/v1/scans", json={"region": "us-east-1"})
        resp = client.get("/api/v1/assets")
        assert resp.status_code == 200
        assets = resp.json()
        assert any(a["type"] == "EC2" for a in assets)
        assert any(a["type"] == "S3" for a in assets)

    def test_list_assets_with_no_scan_returns_404(self):
        resp = client.get("/api/v1/assets")
        assert resp.status_code == 404

    @mock_aws
    def test_statistics_reflect_graph(self):
        _seed_mocked_aws()
        client.post("/api/v1/scans", json={"region": "us-east-1"})
        resp = client.get("/api/v1/statistics")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["node_count"] > 0
        assert "EC2" in stats["node_types"]
