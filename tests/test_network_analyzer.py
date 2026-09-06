from engine.iam.policy_eval import evaluate
from engine.models import Asset, EdgeType, NodeType
from engine.network.analyzer import NetworkAnalyzer

ACCOUNT = "123456789012"


def _sg(name: str, ip_permissions: list) -> Asset:
    return Asset(
        id=f"aws:sg/{name}",
        type=NodeType.SECURITY_GROUP,
        account_id=ACCOUNT,
        name=name,
        raw_metadata={"ip_permissions": ip_permissions, "ip_permissions_egress": []},
    )


def _bucket(name: str, policy=None, acl=None, pab=None) -> Asset:
    return Asset(
        id=f"aws:s3/{name}",
        type=NodeType.S3,
        account_id=ACCOUNT,
        name=name,
        raw_metadata={"policy": policy, "acl": acl or {"Grants": []}, "public_access_block": pab or {}},
    )


class TestNetworkAnalyzerSecurityGroups:
    def test_flags_open_ssh_as_critical(self):
        sg = _sg(
            "web-sg",
            [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        findings, _ = NetworkAnalyzer().analyze([sg])
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "SSH" in findings[0].detail

    def test_does_not_flag_restricted_cidr(self):
        sg = _sg(
            "internal-sg",
            [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
        )
        findings, _ = NetworkAnalyzer().analyze([sg])
        assert findings == []

    def test_flags_non_sensitive_wide_open_port_as_medium(self):
        sg = _sg(
            "app-sg",
            [{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        findings, _ = NetworkAnalyzer().analyze([sg])
        assert len(findings) == 1
        assert findings[0].severity == "medium"


class TestNetworkAnalyzerS3:
    def test_public_access_block_fully_enabled_prevents_public_finding(self):
        bucket = _bucket(
            "safe-bucket",
            policy='{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}',
            pab={
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        )
        findings, relationships = NetworkAnalyzer().analyze([bucket])
        assert findings == []
        assert relationships == []

    def test_public_policy_without_block_is_flagged_and_wired_to_internet(self):
        bucket = _bucket(
            "leaky-bucket",
            policy='{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}',
            pab={},
        )
        findings, relationships = NetworkAnalyzer().analyze([bucket])
        assert len(findings) == 1
        assert findings[0].category == "public_s3_bucket"
        assert any(r.type == EdgeType.EXPOSED_TO and r.target_id == bucket.id for r in relationships)

    def test_private_bucket_with_no_policy_is_not_flagged(self):
        bucket = _bucket("private-bucket", policy=None, pab={})
        findings, relationships = NetworkAnalyzer().analyze([bucket])
        assert findings == []
        assert relationships == []


class TestPolicyEvalEffectivePermissions:
    def test_explicit_deny_overrides_allow(self):
        identity_policies = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
            {"Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]},
        ]
        assert evaluate("s3:GetObject", "arn:aws:s3:::bucket/x", identity_policies) is True
        assert evaluate("s3:DeleteObject", "arn:aws:s3:::bucket/x", identity_policies) is False

    def test_boundary_narrows_but_never_expands(self):
        identity_policies = [{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}]
        narrow_boundary = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}

        assert evaluate("s3:GetObject", "x", identity_policies, boundary_policy=narrow_boundary) is True
        assert evaluate("s3:DeleteObject", "x", identity_policies, boundary_policy=narrow_boundary) is False

    def test_no_allow_anywhere_means_denied_by_default(self):
        identity_policies = [{"Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}]
        assert evaluate("s3:GetObject", "x", identity_policies) is False
