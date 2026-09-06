"""
Phase 3 unit tests — fully offline, no AWS/moto needed. Constructs Asset
objects directly to test the IAM analysis logic in isolation.
"""
from engine.iam.analyzer import IAMAnalyzer
from engine.models import Asset, EdgeType, NodeType

ACCOUNT = "123456789012"


def _role(name: str, arn: str, inline_policies=None, attached_policies=None, trust_doc=None) -> Asset:
    return Asset(
        id=f"aws:iam:role/{name}",
        type=NodeType.ROLE,
        account_id=ACCOUNT,
        arn=arn,
        name=name,
        raw_metadata={
            "assume_role_policy": trust_doc,
            "policies": {"inline": inline_policies or [], "attached": attached_policies or []},
        },
    )


class TestIAMAnalyzer:
    def test_flags_wildcard_action_and_resource_as_critical(self):
        role = _role(
            "AdminRole",
            "arn:aws:iam::123456789012:role/AdminRole",
            inline_policies=[
                {"name": "AdminAccess", "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
            ],
        )
        findings, _ = IAMAnalyzer().analyze([role])
        categories = {f.category for f in findings}
        assert "wildcard_action_and_resource" in categories
        assert any(f.severity == "critical" for f in findings)

    def test_flags_dangerous_action_pass_role(self):
        role = _role(
            "DeployRole",
            "arn:aws:iam::123456789012:role/DeployRole",
            inline_policies=[
                {
                    "name": "PassRolePolicy",
                    "document": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
                }
            ],
        )
        findings, _ = IAMAnalyzer().analyze([role])
        assert any(f.category == "dangerous_action" and "passrole" in f.evidence.get("action", "") for f in findings)

    def test_scoped_service_wildcard_is_not_flagged_as_full_admin(self):
        """`s3:*` on a scoped resource is NOT the same as `*` on `*` — the
        analyzer must not conflate a service-scoped wildcard with full
        admin access. This is the naive-'*'-detection trap called out in
        ARCHITECTURE.md Section 8. Effective-permission narrowing via an
        explicit Deny is covered separately in policy_eval tests."""
        role = _role(
            "S3AdminRole",
            "arn:aws:iam::123456789012:role/S3AdminRole",
            inline_policies=[
                {
                    "name": "S3FullAccess",
                    "document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
                }
            ],
        )
        findings, _ = IAMAnalyzer().analyze([role])
        categories = {f.category for f in findings}
        assert "wildcard_action_and_resource" not in categories
        assert "wildcard_action" not in categories

    def test_builds_can_pass_role_edge_between_roles(self):
        target_role = _role("TargetRole", "arn:aws:iam::123456789012:role/TargetRole")
        source_role = _role(
            "SourceRole",
            "arn:aws:iam::123456789012:role/SourceRole",
            inline_policies=[
                {
                    "name": "PassToTarget",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:PassRole",
                                "Resource": "arn:aws:iam::123456789012:role/TargetRole",
                            }
                        ]
                    },
                }
            ],
        )
        _, relationships = IAMAnalyzer().analyze([source_role, target_role])
        pass_role_edges = [r for r in relationships if r.type == EdgeType.CAN_PASS_ROLE]
        assert len(pass_role_edges) == 1
        assert pass_role_edges[0].source_id == source_role.id
        assert pass_role_edges[0].target_id == target_role.id

    def test_builds_can_assume_edge_from_trust_policy(self):
        role = _role(
            "AssumableRole",
            "arn:aws:iam::123456789012:role/AssumableRole",
            trust_doc={
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/OtherRole"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        )
        _, relationships = IAMAnalyzer().analyze([role])
        assume_edges = [r for r in relationships if r.type == EdgeType.CAN_ASSUME]
        assert len(assume_edges) == 1
        assert assume_edges[0].source_id == "aws:iam:role/OtherRole"
        assert assume_edges[0].target_id == role.id
