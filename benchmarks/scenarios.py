"""
Phase 17 — benchmark scenario definitions.

Each scenario builds a ScanResult (same shapes as
tests/test_synthetic_scenarios.py) PLUS declares its ground truth:
exactly which attack paths, findings, and MITRE techniques SHOULD be
discovered. The benchmark runner (run_benchmark.py) diffs actual output
against this ground truth to compute precision/recall — this file is
deliberately kept separate from the test file so ground truth is a
first-class, readable data structure rather than buried in assert
statements.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult

ACCOUNT = "123456789012"


@dataclass
class ScenarioGroundTruth:
    name: str
    scan: ScanResult
    entry_points: list[str]
    targets: list[str]
    expected_path_keys: set[tuple]  # (entry, target, hop_count)
    expected_finding_categories: set[str]
    expected_mitre_techniques: set[str]


def scenario_1_public_ec2_to_s3() -> ScenarioGroundTruth:
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(id="aws:iam:role/WebServerRole", type=NodeType.ROLE, account_id=ACCOUNT, name="WebServerRole"),
        Asset(id="aws:s3/customer-data", type=NodeType.S3, account_id=ACCOUNT, name="customer-data"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(source_id="aws:ec2/i-1", target_id="aws:iam:role/WebServerRole", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(source_id="aws:iam:role/WebServerRole", target_id="aws:s3/customer-data", type=EdgeType.CAN_READ, confidence=0.9),
    ]
    return ScenarioGroundTruth(
        name="public_ec2_to_s3",
        scan=scan,
        entry_points=["aws:internet"],
        targets=["aws:s3/customer-data"],
        expected_path_keys={("aws:internet", "aws:s3/customer-data", 3)},
        expected_finding_categories=set(),  # no wildcard/dangerous perms, no open SG in this scenario
        expected_mitre_techniques={"T1190", "T1133", "T1530"},
    )


def scenario_2_pass_role_escalation() -> ScenarioGroundTruth:
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(id="aws:internet", type=NodeType.INTERNET, account_id=ACCOUNT, name="Internet"),
        Asset(id="aws:ec2/i-1", type=NodeType.EC2, account_id=ACCOUNT, name="i-1", public=True),
        Asset(
            id="aws:iam:role/LowPriv",
            type=NodeType.ROLE,
            account_id=ACCOUNT,
            name="LowPriv",
            raw_metadata={
                "policies": {
                    "inline": [
                        {"name": "PassRolePolicy", "document": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}
                    ],
                    "attached": [],
                }
            },
        ),
        Asset(id="aws:iam:role/HighPriv", type=NodeType.ROLE, account_id=ACCOUNT, name="HighPriv"),
        Asset(id="aws:s3/secrets-bucket", type=NodeType.S3, account_id=ACCOUNT, name="secrets-bucket"),
    ]
    scan.relationships = [
        Relationship(source_id="aws:internet", target_id="aws:ec2/i-1", type=EdgeType.EXPOSED_TO, confidence=1.0),
        Relationship(source_id="aws:ec2/i-1", target_id="aws:iam:role/LowPriv", type=EdgeType.RUNS_AS, confidence=1.0),
        Relationship(source_id="aws:iam:role/HighPriv", target_id="aws:s3/secrets-bucket", type=EdgeType.CAN_READ, confidence=0.9),
    ]
    return ScenarioGroundTruth(
        name="pass_role_escalation",
        scan=scan,
        entry_points=["aws:internet"],
        targets=["aws:s3/secrets-bucket"],
        expected_path_keys={("aws:internet", "aws:s3/secrets-bucket", 4)},
        expected_finding_categories={"dangerous_action"},
        expected_mitre_techniques={"T1190", "T1133", "T1098.003", "T1530"},
    )


def scenario_3_public_bucket() -> ScenarioGroundTruth:
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(
            id="aws:s3/leaky-bucket",
            type=NodeType.S3,
            account_id=ACCOUNT,
            name="leaky-bucket",
            raw_metadata={
                "policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}',
                "public_access_block": {},
            },
        )
    ]
    return ScenarioGroundTruth(
        name="public_bucket",
        scan=scan,
        entry_points=["aws:internet"],
        targets=["aws:s3/leaky-bucket"],
        expected_path_keys={("aws:internet", "aws:s3/leaky-bucket", 1)},
        expected_finding_categories={"public_s3_bucket"},
        expected_mitre_techniques={"T1190", "T1133", "T1530"},
    )


def scenario_4_open_security_group() -> ScenarioGroundTruth:
    scan = ScanResult(account_id=ACCOUNT, provider="aws")
    scan.assets = [
        Asset(
            id="aws:sg/db-sg",
            type=NodeType.SECURITY_GROUP,
            account_id=ACCOUNT,
            name="db-sg",
            raw_metadata={
                "ip_permissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            },
        )
    ]
    return ScenarioGroundTruth(
        name="open_security_group",
        scan=scan,
        entry_points=["aws:internet"],
        targets=[],  # this scenario is about the FINDING, not a path
        expected_path_keys=set(),
        expected_finding_categories={"open_security_group"},
        expected_mitre_techniques=set(),
    )


ALL_SCENARIOS: list[ScenarioGroundTruth] = [
    scenario_1_public_ec2_to_s3,
    scenario_2_pass_role_escalation,
    scenario_3_public_bucket,
    scenario_4_open_security_group,
]
