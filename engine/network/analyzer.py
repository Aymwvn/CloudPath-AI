"""
Phase 4 — Network analyzer.

Consumes normalized Asset objects (security groups, S3 buckets, EC2) and:
  1. Flags overly-broad security group rules (0.0.0.0/0 on sensitive ports).
  2. Determines TRUE S3 bucket public-ness by actually parsing the bucket
     policy document (not just the coarse PublicAccessBlock flag set by
     AWSProvider in Phase 1 — that flag is a fast pre-filter, this module
     does the real determination).
  3. Emits EXPOSED_TO relationships from Internet to anything it confirms
     is genuinely reachable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from engine.iam import policy_eval
from engine.models import Asset, EdgeType, NodeType, Relationship

# Ports worth calling out specifically when open to 0.0.0.0/0 — this is a
# starting set, not exhaustive; anything not in here still gets flagged at
# "medium" if it's a wide-open rule, just without the specific port callout.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    27017: "MongoDB",
    9200: "Elasticsearch",
    6379: "Redis",
}

WIDE_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass
class NetworkFinding:
    asset_id: str
    category: str  # "open_security_group" | "public_s3_bucket"
    severity: str
    detail: str
    evidence: dict = field(default_factory=dict)


class NetworkAnalyzer:
    def analyze(self, assets: list[Asset]) -> tuple[list[NetworkFinding], list[Relationship]]:
        findings: list[NetworkFinding] = []
        relationships: list[Relationship] = []

        for asset in assets:
            if asset.type == NodeType.SECURITY_GROUP:
                findings.extend(self._analyze_security_group(asset))
            elif asset.type == NodeType.S3:
                f, r = self._analyze_s3_bucket(asset)
                findings.extend(f)
                relationships.extend(r)

        return findings, relationships

    def _analyze_security_group(self, asset: Asset) -> list[NetworkFinding]:
        findings: list[NetworkFinding] = []
        for perm in asset.raw_metadata.get("ip_permissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [
                r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])
            ]
            if not any(c in WIDE_OPEN_CIDRS for c in cidrs if c):
                continue

            if from_port in SENSITIVE_PORTS:
                findings.append(
                    NetworkFinding(
                        asset_id=asset.id,
                        category="open_security_group",
                        severity="critical",
                        detail=(
                            f"Security group '{asset.name}' allows {SENSITIVE_PORTS[from_port]} "
                            f"(port {from_port}) from 0.0.0.0/0."
                        ),
                        evidence={"from_port": from_port, "to_port": to_port},
                    )
                )
            elif from_port is None and to_port is None:
                # all-traffic / all-ports rule (e.g. -1 protocol)
                findings.append(
                    NetworkFinding(
                        asset_id=asset.id,
                        category="open_security_group",
                        severity="critical",
                        detail=f"Security group '{asset.name}' allows ALL traffic from 0.0.0.0/0.",
                        evidence={"protocol": perm.get("IpProtocol")},
                    )
                )
            else:
                findings.append(
                    NetworkFinding(
                        asset_id=asset.id,
                        category="open_security_group",
                        severity="medium",
                        detail=(
                            f"Security group '{asset.name}' allows port {from_port}-{to_port} "
                            "from 0.0.0.0/0."
                        ),
                        evidence={"from_port": from_port, "to_port": to_port},
                    )
                )
        return findings

    def _analyze_s3_bucket(self, asset: Asset) -> tuple[list[NetworkFinding], list[Relationship]]:
        findings: list[NetworkFinding] = []
        relationships: list[Relationship] = []

        pab = asset.raw_metadata.get("public_access_block") or {}
        block_all = all(
            pab.get(k, False)
            for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
        )
        if block_all:
            # public access block fully enabled — bucket policy can't make it
            # public regardless of what the policy document says.
            return findings, relationships

        policy_raw = asset.raw_metadata.get("policy")
        is_public = False
        evidence: dict = {}

        if policy_raw:
            document = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
            for statement in policy_eval.parse_statements(document):
                if statement.effect.value != "Allow":
                    continue
                principal = statement.raw.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    is_public = True
                    evidence = {"statement": statement.raw}
                    break

        acl = asset.raw_metadata.get("acl") or {}
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                is_public = True
                evidence = {"acl_grant": grant}
                break

        if is_public:
            findings.append(
                NetworkFinding(
                    asset_id=asset.id,
                    category="public_s3_bucket",
                    severity="critical",
                    detail=f"S3 bucket '{asset.name}' is publicly accessible (policy or ACL grants public access).",
                    evidence=evidence,
                )
            )
            relationships.append(
                Relationship(
                    source_id="aws:internet",
                    target_id=asset.id,
                    type=EdgeType.EXPOSED_TO,
                    evidence=evidence,
                )
            )

        return findings, relationships
