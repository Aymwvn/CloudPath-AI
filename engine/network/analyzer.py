"""
Network analyzer. Flags overly-broad security group rules, determines
real S3 bucket public-ness, and (new) derives CONNECTED_TO edges from
security-group-to-security-group reachability rules — e.g. a DB
security group that allows inbound from a web security group means any
resource using the web SG can reach any resource using the DB SG.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from engine.iam import policy_eval
from engine.models import Asset, EdgeType, NodeType, Relationship

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
    category: str
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

        relationships.extend(self._derive_sg_to_sg_connectivity(assets))

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

    # ------------------------------------------------------------------
    # New: security-group-to-security-group reachability correlation.
    #
    # An SG rule can reference another SG as its source (UserIdGroupPairs)
    # instead of a CIDR — this is the mechanism AWS itself uses to express
    # "anything in the web tier can reach the db tier." Previously this
    # platform only flagged CIDR-based 0.0.0.0/0 exposure; it never
    # derived a CONNECTED_TO edge for SG-to-SG rules, so a resource behind
    # a "safe-looking" SG (no public CIDR at all) that's actually reachable
    # from another resource via an SG-to-SG rule was invisible to the
    # attack path engine. This closes that gap.
    # ------------------------------------------------------------------
    def _derive_sg_to_sg_connectivity(self, assets: list[Asset]) -> list[Relationship]:
        relationships: list[Relationship] = []

        # Map security_group_id -> list of asset ids that USE it. Read
        # directly from each resource's raw_metadata rather than
        # requiring the caller to also pass in structural relationships —
        # keeps this analyzer's interface (just `assets`) unchanged.
        sg_to_resources: dict[str, list[str]] = {}
        for asset in assets:
            sg_ids: list[str] = []
            if asset.type == NodeType.EC2:
                sg_ids = asset.raw_metadata.get("security_groups", [])
            elif asset.type == NodeType.RDS:
                sg_ids = asset.raw_metadata.get("vpc_security_groups", [])
            elif asset.type == NodeType.LAMBDA:
                sg_ids = asset.raw_metadata.get("security_groups", [])
            for sg_id in sg_ids:
                sg_to_resources.setdefault(sg_id, []).append(asset.id)

        for asset in assets:
            if asset.type != NodeType.SECURITY_GROUP:
                continue
            target_sg_id = self._extract_sg_id(asset)

            for perm in asset.raw_metadata.get("ip_permissions", []):
                for pair in perm.get("UserIdGroupPairs", []):
                    source_sg_id = pair.get("GroupId")
                    if not source_sg_id:
                        continue

                    source_resources = sg_to_resources.get(source_sg_id, [])
                    target_resources = sg_to_resources.get(target_sg_id, [])
                    confidence = self._egress_confidence(assets, source_sg_id, target_sg_id, perm)

                    for source_resource_id in source_resources:
                        for target_resource_id in target_resources:
                            if source_resource_id == target_resource_id:
                                continue
                            relationships.append(
                                Relationship(
                                    source_id=source_resource_id,
                                    target_id=target_resource_id,
                                    type=EdgeType.CONNECTED_TO,
                                    evidence={
                                        "via_security_group": target_sg_id,
                                        "allowed_from_security_group": source_sg_id,
                                        "protocol": perm.get("IpProtocol"),
                                        "from_port": perm.get("FromPort"),
                                        "to_port": perm.get("ToPort"),
                                    },
                                    confidence=confidence,
                                )
                            )

        return relationships

    def _egress_confidence(self, assets: list[Asset], source_sg_id: str, target_sg_id: str, ingress_perm: dict) -> float:
        """The target's ingress rule allowing the source SG is only half
        the reachability story — the SOURCE's own egress rules have to
        actually permit traffic out too. AWS default behavior: a freshly
        created security group has no egress RESTRICTIONS configured
        (an implicit/explicit allow-all-outbound rule), so an empty or
        allow-all egress list means unrestricted (confidence 1.0, same as
        before this change). If the source SG has been given explicit,
        narrower egress rules, only full confidence when one of them
        actually covers this destination — otherwise the target is still
        listed (we don't silently drop real evidence), but at reduced
        confidence, since the egress restriction makes the path
        genuinely uncertain rather than disproven outright."""
        source_sg_asset = next(
            (a for a in assets if a.type == NodeType.SECURITY_GROUP and self._extract_sg_id(a) == source_sg_id), None
        )
        if source_sg_asset is None:
            return 1.0  # source SG's rules aren't visible to us — can't second-guess with no evidence

        egress_rules = source_sg_asset.raw_metadata.get("ip_permissions_egress", [])
        if not egress_rules:
            return 1.0  # no explicit egress restrictions configured — matches AWS's default allow-all-outbound

        for egress_perm in egress_rules:
            if self._is_allow_all_egress(egress_perm):
                return 1.0
            for pair in egress_perm.get("UserIdGroupPairs", []):
                if pair.get("GroupId") == target_sg_id:
                    return 1.0

        # explicit egress rules exist, but none of them appear to permit
        # reaching the target — evidence is genuinely uncertain, not
        # proof of no path (there could be rules/routing we don't model)
        return 0.5

    @staticmethod
    def _is_allow_all_egress(perm: dict) -> bool:
        if perm.get("IpProtocol") == "-1":
            return True
        cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
        return any(c in WIDE_OPEN_CIDRS for c in cidrs if c)

    @staticmethod
    def _extract_sg_id(sg_asset: Asset) -> str:
        # Asset.id is formatted "aws:sg/{GroupId}" by AWSProvider — pull
        # the raw GroupId back out since UserIdGroupPairs reference the
        # raw AWS id, not our internal asset id format.
        return sg_asset.id.split("/", 1)[-1]
