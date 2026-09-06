"""
Core graph data model shared by every engine module and every provider.

This is intentionally provider-agnostic (Section 24 of ARCHITECTURE.md):
AWSProvider (and later Azure/GCP) must only ever produce Asset / Relationship
objects defined here. No engine module should import anything AWS-specific.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"
    POLICY = "POLICY"
    EC2 = "EC2"
    S3 = "S3"
    LAMBDA = "LAMBDA"
    RDS = "RDS"
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    SECRET = "SECRET"
    KMS_KEY = "KMS_KEY"
    INTERNET = "INTERNET"
    ACCOUNT = "ACCOUNT"


class EdgeType(str, Enum):
    CAN_ASSUME = "CAN_ASSUME"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_DELETE = "CAN_DELETE"
    TRUSTS = "TRUSTS"
    RUNS_AS = "RUNS_AS"
    CONNECTED_TO = "CONNECTED_TO"
    EXPOSED_TO = "EXPOSED_TO"
    CONTAINS = "CONTAINS"
    USES = "USES"
    ENCRYPTED_BY = "ENCRYPTED_BY"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"


class Asset(BaseModel):
    """A single normalized cloud resource, regardless of provider."""

    id: str  # stable, provider-qualified id, e.g. "aws:iam:role/WebServerRole"
    type: NodeType
    provider: str = "aws"
    account_id: str
    region: Optional[str] = None
    arn: Optional[str] = None
    name: str
    tags: dict[str, str] = Field(default_factory=dict)
    public: bool = False
    sensitivity: Optional[str] = None  # "low" | "medium" | "high" | None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Relationship(BaseModel):
    """A directed, evidenced edge between two assets."""

    source_id: str
    target_id: str
    type: EdgeType
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0  # 0.0 - 1.0, see ARCHITECTURE.md Section 11

    def key(self) -> tuple[str, str, str]:
        """Dedup key so the same evidenced edge isn't added twice."""
        return (self.source_id, self.target_id, self.type.value)


class ScanResult(BaseModel):
    """Everything a single provider scan produces, before graph assembly."""

    account_id: str
    provider: str
    assets: list[Asset] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
