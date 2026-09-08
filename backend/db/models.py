"""
Phase 9 — SQLAlchemy models.

MVP subset of the full schema in ARCHITECTURE.md Section 16. Tables not
yet needed by anything the engine produces (iam_policies, network_rules
as first-class tables, mitre_techniques, remediation, audit_logs,
analyst_feedback) are deferred — findings/relationships/attack paths
already carry their evidence as JSON, which covers the MVP's needs
without those tables existing yet. Extending this file additively when
those phases land is the intended path, not a rewrite.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Boolean,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CloudAccountModel(Base):
    __tablename__ = "cloud_accounts"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False, default="aws")
    external_account_id = Column(String, nullable=False)
    region = Column(String, nullable=False, default="us-east-1")
    created_at = Column(DateTime, default=_now)


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=_uuid)
    account_external_id = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")  # pending | running | completed | failed
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    asset_count = Column(Integer, default=0)
    relationship_count = Column(Integer, default=0)

    assets = relationship("AssetModel", back_populates="scan_job", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="scan_job", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPathModel", back_populates="scan_job", cascade="all, delete-orphan")


class AssetModel(Base):
    __tablename__ = "assets"

    # NOTE: `id` here is a per-row synthetic PK, NOT the same thing as
    # Asset.id from engine/models.py (e.g. "aws:internet") — that natural
    # id repeats across every scan (every account has an "aws:internet"
    # node), so it can't be a global primary key. It's stored in
    # `asset_id` instead, unique only within a given scan_job.
    pk = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, nullable=False)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    type = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    region = Column(String, nullable=True)
    arn = Column(String, nullable=True)
    name = Column(String, nullable=False)
    tags = Column(JSON, default=dict)
    public = Column(Boolean, default=False)
    sensitivity = Column(String, nullable=True)
    raw_metadata = Column(JSON, default=dict)
    updated_at = Column(DateTime, default=_now)

    scan_job = relationship("ScanJobModel", back_populates="assets")


class RelationshipModel(Base):
    __tablename__ = "relationships"

    id = Column(String, primary_key=True, default=_uuid)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    source_id = Column(String, nullable=False)
    target_id = Column(String, nullable=False)
    type = Column(String, nullable=False)
    evidence = Column(JSON, default=dict)
    confidence = Column(Float, default=1.0)


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    asset_id = Column(String, nullable=False)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    detail = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)

    scan_job = relationship("ScanJobModel", back_populates="findings")


class AttackPathModel(Base):
    __tablename__ = "attack_paths"

    id = Column(String, primary_key=True, default=_uuid)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    entry_asset_id = Column(String, nullable=False)
    target_asset_id = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String, nullable=False)  # "path" | "potential_path"

    scan_job = relationship("ScanJobModel", back_populates="attack_paths")
    steps = relationship("AttackPathStepModel", back_populates="attack_path", cascade="all, delete-orphan")
    ai_analysis = relationship("AIAnalysisModel", back_populates="attack_path", uselist=False)


class AttackPathStepModel(Base):
    __tablename__ = "attack_path_steps"

    id = Column(String, primary_key=True, default=_uuid)
    attack_path_id = Column(String, ForeignKey("attack_paths.id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    source_id = Column(String, nullable=False)
    target_id = Column(String, nullable=False)
    edge_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    evidence = Column(JSON, default=dict)

    attack_path = relationship("AttackPathModel", back_populates="steps")


class AIAnalysisModel(Base):
    """Phase 12 output storage — the evidence-first AI explanation JSON."""

    __tablename__ = "ai_analysis"

    id = Column(String, primary_key=True, default=_uuid)
    attack_path_id = Column(String, ForeignKey("attack_paths.id"), nullable=False, unique=True)
    summary_json = Column(JSON, nullable=False)
    model_used = Column(String, nullable=False)
    created_at = Column(DateTime, default=_now)

    attack_path = relationship("AttackPathModel", back_populates="ai_analysis")


class CrownJewelModel(Base):
    __tablename__ = "crown_jewels"

    id = Column(String, primary_key=True, default=_uuid)
    account_external_id = Column(String, nullable=False)
    asset_id = Column(String, nullable=False)
    label = Column(String, nullable=False)


class MitreTechniqueModel(Base):
    """Phase 14 — deterministic MITRE ATT&CK mappings for an attack path."""

    __tablename__ = "mitre_techniques"

    id = Column(String, primary_key=True, default=_uuid)
    attack_path_id = Column(String, ForeignKey("attack_paths.id"), nullable=False)
    technique_id = Column(String, nullable=False)
    technique_name = Column(String, nullable=False)
    evidence = Column(JSON, default=dict)
    confidence = Column(Float, default=1.0)
