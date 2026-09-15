import enum
from datetime import datetime
from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text, Enum, ForeignKey,
    UniqueConstraint, Index, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base, JSONBType


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(512))
    pcap_path: Mapped[str] = mapped_column(String(1024))
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.PENDING)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    message: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    org_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("organizations.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    sessions: Mapped[list["Session"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    summary: Mapped[list["SessionSummary"]] = relationship(back_populates="job", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64), ForeignKey("analysis_jobs.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    five_tuple: Mapped[str] = mapped_column(String(512))
    src_ip: Mapped[str] = mapped_column(String(64))
    dst_ip: Mapped[str] = mapped_column(String(64))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    is_starttls: Mapped[bool] = mapped_column(Boolean, default=False)
    transition_offset: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    negotiated_cipher: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cipher_strength: Mapped[float | None] = mapped_column(Float, nullable=True)
    key_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pfs_supported: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    cert_chain_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    cert_age_days: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    org_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("organizations.id"), nullable=True, index=True)
    details: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)

    job: Mapped[AnalysisJob] = relationship(back_populates="sessions")
    findings: Mapped[list["Finding"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    shaps: Mapped[list["ShaPRow"]] = relationship(back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_session_job", "job_id"),)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), ForeignKey("sessions.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(128))
    rule_name: Mapped[str] = mapped_column(String(256))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    reference: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(32), default="rule")  # rule | ml | anomaly
    source: Mapped[str] = mapped_column(String(32), default="rules-engine")
    evidence: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)

    session: Mapped[Session] = relationship(back_populates="findings")


class ShaPRow(Base):
    __tablename__ = "shap_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), ForeignKey("sessions.id"), index=True)
    feature: Mapped[str] = mapped_column(String(128))
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    impact: Mapped[float] = mapped_column(Float)
    method: Mapped[str] = mapped_column(String(32), default="score")

    session: Mapped[Session] = relationship(back_populates="shaps")


class SessionSummary(Base):
    __tablename__ = "session_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), ForeignKey("analysis_jobs.id"), index=True)
    key: Mapped[str] = mapped_column(String(128))
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    string_value: Mapped[str | None] = mapped_column(String(512), nullable=True)

    job: Mapped[AnalysisJob] = relationship(back_populates="summary")


# ---------------------------------------------------------------------------
# Track 1: multi-tenancy + auth. org_id is nullable for backward compat with
# rows created before auth existed; all new writes set it. Queries filter by
# the caller's org, so true multi-tenancy is a policy change, not a migration.
# ---------------------------------------------------------------------------

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="org")


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    org: Mapped[Organization] = relationship(back_populates="users")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class TrackedCert(Base):
    """Persistent certificate inventory, independent of sessions.

    One row per observed leaf certificate (keyed by SHA-256 fingerprint).
    Powers proactive expiry forecasting: alert N days *before* expiry,
    not just when an already-expired cert is observed on the wire.
    """
    __tablename__ = "tracked_certs"

    fingerprint: Mapped[str] = mapped_column(String(128), primary_key=True)
    org_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("organizations.id"), nullable=True, index=True)
    subject_cn: Mapped[str] = mapped_column(String(512), default="")
    issuer_cn: Mapped[str] = mapped_column(String(512), default="")
    sans: Mapped[list | None] = mapped_column(JSONBType, nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    pubkey_alg: Mapped[str] = mapped_column(String(64), default="")
    pubkey_bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature_alg: Mapped[str] = mapped_column(String(128), default="")
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_result: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    expiry_alerted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (Index("ix_trackedcert_org_notafter", "org_id", "not_after"),)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(256))  # email or "api-key:<prefix>"
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource: Mapped[str] = mapped_column(String(512), default="")
    detail: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
