"""ORM models.

Raw ``.eml`` files and attachment bytes are never stored in the database, only their path
in the blob store and their SHA-256 (see app.storage).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Deterministic constraint names. Without them PostgreSQL picks its own, and later Alembic
# migrations that drop or rename a constraint cannot refer to it reliably.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# JSONB on PostgreSQL (indexable, compact); plain JSON elsewhere (SQLite in unit tests).
JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class ReportSource(StrEnum):
    IMAP = "imap"
    UPLOAD = "upload"
    API = "api"


class ReportStatus(StrEnum):
    QUEUED = "queued"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LOW_RISK = "low_risk"
    NO_ISSUES = "no_issues"


class ObservableType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    SHA256 = "sha256"


def _enum(enum: type[StrEnum], name: str) -> Enum:
    # Stored as VARCHAR + CHECK constraint rather than a native PostgreSQL ENUM type:
    # adding a value later is then an ordinary migration, not an ALTER TYPE dance.
    return Enum(
        enum,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=16,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


class Report(Base):
    """One reported email. A submission carrying several originals becomes several
    reports; the extra ones point to the first through ``parent_id``."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[ReportSource] = mapped_column(_enum(ReportSource, "report_source"))
    reporter_email: Mapped[str | None] = mapped_column(String(320), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    status: Mapped[ReportStatus] = mapped_column(
        _enum(ReportStatus, "report_status"), default=ReportStatus.QUEUED, index=True
    )
    intake_mode: Mapped[str | None] = mapped_column(String(16))
    score: Mapped[int | None] = mapped_column(Integer)
    verdict: Mapped[Verdict | None] = mapped_column(_enum(Verdict, "verdict"), index=True)
    analyst_verdict: Mapped[Verdict | None] = mapped_column(_enum(Verdict, "analyst_verdict"))
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    # The message as it was submitted (for IMAP: the reporter's wrapper message).
    submission_path: Mapped[str | None] = mapped_column(String(255))
    submission_sha256: Mapped[str] = mapped_column(String(64), index=True)
    submission_size: Mapped[int] = mapped_column(Integer)
    outer_message_id: Mapped[str | None] = mapped_column(String(998), index=True)

    email: Mapped[Email | None] = relationship(
        back_populates="report", cascade="all, delete-orphan", uselist=False
    )
    attachments: Mapped[list[Attachment]] = relationship(
        back_populates="report", cascade="all, delete-orphan", order_by="Attachment.filename"
    )
    observables: Mapped[list[Observable]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )
    children: Mapped[list[Report]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def final_verdict(self) -> Verdict | None:
        """The analyst's verdict when there is one, else the automatic one."""
        return self.analyst_verdict or self.verdict


class Email(Base):
    """The reported (original) email, one per report."""

    __tablename__ = "emails"

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True
    )
    raw_path: Mapped[str | None] = mapped_column(String(255))
    raw_sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(Integer)
    message_id: Mapped[str | None] = mapped_column(String(998), index=True)
    subject: Mapped[str] = mapped_column(Text, default="")
    from_addr: Mapped[str | None] = mapped_column(String(320), index=True)
    from_display: Mapped[str | None] = mapped_column(Text)
    reply_to: Mapped[str | None] = mapped_column(Text)
    return_path: Mapped[str | None] = mapped_column(String(998))
    to_addrs: Mapped[list[str]] = mapped_column(JSONType, default=list)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    headers: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    auth_results: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    received_hops: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    body_text: Mapped[str] = mapped_column(Text, default="")
    body_html_clean: Mapped[str | None] = mapped_column(Text)
    forwarded_inline: Mapped[bool] = mapped_column(Boolean, default=False)
    defects: Mapped[list[str]] = mapped_column(JSONType, default=list)

    report: Mapped[Report] = relationship(back_populates="email")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))  # display only, never a path
    declared_type: Mapped[str] = mapped_column(String(255))
    detected_type: Mapped[str | None] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    has_macros: Mapped[bool | None] = mapped_column(Boolean)
    is_encrypted: Mapped[bool | None] = mapped_column(Boolean)
    storage_path: Mapped[str | None] = mapped_column(String(255))

    report: Mapped[Report] = relationship(back_populates="attachments")


class Observable(Base):
    """An IOC seen in a report; unique per (report, type, value)."""

    __tablename__ = "observables"
    __table_args__ = (
        UniqueConstraint("report_id", "type", "value"),
        Index("ix_observables_type_value", "type", "value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[ObservableType] = mapped_column(_enum(ObservableType, "observable_type"))
    value: Mapped[str] = mapped_column(String(2048))
    defanged: Mapped[str] = mapped_column(String(4096))

    report: Mapped[Report] = relationship(back_populates="observables")
