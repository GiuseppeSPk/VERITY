"""SQLAlchemy database models.

Defines all database tables for VERITY.
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from verity.api.database import Base


def generate_uuid() -> str:
    """Generate short UUID for IDs."""
    return str(uuid4())[:8]


class User(Base):
    """User account model."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # User tier
    tier: Mapped[str] = mapped_column(String(50), default="standard")

    # Usage tracking
    attacks_this_month: Mapped[int] = mapped_column(Integer, default=0)
    attacks_limit: Mapped[int] = mapped_column(Integer, default=100)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    campaigns: Mapped[list["Campaign"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class APIKey(Base):
    """API key for programmatic access."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)

    # Status and expiration
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")


class Campaign(Base):
    """Security assessment campaign."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_provider: Mapped[str] = mapped_column(String(50), nullable=False)
    target_model: Mapped[str] = mapped_column(String(100), nullable=False)

    # Configuration
    attack_types: Mapped[str] = mapped_column(Text, default="injection,jailbreak,leak")  # CSV
    max_attacks_per_type: Mapped[int] = mapped_column(Integer, default=5)

    # Status: pending, running, completed, failed
    status: Mapped[str] = mapped_column(String(20), default="pending")

    # Results
    total_attacks: Mapped[int] = mapped_column(Integer, default=0)
    successful_attacks: Mapped[int] = mapped_column(Integer, default=0)
    asr: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_harm_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="campaigns")
    attack_results: Mapped[list["AttackResult"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class AttackResult(Base):
    """Individual attack result."""

    __tablename__ = "attack_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)

    attack_name: Mapped[str] = mapped_column(String(255), nullable=False)
    attack_category: Mapped[str] = mapped_column(String(50), nullable=False)

    # Attack data
    prompt_used: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=False)

    # Judge evaluation (if used)
    verdict: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # safe/unsafe/borderline
    harm_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Metadata
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="attack_results")


class Report(Base):
    """Generated security report."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)

    # Report format: markdown, json, html
    format: Mapped[str] = mapped_column(String(20), nullable=False)

    # Storage - could be S3 path or inline content
    content: Mapped[str] = mapped_column(Text, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Metadata
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="reports")
