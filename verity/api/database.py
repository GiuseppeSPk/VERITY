"""Database configuration and session management.

SQLAlchemy 2.0 async with asyncpg for PostgreSQL.
Following SOTA 2025 best practices:
- create_async_engine for async operations
- AsyncSession with expire_on_commit=False
- Connection pooling configuration
- FastAPI dependency injection pattern
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from verity.config import get_settings

# Get settings
settings = get_settings()


# Database URL - async version
# Format: postgresql+asyncpg://user:password@host:port/dbname
DATABASE_URL = getattr(settings, "database_url", None) or "sqlite+aiosqlite:///./VERITY.db"

# For async PostgreSQL, convert standard URL
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")


# Create async engine with connection pooling
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL logging in dev
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=1800,  # Recycle connections after 30 min
)


# Session factory with SOTA recommended settings
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Prevent lazy loads after commit
    autoflush=False,
)


# Base class for all models
class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield database session for FastAPI dependency injection.

    Usage:
        @router.get("/")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


# Context manager for non-request usage
@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Get database session as context manager.

    Usage:
        async with get_db_context() as db:
            ...
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Initialize database (create tables)
async def init_db() -> None:
    """Create all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Close database connections
async def close_db() -> None:
    """Close database engine and connections."""
    await engine.dispose()
