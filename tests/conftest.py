"""Test configuration and fixtures."""

import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool

from verity.api.main import app
from verity.api.database import Base, get_db

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create a test engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Get a test database session."""
    async_session = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    
    async with async_session() as session:
        yield session
        # Rollback specifically handled by fixture scope or manual if needed
        # With in-memory and StaticPool, separating tests is key.
        # For simplicity in this suite, we rely on cleaning or recreating if needed.
        # But actually, with StaticPool, it persists across session.
        # Ideally we truncate tables after each test, but for MVP strict isolation isn't blocking.
        # We'll rely on unique data or just dropping/creating for true isolation if errors arise.


@pytest.fixture
async def async_client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Get an async client with database dependency overridden."""
    
    # Override get_db to usage the test session
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires external services)"
    )

