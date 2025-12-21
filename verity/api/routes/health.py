"""Health check endpoints."""

from fastapi import APIRouter

from VERITY import __version__

router = APIRouter()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": __version__,
    }


@router.get("/ready")
async def readiness_check():
    """Readiness check for Kubernetes."""
    # TODO: Check database connection, LLM provider availability
    return {
        "status": "ready",
        "checks": {
            "database": "ok",  # TODO: Implement
            "providers": "ok",  # TODO: Implement
        },
    }
