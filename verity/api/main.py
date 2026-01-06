"""FastAPI main application.

VERITY REST API
- OAuth2 + JWT authentication
- API key authentication for programmatic access
- Rate limiting
- CORS configuration
"""

import traceback
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from verity import __version__
from verity.api.routes import attacks, auth, campaigns, health, reports
from verity.config.logging import get_logger, setup_logging
from verity.config.settings import get_settings

# Initialize settings and logging
settings = get_settings()
logger = setup_logging(level=settings.log_level)
api_logger = get_logger("api")


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    api_logger.info(f"VERITY API v{__version__} starting...")
    api_logger.info(f"Debug mode: {settings.debug}")
    api_logger.info(f"CORS origins: {settings.cors_origins}")
    yield
    # Shutdown
    api_logger.info("VERITY API shutting down...")


# Create FastAPI application
app = FastAPI(
    title="VERITY API",
    description="Verification of Ethics, Resilience & Integrity for Trusted AI - LLM Red Teaming API",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# CORS Configuration - loaded from settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(campaigns.router, prefix="/api/v1/campaigns", tags=["Campaigns"])
app.include_router(attacks.router, prefix="/api/v1/attacks", tags=["Attacks"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions."""
    api_logger.error(f"Unhandled exception: {exc}", exc_info=settings.debug)

    response_content = {
        "error": "internal_server_error",
        "message": "An unexpected error occurred",
        "timestamp": datetime.now(UTC).isoformat(),
    }

    # Include stack trace in debug mode
    if settings.debug:
        response_content["detail"] = str(exc)
        response_content["traceback"] = traceback.format_exc()

    return JSONResponse(status_code=500, content=response_content)


# Root endpoint
@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": "VERITY API",
        "version": __version__,
        "status": "operational",
        "docs": "/docs",
    }

