"""
FastAPI application entry-point for the HallucinatingCrusaders API.

Responsibilities
----------------
* Wire up all routers (alerts, health, auth).
* Configure CORS middleware for the dashboard frontend.
* Manage the ``AlertCollector`` lifecycle via the ASGI lifespan.
* Add lightweight request-logging middleware.
* Redirect the root URL to ``/docs`` for discoverability.

Run with::

    uvicorn soc_analyst.api.main:app --reload --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends

from soc_analyst.api.auth import Token, login_for_access_token
from soc_analyst.api.routers import alerts as alerts_router
from soc_analyst.api.routers import health as health_router
from soc_analyst.api.routers import analysis as analysis_router
from soc_analyst.api.routers import response as response_router
from soc_analyst.api.routers import dashboard as dashboard_router
from soc_analyst.collector.main import AlertCollector, build_default_collector
from soc_analyst.config import settings

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ASGI Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifecycle.

    * **Startup** -- instantiate and start the ``AlertCollector``.
    * **Shutdown** -- gracefully stop the collector.
    """
    logger.info("Starting HallucinatingCrusaders API v%s ...", settings.version)

    collector = build_default_collector()
    await collector.start()
    app.state.collector = collector
    app.state.pipeline = collector.pipeline

    logger.info("AlertCollector and AnalystPipeline attached to app.state and started.")

    yield  # application is running

    logger.info("Shutting down ...")
    await collector.stop()
    logger.info("AlertCollector stopped. Goodbye.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HallucinatingCrusaders API",
    description=(
        "REST API for the Agentic AI SOC Analyst platform.  "
        "Provides alert management, health monitoring, and authentication."
    ),
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS Middleware
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Dev: allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request-logging middleware
# ---------------------------------------------------------------------------


@app.middleware("http")
async def log_requests(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Log every inbound HTTP request with method, path, and duration."""
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    logger.info(
        "%s %s -> %d (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ---------------------------------------------------------------------------
# Include routers
# ---------------------------------------------------------------------------

app.include_router(alerts_router.router)
app.include_router(health_router.router)
app.include_router(analysis_router.router)
app.include_router(response_router.router)
app.include_router(dashboard_router.router)

# ---------------------------------------------------------------------------
# Auth endpoint (mounted directly, not in a sub-router)
# ---------------------------------------------------------------------------


@app.post(
    "/auth/token",
    response_model=Token,
    tags=["Authentication"],
    summary="Obtain JWT access token",
    description="Submit username and password to receive a Bearer token.",
)
async def token_endpoint(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    """Issue a JWT after validating credentials."""
    return await login_for_access_token(form_data)


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root_redirect(request: Request) -> RedirectResponse:
    """Redirect ``/`` to dashboard/alerts if authenticated, else /login."""
    token = request.cookies.get("access_token")
    if token:
        try:
            from soc_analyst.api.auth import verify_token
            verify_token(token)
            return RedirectResponse(url="/dashboard/alerts")
        except Exception:
            pass
    return RedirectResponse(url="/login")


__all__ = ["app"]
