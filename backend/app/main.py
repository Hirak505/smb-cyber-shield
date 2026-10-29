"""ShieldDesk FastAPI application factory."""
from __future__ import annotations

import logging
import time

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import auth, scan, playbooks, assessment, actions
from app.core.config import get_settings
from app.core.database import Base, engine
from app.services.kb_loader import kb

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    log.info("Creating database tables…")
    Base.metadata.create_all(bind=engine)
    log.info("Loading knowledge base…")
    prod_mode = settings.APP_ENV == "prod"
    kb.load(prod_mode=prod_mode)
    log.info("ShieldDesk API ready (env=%s)", settings.APP_ENV)
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="ShieldDesk API",
        description=(
            "Affordable cybersecurity for small businesses. "
            "Message scanning, incident playbooks, health checks."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_ORIGIN],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Security headers middleware
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if settings.APP_ENV != "dev":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    # ------------------------------------------------------------------
    # Request timing middleware (dev only)
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def add_timing(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        response.headers["X-Response-Time-Ms"] = str(elapsed)
        return response

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(scan.router, prefix="/api/v1")
    app.include_router(playbooks.router, prefix="/api/v1")
    app.include_router(assessment.router, prefix="/api/v1")
    app.include_router(actions.router, prefix="/api/v1")

    # ------------------------------------------------------------------
    # Health endpoint
    # ------------------------------------------------------------------
    @app.get("/health", tags=["meta"])
    def health():
        return {
            "status": "ok",
            "version": "0.1.0",
            "env": settings.APP_ENV,
        }

    # ------------------------------------------------------------------
    # Custom exception handlers – always return API error envelope
    # ------------------------------------------------------------------
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            content = exc.detail
        else:
            content = {"error": {"code": f"HTTP_{exc.status_code}", "message": str(exc.detail)}}
        return JSONResponse(status_code=exc.status_code, content=content)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "VALIDATION_ERROR", "message": str(exc)}},
        )

    @app.exception_handler(Exception)
    async def global_exc_handler(request: Request, exc: Exception):
        log.exception("Unhandled exception on %s %s", request.method, request.url)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred."}},
        )

    return app


app = create_app()
