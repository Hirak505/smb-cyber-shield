"""Auth router: /auth/register, /auth/login, /auth/logout, GET /me."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import auth_limiter
from app.schemas.schemas import (
    ErrorDetail,
    ErrorResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from app.services.auth import AuthError, get_current_user, login_user, register_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")


def _check_auth_rate(request: Request) -> None:
    ip = _client_ip(request)
    if not auth_limiter.is_allowed(ip):
        raise HTTPException(
            status_code=429,
            detail={"error": {"code": "RATE_LIMITED", "message": "Too many requests. Please wait before trying again."}},
        )


@router.post(
    "/register",
    response_model=UserOut,
    status_code=201,
    responses={409: {"model": ErrorResponse}},
)
def register(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserOut:
    _check_auth_rate(request)
    try:
        user = register_user(req, db)
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc
    return UserOut.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse}},
)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    _check_auth_rate(request)
    try:
        user, access_token, refresh_token = login_user(req.email, req.password, db)
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc

    settings = get_settings()
    # Set httpOnly refresh token cookie (security)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/auth",
    )
    return TokenResponse(access_token=access_token)


@router.post("/logout", status_code=204)
def logout(response: Response) -> None:
    response.delete_cookie("refresh_token", path="/auth")


@router.get(
    "/me",
    response_model=UserOut,
    responses={401: {"model": ErrorResponse}},
)
def me(
    request: Request,
    db: Session = Depends(get_db),
) -> UserOut:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "MISSING_TOKEN", "message": "Authorization header required."}},
        )
    try:
        user = get_current_user(token, db)
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc
    return UserOut.model_validate(user)
