"""Auth service: register, login, get_current_user."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.models import Business, User, UserRole
from app.schemas.schemas import RegisterRequest

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised for all auth-related business errors."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


def register_user(req: RegisterRequest, db: Session) -> User:
    """Create a new user + business. Raises AuthError on conflict."""
    existing = db.query(User).filter(User.email == req.email.lower()).first()
    if existing:
        raise AuthError("EMAIL_TAKEN", "An account with that email already exists.", 409)

    business = Business(name=req.business_name)
    db.add(business)
    db.flush()  # get business.id

    user = User(
        email=req.email.lower(),
        password_hash=hash_password(req.password),
        role=req.role,
        business_id=business.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info("User registered: %s", user.id)
    return user


def login_user(email: str, password: str, db: Session) -> tuple[User, str, str]:
    """
    Authenticate user. Returns (user, access_token, refresh_token).
    Raises AuthError on failure.
    """
    user = db.query(User).filter(User.email == email.lower()).first()

    # Always run verify to prevent timing attacks
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"
    candidate_hash = user.password_hash if user else dummy_hash
    ok = verify_password(password, candidate_hash)

    if not user or not ok:
        raise AuthError("INVALID_CREDENTIALS", "Email or password is incorrect.", 401)

    if not user.is_active:
        raise AuthError("ACCOUNT_DISABLED", "This account has been disabled.", 403)

    # Opportunistic rehash if Argon2 params changed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()

    payload = {"sub": user.id, "email": user.email}
    access_token = create_access_token(payload)
    refresh_token = create_refresh_token(payload)
    return user, access_token, refresh_token


def get_current_user(token: str, db: Session) -> User:
    """Validate JWT access token and return the User. Raises AuthError."""
    try:
        payload = decode_token(token)
    except JWTError as exc:
        raise AuthError("INVALID_TOKEN", "Authentication token is invalid or expired.", 401) from exc

    if payload.get("type") != "access":
        raise AuthError("INVALID_TOKEN", "Not an access token.", 401)

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise AuthError("INVALID_TOKEN", "Token payload missing subject.", 401)

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise AuthError("USER_NOT_FOUND", "User not found.", 401)
    return user
