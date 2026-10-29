"""Test authentication endpoints and service."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.core.rate_limit import auth_limiter, scan_limiter
from app.core.security import hash_password, verify_password, create_access_token, decode_token
from app.main import create_app
from app.models.models import Business, User


# ---------------------------------------------------------------------------
# Test DB + app fixtures
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite:///./test_shielddesk.db"

@pytest.fixture(autouse=True)
def reset_limiters():
    auth_limiter.clear()
    scan_limiter.clear()

@pytest.fixture(scope="session")
def engine():
    eng = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)


@pytest.fixture()
def db(engine):
    TestSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestSession()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def client(engine):
    TestSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_get_db():
        s = TestSession()
        try:
            yield s
        finally:
            s.rollback()
            s.close()

    from app.services.kb_loader import kb
    kb.load(prod_mode=False)

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Security unit tests
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "SecurePass1"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct-horse-battery1")
        assert not verify_password("wrong-password", hashed)

    def test_hash_is_not_plaintext(self):
        pw = "MySecret123"
        hashed = hash_password(pw)
        assert pw not in hashed

    def test_two_hashes_differ(self):
        pw = "SamePassword1"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2   # Argon2 uses random salt


class TestJWT:
    def test_access_token_round_trip(self):
        token = create_access_token({"sub": "user-123", "email": "a@b.com"})
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"

    def test_tampered_token_rejected(self):
        from jose import JWTError
        token = create_access_token({"sub": "user-123"})
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)


# ---------------------------------------------------------------------------
# Registration endpoint tests
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_success(self, client):
        resp = client.post("/api/v1/auth/register", json={
            "email": "owner@example.com",
            "password": "Password123",
            "business_name": "Acme Ltd",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "owner@example.com"
        assert data["role"] == "owner"
        assert "id" in data
        assert "password_hash" not in data

    def test_register_duplicate_email(self, client):
        payload = {
            "email": "dup@example.com",
            "password": "Password123",
            "business_name": "Corp",
        }
        client.post("/api/v1/auth/register", json=payload)
        resp = client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "EMAIL_TAKEN"

    def test_register_weak_password_no_digit(self, client):
        resp = client.post("/api/v1/auth/register", json={
            "email": "weak@example.com",
            "password": "onlyletters",
            "business_name": "Test",
        })
        assert resp.status_code == 422

    def test_register_weak_password_too_short(self, client):
        resp = client.post("/api/v1/auth/register", json={
            "email": "short@example.com",
            "password": "Ab1",
            "business_name": "Test",
        })
        assert resp.status_code == 422

    def test_register_invalid_email(self, client):
        resp = client.post("/api/v1/auth/register", json={
            "email": "not-an-email",
            "password": "Password123",
            "business_name": "Test",
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Login endpoint tests
# ---------------------------------------------------------------------------

class TestLogin:
    def _register(self, client, email="login@example.com"):
        client.post("/api/v1/auth/register", json={
            "email": email,
            "password": "Password123",
            "business_name": "Login Corp",
        })

    def test_login_success(self, client):
        self._register(client, "login2@example.com")
        resp = client.post("/api/v1/auth/login", json={
            "email": "login2@example.com",
            "password": "Password123",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self, client):
        self._register(client, "login3@example.com")
        resp = client.post("/api/v1/auth/login", json={
            "email": "login3@example.com",
            "password": "WrongPass123",
        })
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"

    def test_login_unknown_email(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "email": "ghost@example.com",
            "password": "Password123",
        })
        assert resp.status_code == 401

    def test_login_sets_refresh_cookie(self, client):
        self._register(client, "login4@example.com")
        resp = client.post("/api/v1/auth/login", json={
            "email": "login4@example.com",
            "password": "Password123",
        })
        assert resp.status_code == 200
        # TestClient stores cookies
        assert "refresh_token" in client.cookies or resp.headers.get("set-cookie", "")


# ---------------------------------------------------------------------------
# /me endpoint tests
# ---------------------------------------------------------------------------

class TestMe:
    def _register_and_login(self, client, email="me@example.com"):
        client.post("/api/v1/auth/register", json={
            "email": email,
            "password": "Password123",
            "business_name": "Me Corp",
        })
        resp = client.post("/api/v1/auth/login", json={
            "email": email,
            "password": "Password123",
        })
        return resp.json()["access_token"]

    def test_me_with_valid_token(self, client):
        token = self._register_and_login(client, "me2@example.com")
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "me2@example.com"

    def test_me_without_token(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_invalid_token(self, client):
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer garbage.token.here"},
        )
        assert resp.status_code == 401
