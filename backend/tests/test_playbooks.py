"""Tests for the incident playbook engine."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.core.rate_limit import auth_limiter, scan_limiter
from app.main import create_app
from app.services.kb_loader import kb
from app.services.playbooks import (
    PlaybookError,
    create_incident,
    complete_step,
    export_incident,
    get_playbook,
    list_playbooks,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite:///./test_playbooks.db"


@pytest.fixture(autouse=True)
def reset_limiters():
    auth_limiter.clear()
    scan_limiter.clear()


@pytest.fixture(scope="session")
def engine():
    eng = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    kb.load(prod_mode=False)
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

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """Client with a registered+logged-in user; returns (client, token, business_id)."""
    client.post("/api/v1/auth/register", json={
        "email": "playbook_user@example.com",
        "password": "Password123",
        "business_name": "Playbook Corp",
    })
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "playbook_user@example.com",
        "password": "Password123",
    })
    token = login_resp.json()["access_token"]
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    business_id = me_resp.json().get("business_id")
    return client, token, business_id


# ---------------------------------------------------------------------------
# KB Playbook unit tests
# ---------------------------------------------------------------------------

class TestKBPlaybooks:
    def test_three_playbooks_loaded(self):
        playbooks = list_playbooks()
        assert len(playbooks) >= 3

    def test_phishing_playbook_exists(self):
        pb = get_playbook("PB-PHISH-CLICK")
        assert pb is not None
        assert pb.id == "PB-PHISH-CLICK"

    def test_invoice_fraud_playbook_exists(self):
        pb = get_playbook("PB-INVOICE-FRAUD")
        assert pb is not None
        assert len(pb.steps) >= 4

    def test_ransomware_playbook_exists(self):
        pb = get_playbook("PB-RANSOM")
        assert pb is not None

    def test_unknown_playbook_raises(self):
        with pytest.raises(PlaybookError) as exc:
            get_playbook("PB-DOES-NOT-EXIST")
        assert exc.value.status == 404

    def test_playbook_steps_have_kb_refs(self):
        pb = get_playbook("PB-PHISH-CLICK")
        for step in pb.steps:
            assert step.kb_ref.startswith("KB-")

    def test_playbook_steps_have_actions(self):
        pb = get_playbook("PB-INVOICE-FRAUD")
        for step in pb.steps:
            assert len(step.action) > 5


# ---------------------------------------------------------------------------
# Incident service unit tests
# ---------------------------------------------------------------------------

class TestIncidentService:
    def test_create_incident_phishing(self, db):
        from app.models.models import Business
        biz = Business(name="Test Biz")
        db.add(biz)
        db.flush()

        incident = create_incident("PB-PHISH-CLICK", biz.id, db)
        assert incident.id is not None
        assert incident.playbook_id == "PB-PHISH-CLICK"
        assert incident.status == "open"

    def test_incident_has_all_steps(self, db):
        from app.models.models import Business
        biz = Business(name="Step Test Biz")
        db.add(biz)
        db.flush()

        pb = get_playbook("PB-PHISH-CLICK")
        incident = create_incident("PB-PHISH-CLICK", biz.id, db)
        assert len(incident.steps) == len(pb.steps)

    def test_complete_step_marks_done(self, db):
        from app.models.models import Business
        biz = Business(name="Complete Step Biz")
        db.add(biz)
        db.flush()

        incident = create_incident("PB-INVOICE-FRAUD", biz.id, db)
        first_step_id = incident.steps[0].step_id

        updated = complete_step(
            incident_id=incident.id,
            step_id=first_step_id,
            done=True,
            note="Called vendor, confirmed legit",
            business_id=biz.id,
            db=db,
        )
        done_step = next(s for s in updated.steps if s.step_id == first_step_id)
        assert done_step.done_at is not None
        assert done_step.note == "Called vendor, confirmed legit"

    def test_all_steps_done_closes_incident(self, db):
        from app.models.models import Business
        biz = Business(name="Close Incident Biz")
        db.add(biz)
        db.flush()

        incident = create_incident("PB-INVOICE-FRAUD", biz.id, db)
        for step in incident.steps:
            last = complete_step(
                incident_id=incident.id,
                step_id=step.step_id,
                done=True,
                note=None,
                business_id=biz.id,
                db=db,
            )
        assert last.status == "closed"
        assert last.closed_at is not None

    def test_export_contains_playbook(self, db):
        from app.models.models import Business
        biz = Business(name="Export Biz")
        db.add(biz)
        db.flush()

        incident = create_incident("PB-RANSOM", biz.id, db)
        export = export_incident(incident.id, biz.id, db)
        assert export.playbook.id == "PB-RANSOM"
        assert export.incident.id == incident.id


# ---------------------------------------------------------------------------
# Incident API endpoint tests
# ---------------------------------------------------------------------------

class TestIncidentAPI:
    def test_create_incident_api(self, auth_client):
        client, token, business_id = auth_client
        resp = client.post(
            "/api/v1/incidents",
            json={"playbook_id": "PB-PHISH-CLICK"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["playbook_id"] == "PB-PHISH-CLICK"
        assert data["status"] == "open"

    def test_create_incident_unknown_playbook(self, auth_client):
        client, token, _ = auth_client
        resp = client.post(
            "/api/v1/incidents",
            json={"playbook_id": "PB-NONEXISTENT"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    def test_patch_step(self, auth_client):
        client, token, business_id = auth_client
        create_resp = client.post(
            "/api/v1/incidents",
            json={"playbook_id": "PB-INVOICE-FRAUD"},
            headers={"Authorization": f"Bearer {token}"},
        )
        incident_id = create_resp.json()["id"]
        step_id = create_resp.json()["steps"][0]["step_id"]

        patch_resp = client.patch(
            f"/api/v1/incidents/{incident_id}/steps/{step_id}",
            json={"done": True, "note": "Did not pay the invoice."},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert patch_resp.status_code == 200
        steps = patch_resp.json()["steps"]
        done = next(s for s in steps if s["step_id"] == step_id)
        assert done["done_at"] is not None

    def test_export_incident_api(self, auth_client):
        client, token, business_id = auth_client
        create_resp = client.post(
            "/api/v1/incidents",
            json={"playbook_id": "PB-RANSOM"},
            headers={"Authorization": f"Bearer {token}"},
        )
        incident_id = create_resp.json()["id"]

        export_resp = client.get(
            f"/api/v1/incidents/{incident_id}/export",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert export_resp.status_code == 200
        data = export_resp.json()
        assert "incident" in data
        assert "playbook" in data
        assert "exported_at" in data

    def test_list_playbooks_api(self, auth_client):
        client, token, _ = auth_client
        resp = client.get("/api/v1/playbooks")
        assert resp.status_code == 200
        assert len(resp.json()) >= 3

    def test_get_playbook_by_id_api(self, auth_client):
        client, _, _ = auth_client
        resp = client.get("/api/v1/playbooks/PB-PHISH-CLICK")
        assert resp.status_code == 200
        assert resp.json()["id"] == "PB-PHISH-CLICK"

    def test_get_nonexistent_playbook_api(self, auth_client):
        client, _, _ = auth_client
        resp = client.get("/api/v1/playbooks/PB-DOES-NOT-EXIST")
        assert resp.status_code == 404

    def test_create_incident_unauthenticated(self, auth_client):
        client, _, _ = auth_client
        resp = client.post(
            "/api/v1/incidents",
            json={"playbook_id": "PB-PHISH-CLICK"},
        )
        assert resp.status_code == 401
