# ShieldDesk Backend

Production-grade FastAPI backend for ShieldDesk cybersecurity assistant for small businesses.

## Tech Stack
- **Framework**: FastAPI (Python 3.12/3.13)
- **Validation**: Pydantic v2 & Pydantic-Settings
- **ORM / DB**: SQLAlchemy 2 (SQLite for local dev & testing, PostgreSQL for production)
- **Password Hashing**: Argon2id via `argon2-cffi`
- **Auth Tokens**: JWT (JSON Web Tokens) with HS256 and secure httpOnly cookies
- **Testing**: `pytest`, `pytest-asyncio`, `httpx`

---

## Getting Started

### 1. Environment Setup
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Key environment variables:
- `APP_ENV`: `dev` or `prod`
- `DATABASE_URL`: `sqlite:///./shielddesk.db` (or PostgreSQL connection string)
- `SECRET_KEY`: Secret string used to sign JWT tokens (must be replaced in production)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT access token TTL (default: `60`)
- `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token TTL stored in httpOnly cookie (default: `7`)
- `FRONTEND_ORIGIN`: CORS allowed origin (default: `http://localhost:5173`)
- `AUTH_RATE_LIMIT`: Max auth attempts per IP per window (default: `10`)
- `SCAN_RATE_LIMIT`: Max scan requests per IP per window (default: `20`)

### 2. Database Integration & Setup
ShieldDesk uses SQLAlchemy 2 with SQLite for local development:
- The database schema is automatically created on startup via SQLAlchemy declarative models (`Base.metadata.create_all(bind=engine)`).
- No manual SQL migrations or database provisioning are required to run locally.
- For production, set `DATABASE_URL=postgresql://user:password@localhost:5432/shielddesk`.

### 3. Running the Server Locally
To start the FastAPI development server with auto-reload:
```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Interactive Swagger API docs are available at: `http://localhost:8000/docs`  
ReDoc API docs are available at: `http://localhost:8000/redoc`

### 4. Running Tests
Run the full test suite with verbose output:
```bash
python -m pytest -v
```

---

## Core Modules & Architecture

### 1. Authentication & Security Hardening
- **Argon2id Hashing**: High-memory, GPU-resistant password hashing using `argon2-cffi`. Timing-attack safe comparisons against dummy hashes on non-existent accounts.
- **JWT Authentication**: Short-lived bearer access tokens + httpOnly `refresh_token` cookies with SameSite protection.
- **Security Headers Middleware**: Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy`.
- **In-Memory Rate Limiting**: Fixed-window thread-safe rate limiter on sensitive endpoints (`/auth/*` and `/scan/*`).
- **Input Cap & Sanitization**: 20 KB cap on scanned text payloads to prevent memory exhaustion / DoS attacks.
- **Privacy Hardening**: Full message bodies and raw passwords are never logged or stored in the database. Only SHA-256 hashes and evidence snippets (<=200 chars) are stored.

### 2. Incident Playbook Engine
Handles guided incident response for SMB owners:
- Playbooks loaded directly from `backend/app/kb/playbooks.yaml`:
  - `PB-PHISH-CLICK`: Phishing links & credential compromise
  - `PB-INVOICE-FRAUD`: Suspicious invoice / payment detail change
  - `PB-RANSOM`: Ransomware & locked files
- **Incident State Tracking**: Track step-by-step progress, timestamps (`done_at`), and notes.
- **Auto-Closure**: Automatically closes the incident when all steps are completed.
- **Incident Export**: Full incident log and playbook snapshot export for compliance/reporting.

### 3. Detection Engine & Health Check
- Pure, deterministic detection rules R01-R12 covering urgency, credential harvesting, link text domain mismatch, punycode/lookalike domains, free-mail executive impersonation, payment changes, and suspicious attachments.
- Returns character offsets (`EvidenceSpan`) so the frontend can highlight suspicious phrases.
- Health-check scoring engine evaluating SMB security posture across 8 critical domains.

---

## REST API Specification

### Auth Endpoints
- `POST /api/v1/auth/register` – Register business owner or employee
  - Body: `{ "email": str, "password": str, "business_name": str, "role": "owner" | "employee" }`
  - Response: `201 Created` with User object
- `POST /api/v1/auth/login` – Authenticate user
  - Body: `{ "email": str, "password": str }`
  - Response: `200 OK` with `{ "access_token": str, "token_type": "bearer" }` and `refresh_token` in httpOnly cookie
- `POST /api/v1/auth/logout` – Clear auth cookie
- `GET /api/v1/auth/me` – Retrieve current user profile (requires `Authorization: Bearer <token>`)

### Playbook & Incident Endpoints
- `GET /api/v1/playbooks` – List available response playbooks
- `GET /api/v1/playbooks/{id}` – Get playbook details and step checklists
- `POST /api/v1/incidents` – Open a new incident for the user's business
  - Body: `{ "playbook_id": str }`
- `PATCH /api/v1/incidents/{incident_id}/steps/{step_id}` – Mark step complete/incomplete with notes
  - Body: `{ "done": bool, "note": str }`
- `GET /api/v1/incidents/{incident_id}/export` – Export incident audit log

### Scan Endpoints
- `POST /api/v1/scan/message` – Scan email/message for phishing and invoice fraud
  - Body: `{ "text": str, "sender": str?, "urls": str[]? }`
- `POST /api/v1/scan/link` – Scan link for homoglyphs and shorteners
- `POST /api/v1/scan/domain` – Check SPF / DMARC DNS records for own domain
- `POST /api/v1/scan/password` – HIBP k-anonymity SHA-1 range proxy (never transmits or stores passwords)

### Assessment & Actions Endpoints
- `GET /api/v1/assessment/questions` – Get security posture assessment questions
- `POST /api/v1/assessment` – Submit assessment answers and receive risk score & top actions
- `GET /api/v1/assessment/latest` – Retrieve latest business assessment
- `GET /api/v1/actions` – Get action items
- `PATCH /api/v1/actions/{id}` – Update action item status (`todo` | `doing` | `done`)
