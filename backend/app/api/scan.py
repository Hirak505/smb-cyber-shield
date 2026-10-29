"""Scan router: /scan/message, /scan/link, /scan/domain, /scan/password."""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import scan_limiter
from app.schemas.schemas import (
    ErrorResponse,
    ScanDomainRequest,
    ScanDomainResponse,
    ScanLinkRequest,
    ScanLinkResponse,
    ScanMessageRequest,
    ScanMessageResponse,
    ScanPasswordRequest,
    ScanPasswordResponse,
)
from app.services.scanner import scan_link, scan_message

log = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["scan"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")


def _check_scan_rate(request: Request) -> None:
    ip = _client_ip(request)
    if not scan_limiter.is_allowed(ip):
        raise HTTPException(
            status_code=429,
            detail={
                "error": {
                    "code": "RATE_LIMITED",
                    "message": "Too many scan requests. Please wait before trying again.",
                }
            },
        )


@router.post(
    "/message",
    response_model=ScanMessageResponse,
    responses={422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan_message_endpoint(
    req: ScanMessageRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ScanMessageResponse:
    _check_scan_rate(request)

    if len(req.text.encode()) > get_settings().MAX_MESSAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Message exceeds 20 KB limit."}},
        )

    return scan_message(
        text=req.text,
        sender=req.sender,
        urls=req.urls,
        db=db,
    )


@router.post(
    "/link",
    response_model=ScanLinkResponse,
    responses={429: {"model": ErrorResponse}},
)
def scan_link_endpoint(
    req: ScanLinkRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ScanLinkResponse:
    _check_scan_rate(request)
    return scan_link(url=req.url, db=db)


@router.post(
    "/domain",
    response_model=ScanDomainResponse,
    responses={429: {"model": ErrorResponse}},
)
def scan_domain_endpoint(
    req: ScanDomainRequest,
    request: Request,
) -> ScanDomainResponse:
    _check_scan_rate(request)

    domain = req.domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
    findings: list[str] = []
    spf = dkim = dmarc = None

    try:
        import dns.resolver

        def _query(name: str, rtype: str) -> str | None:
            try:
                answers = dns.resolver.resolve(name, rtype, lifetime=5)
                return " ".join(str(r) for r in answers)
            except Exception:
                return None

        spf_record = _query(domain, "TXT")
        if spf_record:
            if "v=spf1" in spf_record:
                spf = "present"
            else:
                spf = "missing"
                findings.append("SPF record not found – email spoofing is easier without it.")
        else:
            findings.append("No TXT records found for SPF check.")

        dmarc_record = _query(f"_dmarc.{domain}", "TXT")
        if dmarc_record and "v=DMARC1" in dmarc_record:
            dmarc = "present"
        else:
            dmarc = "missing"
            findings.append("DMARC record not found – phishing in your name is easier.")

        # DKIM requires a selector; we skip it in MVP
        dkim = "not_checked"
        findings.append("DKIM not checked automatically – provide a selector to verify.")

    except ImportError:
        findings.append("DNS library not available; install dnspython.")

    return ScanDomainResponse(
        domain=domain,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        findings=findings,
    )


@router.post(
    "/password",
    response_model=ScanPasswordResponse,
    responses={429: {"model": ErrorResponse}},
)
async def scan_password_endpoint(
    req: ScanPasswordRequest,
    request: Request,
) -> ScanPasswordResponse:
    """
    Proxy HIBP k-anonymity range API.
    Never logs or stores the prefix; never sees or stores passwords.
    """
    _check_scan_rate(request)

    prefix = req.sha1_prefix.upper()
    hibp_url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(hibp_url)
            resp.raise_for_status()
            suffixes = resp.text.strip().splitlines()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": {"code": "HIBP_ERROR", "message": "Password breach service unavailable."}},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": {"code": "HIBP_ERROR", "message": "Password breach service unavailable."}},
        ) from exc

    return ScanPasswordResponse(suffixes=suffixes)
