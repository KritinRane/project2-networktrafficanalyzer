"""Report persistence + delivery.

Admin path
    POST /api/reports/send   Persist a finished analysis for a customer,
                             creating (and inviting) the customer account if
                             they don't exist yet. PDF rendering + emailing is
                             wired in during Phase 3; this phase persists the
                             report and returns the invite link.

Customer path (portal)
    GET  /api/my/reports          List the caller's reports (metadata only).
    GET  /api/my/reports/{id}     Full stored analysis for one report.
    GET  /api/my/reports/{id}/pdf Download the stored PDF (once Phase 3 fills it).

Route-role gating is enforced in main.py's middleware: /api/reports/* is
admin-only, /api/my/* is customer-only.
"""
import os
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from app import db, pdf, email_sender

router = APIRouter()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _invite_url(request: Request, token: str) -> str:
    """Absolute link the customer clicks to set their password. Prefers
    PUBLIC_BASE_URL (set in prod so links point at the real domain, not an
    internal host) and falls back to the request's own base URL."""
    base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/") or str(request.base_url).rstrip("/")
    return f"{base}/?invite={token}"


def _usable_invite(cust: dict) -> str | None:
    """Return a valid invite token for an inactive customer, refreshing an
    expired/missing one. Returns None for already-active accounts."""
    if cust.get("active"):
        return None
    token = cust.get("invite_token")
    if not token or (cust.get("invite_expires") or 0) < time.time():
        token = db.refresh_invite(cust["id"])
    return token


# ── Admin: persist + (Phase 3) deliver ────────────────────────────────────────

class SendReportBody(BaseModel):
    customer_email: str
    customer_name: str = ""
    customer_company: str = ""
    filename: str = ""
    analysis: dict


@router.post("/reports/send")
def send_report(body: SendReportBody, request: Request):
    email = body.customer_email.strip()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="A valid customer email is required.")
    if not body.analysis:
        raise HTTPException(status_code=400, detail="Report analysis payload is empty.")

    existed = db.get_customer_by_email(email) is not None
    cust = db.upsert_customer(email, body.customer_name, body.customer_company)

    created_by = (getattr(request.state, "claims", {}) or {}).get("sub", "admin")
    report_id = db.save_report(
        customer_id=cust["id"],
        analysis=body.analysis,
        created_by=created_by,
        filename=body.filename,
    )

    invite_token = _usable_invite(cust)
    invite_url = _invite_url(request, invite_token) if invite_token else None

    # Render the PDF (None if WeasyPrint/native libs unavailable) and persist it
    # on the report row so the portal can serve it later.
    pdf_bytes = pdf.render_report_pdf(body.analysis, {
        "customer_name": cust.get("name") or "",
        "customer_company": cust.get("company") or "",
        "filename": body.filename,
        "generated_at": datetime.now(timezone.utc),
    })
    if pdf_bytes:
        db.attach_pdf(report_id, pdf_bytes)

    # Email the PDF + portal invite. Failure here never fails the request — the
    # report is already saved and downloadable from the portal.
    emailed, email_detail = email_sender.send_report_email(
        to_email=cust["email"],
        name=cust.get("name") or "",
        pdf_bytes=pdf_bytes,
        invite_url=invite_url,
    )

    return JSONResponse({
        "status": "ok",
        "report_id": report_id,
        "customer_id": cust["id"],
        "customer_email": cust["email"],
        "new_customer": not existed,
        "account_active": bool(cust["active"]),
        "invite_url": invite_url,
        "pdf_generated": pdf_bytes is not None,
        "emailed": emailed,
        "email_detail": email_detail,
    })


# ── Customer: portal reads ────────────────────────────────────────────────────

def _caller_cid(request: Request) -> int:
    cid = (getattr(request.state, "claims", {}) or {}).get("cid")
    if not cid:
        raise HTTPException(status_code=403, detail="No customer account on this token.")
    return int(cid)


@router.get("/my/reports")
def my_reports(request: Request):
    cid = _caller_cid(request)
    return {"reports": db.list_reports_for_customer(cid)}


@router.get("/my/reports/{report_id}")
def my_report(report_id: int, request: Request):
    cid = _caller_cid(request)
    report = db.get_report(report_id)
    if not report or report["customer_id"] != cid:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {
        "id": report["id"],
        "filename": report["filename"],
        "created_at": report["created_at"],
        "has_pdf": report["pdf"] is not None,
        "analysis": report["analysis"],
    }


@router.get("/my/reports/{report_id}/pdf")
def my_report_pdf(report_id: int, request: Request):
    cid = _caller_cid(request)
    report = db.get_report(report_id)
    if not report or report["customer_id"] != cid:
        raise HTTPException(status_code=404, detail="Report not found.")
    if not report["pdf"]:
        raise HTTPException(status_code=404, detail="No PDF available for this report yet.")
    fname = f"network-report-{report_id}.pdf"
    return Response(
        content=report["pdf"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
