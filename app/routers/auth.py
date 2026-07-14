import os, datetime, time
from collections import defaultdict, deque
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import bcrypt
import jwt

from app import db

router = APIRouter()


def _secret() -> str:
    return os.getenv("JWT_SECRET", "ntg-dev-secret-change-in-prod")


def _make_token(sub: str, role: str, cid: int | None = None) -> str:
    """Issue a JWT carrying the caller's role so the middleware can gate
    admin-only vs customer-only routes. ``cid`` is the customer row id."""
    expire_h = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))
    payload = {
        "sub": sub,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=expire_h),
    }
    if cid is not None:
        payload["cid"] = cid
    return jwt.encode(payload, _secret(), algorithm="HS256")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (ValueError, TypeError):
        return False

# In-memory rate limiter: max 5 failed attempts per IP within a 60-second window
_RATE_WINDOW  = 60   # seconds
_MAX_FAILURES = 5
_fail_log: dict = defaultdict(deque)  # ip -> deque of failure timestamps


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    attempts = _fail_log[ip]
    # Evict entries outside the window
    while attempts and now - attempts[0] > _RATE_WINDOW:
        attempts.popleft()
    return len(attempts) >= _MAX_FAILURES


def _record_failure(ip: str) -> None:
    _fail_log[ip].append(time.monotonic())


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginBody, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    if _is_rate_limited(client_ip):
        return JSONResponse(
            {"error": "Too many failed attempts — please wait 60 seconds and try again."},
            status_code=429,
        )

    username = os.getenv("APP_USERNAME",        "admin")
    password = os.getenv("APP_PASSWORD",        "nerds2go")

    if body.username != username or body.password != password:
        _record_failure(client_ip)
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)

    return JSONResponse({"token": _make_token(body.username, role="admin"), "role": "admin"})


# ── Customer accounts ─────────────────────────────────────────────────────────

class CustomerLoginBody(BaseModel):
    email: str
    password: str


@router.post("/auth/customer/login")
def customer_login(body: CustomerLoginBody, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return JSONResponse(
            {"error": "Too many failed attempts — please wait 60 seconds and try again."},
            status_code=429,
        )

    cust = db.get_customer_by_email(body.email)
    if not cust or not cust.get("active") or not cust.get("password_hash") \
            or not verify_password(body.password, cust["password_hash"]):
        _record_failure(client_ip)
        return JSONResponse({"error": "Invalid email or password"}, status_code=401)

    token = _make_token(cust["email"], role="customer", cid=cust["id"])
    return JSONResponse({"token": token, "role": "customer", "name": cust.get("name") or ""})


class AcceptInviteBody(BaseModel):
    token: str
    password: str


@router.get("/auth/invite/{token}")
def invite_info(token: str):
    """Let the set-password page confirm an invite is valid before showing the
    form, and greet the customer by name."""
    cust = db.get_customer_by_invite(token)
    if not cust or (cust.get("invite_expires") or 0) < time.time():
        return JSONResponse({"valid": False}, status_code=404)
    return JSONResponse({
        "valid": True,
        "email": cust["email"],
        "name": cust.get("name") or "",
        "company": cust.get("company") or "",
    })


@router.post("/auth/accept-invite")
def accept_invite(body: AcceptInviteBody):
    cust = db.get_customer_by_invite(body.token)
    if not cust or (cust.get("invite_expires") or 0) < time.time():
        return JSONResponse({"error": "This invite link is invalid or has expired."}, status_code=400)
    if len(body.password) < 8:
        return JSONResponse({"error": "Password must be at least 8 characters."}, status_code=400)

    db.set_password(cust["id"], hash_password(body.password))
    token = _make_token(cust["email"], role="customer", cid=cust["id"])
    return JSONResponse({"token": token, "role": "customer", "name": cust.get("name") or ""})
