import os, datetime, time
from collections import defaultdict, deque
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt

router = APIRouter()

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

    secret   = os.getenv("JWT_SECRET",         "ntg-dev-secret-change-in-prod")
    username = os.getenv("APP_USERNAME",        "admin")
    password = os.getenv("APP_PASSWORD",        "nerds2go")
    expire_h = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))

    if body.username != username or body.password != password:
        _record_failure(client_ip)
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)

    payload = {
        "sub": body.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=expire_h),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return JSONResponse({"token": token})
