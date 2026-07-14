from dotenv import load_dotenv
load_dotenv()  # must run before any module reads os.getenv at import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from app.routers import analyze, speedtest, auth, live, reports
from app import db
import jwt, os

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="NerdsToGo Network Analyzer", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Endpoints reachable without a token.
_PUBLIC = {"/api/auth/login", "/api/auth/customer/login", "/api/auth/accept-invite", "/health"}
# GET prefixes that are public (invite lookup by token).
_PUBLIC_PREFIXES = ("/api/auth/invite/",)


def _is_public(path: str) -> bool:
    return path in _PUBLIC or any(path.startswith(p) for p in _PUBLIC_PREFIXES)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or _is_public(path) or not path.startswith("/api/"):
        return await call_next(request)
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    secret = os.getenv("JWT_SECRET", "ntg-dev-secret-change-in-prod")
    try:
        claims = jwt.decode(header[7:], secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return JSONResponse({"error": "Session expired — please sign in again"}, status_code=401)
    except jwt.InvalidTokenError:
        return JSONResponse({"error": "Invalid token"}, status_code=401)

    # Role gating: /api/my/* is the customer portal; everything else under
    # /api/ is an admin tool (analyze, live capture, speedtest, report sending).
    role = claims.get("role", "admin")  # legacy tokens (pre-roles) => admin
    if path.startswith("/api/my/"):
        if role != "customer":
            return JSONResponse({"error": "Forbidden"}, status_code=403)
    else:
        if role != "admin":
            return JSONResponse({"error": "Forbidden"}, status_code=403)

    request.state.claims = claims
    return await call_next(request)


app.include_router(auth.router, prefix="/api")
app.include_router(analyze.router, prefix="/api")
app.include_router(speedtest.router, prefix="/api")
app.include_router(live.router, prefix="/api")
app.include_router(reports.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def serve_index():
    return FileResponse("index.html")
