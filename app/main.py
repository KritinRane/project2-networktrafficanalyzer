from dotenv import load_dotenv
load_dotenv()  # must run before any module reads os.getenv at import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from app.routers import analyze, speedtest, auth
import jwt, os

app = FastAPI(title="NerdsToGo Network Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_SECRET = os.getenv("JWT_SECRET", "ntg-dev-secret-change-in-prod")
_PUBLIC = {"/api/auth/login", "/health"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Let CORS preflight, public endpoints, and non-API paths through
    if request.method == "OPTIONS" or path in _PUBLIC or not path.startswith("/api/"):
        return await call_next(request)
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        jwt.decode(header[7:], _SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return JSONResponse({"error": "Session expired — please sign in again"}, status_code=401)
    except jwt.InvalidTokenError:
        return JSONResponse({"error": "Invalid token"}, status_code=401)
    return await call_next(request)


app.include_router(auth.router, prefix="/api")
app.include_router(analyze.router, prefix="/api")
app.include_router(speedtest.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def serve_index():
    return FileResponse("index.html")
