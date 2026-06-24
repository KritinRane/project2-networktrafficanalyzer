import os, datetime
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt

router = APIRouter()

_SECRET   = os.getenv("JWT_SECRET", "ntg-dev-secret-change-in-prod")
_USERNAME = os.getenv("APP_USERNAME", "admin")
_PASSWORD = os.getenv("APP_PASSWORD", "nerds2go")
_EXPIRE_H = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginBody):
    if body.username != _USERNAME or body.password != _PASSWORD:
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)
    payload = {
        "sub": body.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=_EXPIRE_H),
    }
    token = jwt.encode(payload, _SECRET, algorithm="HS256")
    return JSONResponse({"token": token})
