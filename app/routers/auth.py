import os, datetime
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginBody):
    secret   = os.getenv("JWT_SECRET",         "ntg-dev-secret-change-in-prod")
    username = os.getenv("APP_USERNAME",        "admin")
    password = os.getenv("APP_PASSWORD",        "nerds2go")
    expire_h = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))

    if body.username != username or body.password != password:
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)
    payload = {
        "sub": body.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=expire_h),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return JSONResponse({"token": token})
