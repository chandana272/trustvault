from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from pwdlib import PasswordHash
from datetime import datetime, timedelta, timezone
import jwt
import os

from backend.database import get_connection

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
password_hash = PasswordHash.recommended()

SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Set TRUSTVAULT_SECRET_KEY before starting TrustVault")

ALGORITHM = "HS256"
TOKEN_MINUTES = 30


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "viewer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def create_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/register")
def register(data: RegisterRequest):
    name = data.name.strip()

    if not name:
        raise HTTPException(400, "Name is required")
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if data.role not in ("owner", "viewer"):
        raise HTTPException(400, "Invalid role")

    hashed_password = password_hash.hash(data.password)

    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO users (name, email, password_hash, role)
                   VALUES (?, ?, ?, ?)""",
                (name, str(data.email).lower(), hashed_password, data.role),
            )
        return {"message": "User registered successfully"}
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(409, "Email already registered")
        raise HTTPException(500, "Registration failed")


@router.post("/login")
def login(data: LoginRequest):
    with get_connection() as conn:
        user = conn.execute(
            """SELECT id, name, email, password_hash, role
               FROM users WHERE email = ?""",
            (str(data.email).lower(),),
        ).fetchone()

    if not user or not password_hash.verify(
        data.password, user["password_hash"]
    ):
        raise HTTPException(401, "Invalid email or password")

    token = create_token(user["id"], user["role"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_MINUTES * 60,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
        },
    }