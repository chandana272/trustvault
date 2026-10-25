import os
import jwt

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.database import get_connection

SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY")
ALGORITHM = "HS256"

bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    if not SECRET_KEY:
        raise HTTPException(500, "Authentication configuration missing")

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(401, "Invalid or expired token")

    with get_connection() as conn:
        user = conn.execute(
            """
            SELECT id, name, email, role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    if not user:
        raise HTTPException(401, "User no longer exists")

    return dict(user)