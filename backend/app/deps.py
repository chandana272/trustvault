from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import SESSION_HOURS
from .db import connect

bearer = HTTPBearer(auto_error=False)


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred:
        raise HTTPException(401, "Not authenticated")
    with connect() as c:
        row = c.execute(
            """SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id
               WHERE s.token=? AND s.created_at > datetime('now', ?)""",
            (cred.credentials, f"-{SESSION_HOURS} hours"),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid or expired token")
    return dict(row)


def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def access(doc_id: int, user, edit: bool = False):
    """Return the document row if the user may read (or edit) it."""
    with connect() as c:
        d = c.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not d:
            raise HTTPException(404, "Document not found")
        if d["owner_id"] == user["id"] or user["role"] == "admin":
            return dict(d)
        p = c.execute(
            "SELECT can_read,can_edit FROM permissions WHERE document_id=? AND user_id=?",
            (doc_id, user["id"]),
        ).fetchone()
    if not p or not p["can_read"]:
        raise HTTPException(403, "Access denied")
    if edit and not p["can_edit"]:
        raise HTTPException(403, "Edit permission required")
    return dict(d)