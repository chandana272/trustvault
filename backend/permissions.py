from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.database import get_connection
from backend.security import get_current_user

router = APIRouter(prefix="/api/permissions", tags=["Permissions"])


class PermissionRequest(BaseModel):
    document_id: int
    user_id: int
    can_read: bool = True
    can_edit: bool = False


@router.post("/grant")
def grant_permission(
    data: PermissionRequest,
    current_user: dict = Depends(get_current_user),
):
    if data.user_id == current_user["id"]:
        raise HTTPException(400, "You already own your account")

    with get_connection() as conn:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (data.document_id, current_user["id"]),
        ).fetchone()

        if not document:
            raise HTTPException(404, "Document not found or not owned by you")

        recipient = conn.execute(
            "SELECT id FROM users WHERE id = ?", (data.user_id,)
        ).fetchone()

        if not recipient:
            raise HTTPException(404, "Recipient user not found")

        conn.execute(
            """
            INSERT INTO permissions
                (document_id, user_id, can_read, can_edit, granted_by)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET
                can_read = excluded.can_read,
                can_edit = excluded.can_edit,
                granted_by = excluded.granted_by,
                created_at = CURRENT_TIMESTAMP
            """,
            (
                data.document_id,
                data.user_id,
                int(data.can_read or data.can_edit),
                int(data.can_edit),
                current_user["id"],
            ),
        )

        conn.execute(
            """
            INSERT INTO audit_logs (user_id, document_id, action, details)
            VALUES (?, ?, 'PERMISSION_GRANTED', ?)
            """,
            (
                current_user["id"],
                data.document_id,
                f"Access granted to user {data.user_id}",
            ),
        )

    return {"message": "Permission granted successfully"}


@router.delete("/revoke/{document_id}/{user_id}")
def revoke_permission(
    document_id: int,
    user_id: int,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, current_user["id"]),
        ).fetchone()

        if not document:
            raise HTTPException(404, "Document not found or not owned by you")

        result = conn.execute(
            "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
            (document_id, user_id),
        )

        conn.execute(
            """
            INSERT INTO audit_logs (user_id, document_id, action, details)
            VALUES (?, ?, 'PERMISSION_REVOKED', ?)
            """,
            (
                current_user["id"],
                document_id,
                f"Access revoked for user {user_id}",
            ),
        )

    return {"message": "Permission revoked successfully"}