
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Header
from pathlib import Path
from uuid import uuid4
import jwt

from backend.database import get_connection
from backend.auth import SECRET_KEY, ALGORITHM

router = APIRouter(prefix="/api/documents", tags=["Documents"])
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "storage" / "documents"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx"}
MAX_SIZE = 5 * 1024 * 1024


def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    try:
        data = jwt.decode(
            authorization[7:], SECRET_KEY, algorithms=[ALGORITHM]
        )
        with get_connection() as conn:
            user = conn.execute(
                "SELECT id,name,email,role FROM users WHERE id=?",
                (int(data["sub"]),)
            ).fetchone()
        if not user:
            raise ValueError()
        return dict(user)
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def audit(conn, user_id, doc_id, action, details=""):
    conn.execute(
        """INSERT INTO audit_logs(user_id,document_id,action,details)
           VALUES(?,?,?,?)""",
        (user_id, doc_id, action, details)
    )


def access(conn, user, doc_id, required="read"):
    doc = conn.execute(
        "SELECT * FROM documents WHERE id=?", (doc_id,)
    ).fetchone()

    if not doc:
        audit(conn, user["id"], doc_id, "DENIED", "Document not found")
        raise HTTPException(404, "Document not found")

    permitted = user["role"] == "admin" or doc["owner_id"] == user["id"]

    if not permitted:
        grant = conn.execute(
            """SELECT access_level FROM permissions
               WHERE document_id=? AND user_id=?""",
            (doc_id, user["id"])
        ).fetchone()
        permitted = bool(grant) and (
            grant["access_level"] == "edit" or required == "read"
        )

    if not permitted:
        audit(conn, user["id"], doc_id, "DENIED", required)
        raise HTTPException(403, "Access denied")

    if required == "edit" and user["role"] != "admin" and doc["owner_id"] != user["id"]:
        grant = conn.execute(
            """SELECT access_level FROM permissions
               WHERE document_id=? AND user_id=?""",
            (doc_id, user["id"])
        ).fetchone()
        if not grant or grant["access_level"] != "edit":
            audit(conn, user["id"], doc_id, "DENIED", "Edit")
            raise HTTPException(403, "Edit permission required")

    return doc


@router.get("/")
def list_documents(search: str = "", authorization: str = Header(None)):
    user = current_user(authorization)
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT DISTINCT d.id,d.filename,d.category,d.owner_id,d.created_at
               FROM documents d
               LEFT JOIN permissions p ON p.document_id=d.id
               WHERE (d.owner_id=? OR p.user_id=? OR ?='admin')
                 AND d.filename LIKE ?
               ORDER BY d.id DESC""",
            (user["id"], user["id"], user["role"], f"%{search}%")
        ).fetchall()
        visible = []
        for row in rows:
            item = dict(row)
            try:
                access(conn, user, item["id"])
                visible.append(item)
            except HTTPException:
                pass
        return visible


@router.post("/")
async def upload_document(
    file: UploadFile = File(...),
    category: str = Form("General"),
    authorization: str = Header(None)
):
    user = current_user(authorization)
    if user["role"] == "viewer":
        raise HTTPException(403, "Viewer accounts cannot upload documents")

    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() not in ALLOWED:
        raise HTTPException(400, "Unsupported file type")
    content = await file.read(MAX_SIZE + 1)
    if not content or len(content) > MAX_SIZE:
        raise HTTPException(400, "File must be between 1 byte and 5 MB")

    stored = uuid4().hex
    path = UPLOAD_DIR / stored
    path.write_bytes(content)

    try:
        with get_connection() as conn:
            cur = conn.execute(
                """INSERT INTO documents(filename,category,owner_id,stored_name)
                   VALUES(?,?,?,?)""",
                (filename, category[:60], user["id"], stored)
            )
            doc_id = cur.lastrowid
            audit(conn, user["id"], doc_id, "UPLOAD", filename)
        return {"message": "Document uploaded", "id": doc_id}
    except Exception:
        path.unlink(missing_ok=True)
        raise HTTPException(500, "Upload failed")


@router.get("/{doc_id}/download")
def download_document(doc_id: int, authorization: str = Header(None)):
    from fastapi.responses import FileResponse
    user = current_user(authorization)
    with get_connection() as conn:
        doc = access(conn, user, doc_id, "read")
        path = UPLOAD_DIR / doc["stored_name"]
        if not path.is_file():
            raise HTTPException(404, "File unavailable")
        audit(conn, user["id"], doc_id, "DOWNLOAD", doc["filename"])
        filename = doc["filename"]
    return FileResponse(path, filename=filename)


@router.post("/{doc_id}/permissions")
def grant_permission(
    doc_id: int,
    email: str,
    access_level: str = "read",
    authorization: str = Header(None)
):
    user = current_user(authorization)
    if access_level not in ("read", "edit"):
        raise HTTPException(400, "Access must be read or edit")

    with get_connection() as conn:
        doc = access(conn, user, doc_id, "edit")
        target = conn.execute(
            "SELECT id FROM users WHERE email=?", (email.lower(),)
        ).fetchone()
        if not target:
            raise HTTPException(404, "Recipient not found")
        if target["id"] == doc["owner_id"]:
            raise HTTPException(400, "Owner already has access")

        conn.execute(
            """INSERT INTO permissions(document_id,user_id,access_level)
               VALUES(?,?,?)
               ON CONFLICT(document_id,user_id)
               DO UPDATE SET access_level=excluded.access_level""",
            (doc_id, target["id"], access_level)
        )
        audit(conn, user["id"], doc_id, "GRANT",
              f"user={target['id']}; access={access_level}")
    return {"message": "Permission granted"}


@router.delete("/{doc_id}/permissions/{target_id}")
def revoke_permission(
    doc_id: int,
    target_id: int,
    authorization: str = Header(None)
):
    user = current_user(authorization)
    with get_connection() as conn:
        access(conn, user, doc_id, "edit")
        conn.execute(
            "DELETE FROM permissions WHERE document_id=? AND user_id=?",
            (doc_id, target_id)
        )
        audit(conn, user["id"], doc_id, "REVOKE", f"user={target_id}")
    return {"message": "Permission revoked"}


@router.delete("/{doc_id}")
def delete_document(doc_id: int, authorization: str = Header(None)):
    user = current_user(authorization)
    with get_connection() as conn:
        doc = access(conn, user, doc_id, "edit")
        if user["role"] != "admin" and doc["owner_id"] != user["id"]:
            raise HTTPException(403, "Only the owner or admin can delete")
        path = UPLOAD_DIR / doc["stored_name"]
        conn.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        audit(conn, user["id"], doc_id, "DELETE", doc["filename"])
    path.unlink(missing_ok=True)
    return {"message": "Document deleted"}


@router.get("/admin/audit")
def get_audit(authorization: str = Header(None)):
    user = current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500"
        ).fetchall()
    return [dict(row) for row in rows]
