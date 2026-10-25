import hashlib
import hmac
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import (
    Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
)
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "storage"
DB_PATH = BASE_DIR / "documents_fixed.db"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
FILES_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="TrustVault", version="1.0")
bearer = HTTPBearer(auto_error=False)


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General',
            owner_id INTEGER NOT NULL REFERENCES users(id),
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            content_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS permissions (
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            can_read INTEGER NOT NULL DEFAULT 1,
            can_edit INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            action TEXT NOT NULL,
            document_id INTEGER,
            details TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "full_name" not in cols:
            c.execute(
                "ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"
            )


init_db()


def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + hashed


def verify_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
        return hmac.compare_digest(hash_password_with_salt(password, salt), stored)
    except (ValueError, AttributeError):
        return False


def hash_password_with_salt(password, salt):
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + hashed


def audit(user, action, doc_id=None, details=""):
    with connect() as c:
        c.execute(
            """INSERT INTO audit(actor_id,action,document_id,details)
               VALUES(?,?,?,?)""",
            (user["id"] if user else None, action, doc_id, details),
        )


def current_user(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    if not cred:
        raise HTTPException(401, "Please sign in")
    with connect() as c:
        row = c.execute(
            """SELECT u.id,u.username,u.full_name,u.role
               FROM sessions s JOIN users u ON u.id=s.user_id
               WHERE s.token=? AND s.created_at>datetime('now','-12 hours')""",
            (cred.credentials,),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Session expired; sign in again")
    return dict(row)


def admin_only(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def get_document(doc_id, user, edit=False):
    with connect() as c:
        doc = c.execute(
            "SELECT * FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        if not doc:
            audit(user, "access_denied", doc_id, "Document does not exist")
            raise HTTPException(404, "Document not found")

        if doc["owner_id"] == user["id"] or user["role"] == "admin":
            return dict(doc)

        perm = c.execute(
            """SELECT can_read,can_edit FROM permissions
               WHERE document_id=? AND user_id=?""",
            (doc_id, user["id"]),
        ).fetchone()

    if not perm or not perm["can_read"]:
        audit(user, "access_denied", doc_id, "Read access denied")
        raise HTTPException(403, "Access denied")

    if edit and not perm["can_edit"]:
        audit(user, "access_denied", doc_id, "Edit access denied")
        raise HTTPException(403, "Edit permission required")
    return dict(doc)


def owner_or_admin(doc, user):
    if doc["owner_id"] != user["id"] and user["role"] != "admin":
        audit(user, "access_denied", doc["id"], "Owner/admin permission required")
        raise HTTPException(403, "Owner or admin required")


class Account(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: str = Field(min_length=8, max_length=256)
    role: str = "owner"


class DocumentUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=200)
    category: Optional[str] = Field(None, max_length=80)


class PermissionInput(BaseModel):
    username: str = Field(min_length=3, max_length=254)
    can_read: bool = True
    can_edit: bool = False


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "TrustVault"}


@app.post("/api/auth/register", status_code=201)
def register(data: Account):
    email = (data.email or data.username or "").strip().lower()
    full_name = (data.full_name or "").strip() or email.split("@")[0]
    role = data.role.strip().lower()

    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(400, "Enter a valid email address")
    if role not in ("owner", "viewer"):
        raise HTTPException(400, "Public registration allows owner or viewer only")

    with connect() as c:
        try:
            cur = c.execute(
                """INSERT INTO users(username,full_name,password_hash,role)
                   VALUES(?,?,?,?)""",
                (email, full_name, hash_password(data.password), role),
            )
            uid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Email already registered")

    audit({"id": uid}, "register", details=f"role={role}")
    return {
        "message": "Registration successful",
        "email": email,
        "username": email,
        "full_name": full_name,
        "role": role,
    }


@app.post("/api/auth/login")
def login(data: Account):
    email = (data.email or data.username or "").strip().lower()
    with connect() as c:
        u = c.execute(
            "SELECT * FROM users WHERE username=?", (email,)
        ).fetchone()
        if not u or not verify_password(data.password, u["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        token = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO sessions(token,user_id) VALUES(?,?)",
            (token, u["id"]),
        )

    audit(dict(u), "login")
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": u["role"],
        "username": u["username"],
        "full_name": u["full_name"],
    }


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.post("/api/documents", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    category: str = Form("General"),
    user=Depends(current_user),
):
    original = Path(file.filename or "file").name
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Maximum file size is 20 MB")
    if not content:
        raise HTTPException(400, "Empty file")

    doc_name = (name or Path(original).stem).strip() or "untitled"
    stored = uuid.uuid4().hex + Path(original).suffix
    (FILES_DIR / stored).write_bytes(content)

    try:
        with connect() as c:
            cur = c.execute(
                """INSERT INTO documents
                   (name,category,owner_id,stored_name,size,content_type)
                   VALUES(?,?,?,?,?,?)""",
                (doc_name, category.strip(), user["id"], stored,
                 len(content), file.content_type),
            )
            doc_id = cur.lastrowid
    except Exception:
        (FILES_DIR / stored).unlink(missing_ok=True)
        raise

    audit(user, "upload", doc_id, doc_name)
    return {"message": "Uploaded", "id": doc_id, "name": doc_name}


@app.get("/api/documents")
def list_documents(
    name: str = "",
    owner: str = "",
    category: str = "",
    date: str = "",
    user=Depends(current_user),
):
    with connect() as c:
        rows = c.execute(
            """SELECT d.id,d.name,d.category,u.username AS owner,
                      d.size,d.created_at,d.updated_at
               FROM documents d JOIN users u ON u.id=d.owner_id
               WHERE (?='admin' OR d.owner_id=? OR EXISTS(
                   SELECT 1 FROM permissions p
                   WHERE p.document_id=d.id AND p.user_id=? AND p.can_read=1))
               AND d.name LIKE ? AND u.username LIKE ?
               AND d.category LIKE ?
               AND (?='' OR date(d.created_at)=date(?))
               ORDER BY d.created_at DESC""",
            (user["role"], user["id"], user["id"], f"%{name}%",
             f"%{owner}%", f"%{category}%", date, date),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/documents/{doc_id}")
def document_details(doc_id: int, user=Depends(current_user)):
    d = get_document(doc_id, user)
    audit(user, "view_metadata", doc_id)
    return {k: d[k] for k in (
        "id", "name", "category", "owner_id", "size",
        "content_type", "created_at", "updated_at"
    )}


@app.get("/api/documents/{doc_id}/download")
def download_document(doc_id: int, user=Depends(current_user)):
    d = get_document(doc_id, user)
    path = FILES_DIR / d["stored_name"]
    if not path.is_file():
        raise HTTPException(404, "Stored file missing")
    audit(user, "download", doc_id)
    return FileResponse(
        path,
        filename=d["name"] + Path(d["stored_name"]).suffix,
        media_type=d["content_type"] or "application/octet-stream",
    )


@app.patch("/api/documents/{doc_id}")
def update_document(doc_id: int, data: DocumentUpdate, user=Depends(current_user)):
    d = get_document(doc_id, user, edit=True)
    name = data.name.strip() if data.name else d["name"]
    category = data.category.strip() if data.category is not None else d["category"]
    with connect() as c:
        c.execute(
            """UPDATE documents SET name=?,category=?,updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (name, category, doc_id),
        )
    audit(user, "update", doc_id, f"name={name};category={category}")
    return {"message": "Updated", "id": doc_id, "name": name, "category": category}


@app.delete("/api/documents/{doc_id}")
def delete_document(doc_id: int, user=Depends(current_user)):
    d = get_document(doc_id, user)
    owner_or_admin(d, user)
    with connect() as c:
        c.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    (FILES_DIR / d["stored_name"]).unlink(missing_ok=True)
    audit(user, "delete", doc_id, d["name"])
    return {"message": "Deleted"}


@app.post("/api/documents/{doc_id}/permissions")
def grant_permission(
    doc_id: int, data: PermissionInput, user=Depends(current_user)
):
    d = get_document(doc_id, user)
    owner_or_admin(d, user)
    can_read = data.can_read or data.can_edit

    with connect() as c:
        target = c.execute(
            "SELECT id FROM users WHERE username=?",
            (data.username.strip().lower(),),
        ).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        if target["id"] == d["owner_id"]:
            raise HTTPException(400, "Owner already has access")
        c.execute(
            """INSERT INTO permissions(document_id,user_id,can_read,can_edit)
               VALUES(?,?,?,?)
               ON CONFLICT(document_id,user_id) DO UPDATE SET
               can_read=excluded.can_read,can_edit=excluded.can_edit""",
            (doc_id, target["id"], int(can_read), int(data.can_edit)),
        )

    audit(user, "permission_grant", doc_id, f"target={data.username}")
    return {
        "message": "Permission saved",
        "username": data.username,
        "can_read": can_read,
        "can_edit": data.can_edit,
    }


@app.delete("/api/documents/{doc_id}/permissions/{username}")
def revoke_permission(
    doc_id: int, username: str, user=Depends(current_user)
):
    d = get_document(doc_id, user)
    owner_or_admin(d, user)
    with connect() as c:
        target = c.execute(
            "SELECT id FROM users WHERE username=?",
            (username.strip().lower(),),
        ).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        c.execute(
            "DELETE FROM permissions WHERE document_id=? AND user_id=?",
            (doc_id, target["id"]),
        )
    audit(user, "permission_revoke", doc_id, f"target={username}")
    return {"message": "Permission revoked", "username": username}


@app.get("/api/documents/{doc_id}/permissions")
def list_permissions(doc_id: int, user=Depends(current_user)):
    d = get_document(doc_id, user)
    owner_or_admin(d, user)
    with connect() as c:
        rows = c.execute(
            """SELECT u.username,p.can_read,p.can_edit
               FROM permissions p JOIN users u ON u.id=p.user_id
               WHERE p.document_id=? ORDER BY u.username""",
            (doc_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/admin/audit")
def admin_audit(
    limit: int = Query(100, ge=1, le=500),
    user=Depends(admin_only),
):
    with connect() as c:
        rows = c.execute(
            """SELECT a.id,a.action,a.document_id,a.details,a.created_at,
                      u.username AS actor
               FROM audit a LEFT JOIN users u ON u.id=a.actor_id
               ORDER BY a.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/admin/summary")
def admin_summary(user=Depends(admin_only)):
    with connect() as c:
        users = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        docs = c.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"]
        events = c.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]
        actions = c.execute(
            "SELECT action,COUNT(*) AS count FROM audit GROUP BY action"
        ).fetchall()
    return {
        "users": users,
        "documents": docs,
        "audit_events": events,
        "actions": [dict(r) for r in actions],
    }