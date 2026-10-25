# TrustVault - Document Management API

FastAPI + SQLite backend with token login, roles, document upload/download,
sharing permissions and an admin audit log.

## Run
    cd backend
    python -m uvicorn app.main:app --reload
Open http://127.0.0.1:8000/docs

## Features
- Register / login (first user becomes admin), 12-hour session tokens
- Upload, list (filter by name, owner, category, date), view, rename, download, delete
- Share documents with read or edit permission, revoke access
- Admin summary and audit log
