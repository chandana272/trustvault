from typing import Optional

from .db import connect


def audit(user, action: str, doc_id: Optional[int] = None, details: str = ""):
    with connect() as c:
        c.execute(
            "INSERT INTO audit(actor_id,action,document_id,details) VALUES(?,?,?,?)",
            (user["id"] if user else None, action, doc_id, details),
        )