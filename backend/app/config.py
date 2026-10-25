from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "storage"
DB_PATH = BASE_DIR / "documents.db"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
SESSION_HOURS = 12
FILES_DIR.mkdir(exist_ok=True)