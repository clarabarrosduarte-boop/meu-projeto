import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_PATH = BASE_DIR / "instance"
UPLOAD_PATH = BASE_DIR / "uploads"

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URI",
        f"sqlite:///{(INSTANCE_PATH / 'explainity.sqlite').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_MB", 4096)) * 1024 * 1024
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(UPLOAD_PATH))
    ALLOWED_EXTENSIONS = {"mp4", "webm", "mov"}
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True

    # basic rate limiting defaults
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 100))
    RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW", 60))
