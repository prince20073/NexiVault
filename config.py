"""Application configuration. Secrets come from the .env file, never from source code."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Database (SQLite file inside the instance/ folder)
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + (BASE_DIR / "instance" / "nexivault.db").as_posix()
    LEGACY_DATABASE_FILE = BASE_DIR / "instance" / "securevault.db"  # copied automatically if found
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Server-side sessions (the unlocked vault key never goes into the browser cookie)
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = str(BASE_DIR / ".flask_session")
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_NAME = "nexivault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"

    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024

    # Tunable security behaviour (set in .env)
    AUTO_LOCK_MINUTES = _int_env("AUTO_LOCK_MINUTES", 15)      # idle time before the vault locks
    SESSION_MAX_HOURS = _int_env("SESSION_MAX_HOURS", 8)        # absolute sign-in lifetime
    MAX_LOGIN_ATTEMPTS = _int_env("MAX_LOGIN_ATTEMPTS", 5)      # failures before a temporary lockout
    LOGIN_LOCK_MINUTES = _int_env("LOGIN_LOCK_MINUTES", 10)
