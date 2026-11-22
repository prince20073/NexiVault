"""Small shared helpers: auth decorators, session start, safe redirects, input cleaning."""
import re
import time
from functools import wraps
from urllib.parse import urlsplit

from flask import current_app, flash, g, jsonify, redirect, request, session, url_for

from extensions import db
from models import User

CATEGORIES = ["Social Media", "Email", "Banking", "Education", "Shopping", "Work", "Entertainment", "Other"]
_HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ------------------------------------------------------------------ session
def current_user():
    """Return the signed-in User (cached per request) or None."""
    if "user" not in g:
        uid = session.get("user_id")
        g.user = db.session.get(User, uid) if uid else None
    return g.user


def wants_json() -> bool:
    return request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest"


def start_session(user, vault_key: bytes | None):
    """Begin a fresh signed-in session (new session id, so old ids can't be reused)."""
    session.clear()
    session["user_id"] = user.id
    if vault_key:
        session["vault_key"] = vault_key.decode("ascii")
    now = time.time()
    session["login_at"] = now
    session["last_active"] = now
    current_app.session_interface.regenerate(session)
    g.pop("user", None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            session.clear()
            if wants_json():
                return jsonify(error="Please sign in again."), 401
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def vault_unlocked(view):
    """Must be used under @login_required."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("vault_key"):
            if wants_json():
                return jsonify(error="Your vault is locked.", locked=True), 401
            flash("Unlock your vault to continue.", "warning")
            return redirect(url_for("auth.unlock"))
        return view(*args, **kwargs)
    return wrapped


def safe_back(default_endpoint: str) -> str:
    """Redirect target for 'return to the page I came from' without allowing open redirects."""
    ref = request.referrer
    if ref:
        parts = urlsplit(ref)
        if parts.netloc == request.host:
            return parts.path + (f"?{parts.query}" if parts.query else "")
    return url_for(default_endpoint)


def client_key(prefix: str) -> str:
    return f"{prefix}:{request.remote_addr}"


# ------------------------------------------------------------------ input cleaning
def clean_text(value: str | None, max_len: int, multiline: bool = False) -> str:
    value = _CONTROL_CHARS.sub("", (value or "").replace("\r\n", "\n"))
    if not multiline:
        value = " ".join(value.split())
    return value.strip()[:max_len]


def normalize_website(raw: str):
    """Return (url, error). Only http/https links are accepted; a missing scheme becomes https."""
    error = "Enter a valid website address, for example https://example.com."
    raw = clean_text(raw, 500)
    if not raw:
        return "", None
    if "://" not in raw:
        raw = "https://" + raw
    if " " in raw:
        return "", error
    parts = urlsplit(raw)
    try:
        host, _ = parts.hostname, parts.port      # .port raises ValueError for junk like "x:alert(1)"
    except ValueError:
        return "", error
    if parts.username is not None or parts.password is not None:   # no user:pass@ tricks in links
        return "", error
    if parts.scheme not in ("http", "https") or not host or not _HOST_RE.fullmatch(host):
        return "", error
    return raw, None


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
