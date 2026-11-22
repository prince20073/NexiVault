"""Vault logic shared by several pages: decryption, security analysis and database upgrades."""
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, session
from sqlalchemy import inspect, text

from extensions import db
from models import SecureNote, VaultItem
from security import decrypt_text, encrypt_text, password_strength

OLD_PASSWORD_DAYS = 180


# ------------------------------------------------------------------ database upgrade
def prepare_database(app):
    """Create tables, copy a legacy SecureVault database if present, and add any new columns."""
    with app.app_context():
        new_path = Path(db.engine.url.database)
        legacy = Path(app.config["LEGACY_DATABASE_FILE"])
        if legacy.exists() and not new_path.exists():
            shutil.copy2(legacy, new_path)  # keep the old file untouched as a backup
        db.create_all()
        _add_missing_columns()


def _add_missing_columns():
    wanted = {
        "user": [("display_name", "VARCHAR(60) NOT NULL DEFAULT ''"), ("last_login_at", "DATETIME")],
        "vault_item": [("password_changed_at", "DATETIME")],
    }
    inspector = inspect(db.engine)
    with db.engine.begin() as conn:
        for table, columns in wanted.items():
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {name} {ddl}'))
                    if name == "password_changed_at":
                        conn.execute(text("UPDATE vault_item SET password_changed_at = COALESCE(updated_at, created_at)"))


# ------------------------------------------------------------------ encryption helpers
def vault_key() -> bytes:
    return session["vault_key"].encode("ascii")


def pack_login(password: str, notes: str) -> bytes:
    return encrypt_text(json.dumps({"password": password, "notes": notes}), vault_key())


def pack_note(content: str) -> bytes:
    return encrypt_text(json.dumps({"content": content}), vault_key())


def unpack(token: bytes) -> dict:
    """Decrypt a payload. Unreadable data is treated as empty rather than crashing the page."""
    try:
        return json.loads(decrypt_text(token, vault_key()))
    except (ValueError, json.JSONDecodeError):
        current_app.logger.warning("A vault record could not be decrypted.")
        return {}


def as_utc(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


# ------------------------------------------------------------------ entries and analysis
@dataclass
class Entry:
    item: VaultItem
    password: str
    notes: str
    strength: dict
    issues: list = field(default_factory=list)


def load_entries(user_id: int, items=None) -> list[Entry]:
    if items is None:
        items = VaultItem.query.filter_by(user_id=user_id).all()
    entries = []
    for item in items:
        data = unpack(item.encrypted_payload)
        password = data.get("password", "")
        entries.append(Entry(item, password, data.get("notes", ""), password_strength(password)))
    return entries


def load_notes(user_id: int):
    """Return [(note, content)] for the user, newest first."""
    notes = SecureNote.query.filter_by(user_id=user_id).order_by(SecureNote.updated_at.desc()).all()
    return [(n, unpack(n.encrypted_payload).get("content", "")) for n in notes]


def analyze_security(entries: list[Entry]) -> dict:
    now = datetime.now(timezone.utc)
    groups = {}
    for e in entries:
        if e.password:
            groups.setdefault(e.password, []).append(e)
    reused_groups = [g for g in groups.values() if len(g) > 1]
    reused_ids = {e.item.id for g in reused_groups for e in g}

    for e in entries:
        e.issues = []
        if not e.password:
            e.issues.append("missing")
            continue
        if e.strength["score"] < 3:   # below "Strong" (under 60 bits)
            e.issues.append("weak")
        if e.item.id in reused_ids:
            e.issues.append("reused")
        changed = as_utc(e.item.password_changed_at or e.item.updated_at or e.item.created_at)
        if changed and (now - changed).days > OLD_PASSWORD_DAYS:
            e.issues.append("old")

    weak = [e for e in entries if "weak" in e.issues]
    missing = [e for e in entries if "missing" in e.issues]
    old = [e for e in entries if "old" in e.issues]
    healthy = [e for e in entries if not e.issues]
    total = len(entries)
    score = round(100 * len(healthy) / total) if total else None

    recommendations = []
    if weak:
        recommendations.append(("danger", f"Replace {len(weak)} weak password{'s' if len(weak) != 1 else ''}",
                                "Use the generator to create long, random replacements."))
    if reused_groups:
        count = sum(len(g) for g in reused_groups)
        recommendations.append(("danger", f"Stop reusing passwords ({count} accounts affected)",
                                "If one site is breached, every account sharing that password is at risk."))
    if missing:
        recommendations.append(("warning", f"Add a password to {len(missing)} incomplete "
                                f"entr{'ies' if len(missing) != 1 else 'y'}", "Entries without a password can't protect anything."))
    if old:
        recommendations.append(("warning", f"Refresh {len(old)} password{'s' if len(old) != 1 else ''} older than "
                                f"{OLD_PASSWORD_DAYS} days", "Rotating important passwords limits long-term exposure."))
    if total and not recommendations:
        recommendations.append(("success", "Your vault looks healthy",
                                "Keep using unique, random passwords and turn on two-factor authentication where possible."))
    if total:
        recommendations.append(("info", "Turn on two-factor authentication",
                                "Even a strong password is safer with a second sign-in step on important accounts."))

    if score is None:
        grade = "No data"
    elif score >= 90:
        grade = "Excellent"
    elif score >= 70:
        grade = "Good"
    elif score >= 40:
        grade = "Needs attention"
    else:
        grade = "At risk"
    return {"total": total, "score": score, "grade": grade, "weak": weak, "missing": missing, "old": old,
            "reused_groups": reused_groups, "reused_count": len(reused_ids), "healthy": healthy,
            "recommendations": recommendations}
