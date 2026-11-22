"""Landing page, dashboard and combined favorites page."""
from datetime import datetime, timezone

from flask import Blueprint, redirect, render_template, url_for

from helpers import current_user, login_required, vault_unlocked
from models import SecureNote
from services import analyze_security, load_entries, load_notes

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    if current_user():
        return redirect(url_for("main.dashboard"))
    return render_template("landing.html")


@bp.route("/dashboard")
@login_required
@vault_unlocked
def dashboard():
    user = current_user()
    entries = load_entries(user.id)
    analysis = analyze_security(entries)
    notes_count = SecureNote.query.filter_by(user_id=user.id).count()
    favorite_notes = SecureNote.query.filter_by(user_id=user.id, is_favorite=True).count()
    floor = datetime.min.replace(tzinfo=timezone.utc)
    by_created = sorted(entries, key=lambda e: e.item.created_at or floor, reverse=True)[:5]
    by_updated = sorted(entries, key=lambda e: e.item.updated_at or floor, reverse=True)[:5]
    categories = {}
    for e in entries:
        categories[e.item.category] = categories.get(e.item.category, 0) + 1
    return render_template(
        "dashboard.html", total=len(entries), notes_count=notes_count,
        favorites_count=sum(1 for e in entries if e.item.is_favorite) + favorite_notes,
        analysis=analysis, recent_added=by_created, recent_updated=by_updated,
        categories=sorted(categories.items(), key=lambda kv: -kv[1]))


@bp.route("/favorites")
@login_required
@vault_unlocked
def favorites():
    user = current_user()
    entries = load_entries(user.id)
    analyze_security(entries)  # fills in each entry's issue badges (reused needs the whole vault)
    favorites = sorted((e for e in entries if e.item.is_favorite), key=lambda e: e.item.title.lower())
    notes = [(n, c) for n, c in load_notes(user.id) if n.is_favorite]
    return render_template("favorites.html", entries=favorites, notes=notes)
