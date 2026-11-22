"""Password vault: list, add, edit, delete, favorite and reveal."""
from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from sqlalchemy.orm.attributes import flag_modified

from extensions import db
from helpers import (CATEGORIES, clean_text, escape_like, login_required, normalize_website, safe_back,
                     current_user, vault_unlocked)
from models import VaultItem
from services import analyze_security, load_entries, pack_login, unpack

bp = Blueprint("vault", __name__, url_prefix="/vault")


def _owned_item(item_id: int) -> VaultItem:
    """Fetch an item only if it belongs to the signed-in user (otherwise 404)."""
    return VaultItem.query.filter_by(id=item_id, user_id=current_user().id).first_or_404()


def _read_form():
    """Validate the add/edit form. Returns (values, error_message)."""
    f = request.form
    website, website_error = normalize_website(f.get("website", ""))
    values = {
        "title": clean_text(f.get("title"), 100),
        "username": clean_text(f.get("username"), 254),
        "website": website or clean_text(f.get("website"), 500),
        "category": f.get("category") if f.get("category") in CATEGORIES else "Other",
        "password": f.get("password", ""),
        "notes": clean_text(f.get("notes"), 2000, multiline=True),
        "is_favorite": f.get("is_favorite") == "on",
    }
    if not values["title"]:
        return values, "Account name is required."
    if len(f.get("title", "").strip()) > 100:
        return values, "Account name is too long (100 characters maximum)."
    if website_error:
        return values, website_error
    if len(values["password"]) > 512:
        return values, "That password is too long (512 characters maximum)."
    return values, None


@bp.route("/")
@login_required
@vault_unlocked
def index():
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "")
    only_favorites = request.args.get("favorites") == "1"
    sort = request.args.get("sort", "updated")

    query = VaultItem.query.filter_by(user_id=current_user().id)
    if q:
        pattern = f"%{escape_like(q)}%"
        query = query.filter(db.or_(VaultItem.title.ilike(pattern, escape="\\"),
                                    VaultItem.username.ilike(pattern, escape="\\"),
                                    VaultItem.website.ilike(pattern, escape="\\")))
    if category in CATEGORIES:
        query = query.filter_by(category=category)
    if only_favorites:
        query = query.filter_by(is_favorite=True)
    order = {"name": db.func.lower(VaultItem.title).asc(), "created": VaultItem.created_at.desc()}.get(
        sort, VaultItem.updated_at.desc())
    entries = load_entries(current_user().id, query.order_by(order).all())

    # Issue badges (weak / reused) must consider the whole vault, not only the filtered rows.
    everything = load_entries(current_user().id)
    analyze_security(everything)
    issues = {e.item.id: e.issues for e in everything}
    for e in entries:
        e.issues = issues.get(e.item.id, [])
    filtered = bool(q or category or only_favorites)
    return render_template("vault.html", entries=entries, search=q, category=category, categories=CATEGORIES,
                           only_favorites=only_favorites, sort=sort, filtered=filtered)


@bp.route("/add", methods=["GET", "POST"])
@login_required
@vault_unlocked
def add():
    values = {"title": "", "username": "", "website": "", "category": "Other", "password": "",
              "notes": "", "is_favorite": request.args.get("favorite") == "1"}
    if request.method == "POST":
        values, error = _read_form()
        if error:
            flash(error, "danger")
        else:
            item = VaultItem(user_id=current_user().id, title=values["title"], username=values["username"],
                             website=values["website"], category=values["category"],
                             is_favorite=values["is_favorite"], notes="",
                             encrypted_payload=pack_login(values["password"], values["notes"]))
            db.session.add(item)
            db.session.commit()
            flash(f"“{item.title}” was saved to your encrypted vault.", "success")
            return redirect(url_for("vault.index"))
    return render_template("item_form.html", item=None, form=values, categories=CATEGORIES)


@bp.route("/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@vault_unlocked
def edit(item_id):
    item = _owned_item(item_id)
    old = unpack(item.encrypted_payload)
    values = {"title": item.title, "username": item.username, "website": item.website,
              "category": item.category, "password": old.get("password", ""),
              "notes": old.get("notes", ""), "is_favorite": item.is_favorite}
    if request.method == "POST":
        values, error = _read_form()
        if error:
            flash(error, "danger")
        else:
            item.title, item.username, item.website = values["title"], values["username"], values["website"]
            item.category, item.is_favorite = values["category"], values["is_favorite"]
            if values["password"] != old.get("password", ""):
                item.password_changed_at = datetime.now(timezone.utc)
            item.encrypted_payload = pack_login(values["password"], values["notes"])
            db.session.commit()
            flash("Changes saved.", "success")
            return redirect(url_for("tools.security_centre") if request.args.get("back") == "security"
                            else url_for("vault.index"))
    return render_template("item_form.html", item=item, form=values, categories=CATEGORIES)


@bp.route("/<int:item_id>/delete", methods=["POST"])
@login_required
@vault_unlocked
def delete(item_id):
    item = _owned_item(item_id)
    title = item.title
    db.session.delete(item)
    db.session.commit()
    flash(f"“{title}” was deleted.", "success")
    return redirect(safe_back("vault.index") if "/edit" not in (request.referrer or "") else url_for("vault.index"))


@bp.route("/<int:item_id>/favorite", methods=["POST"])
@login_required
@vault_unlocked
def favorite(item_id):
    item = _owned_item(item_id)
    item.is_favorite = not item.is_favorite
    flag_modified(item, "updated_at")  # starring something is not an "update" to the entry
    db.session.commit()
    flash(f"“{item.title}” {'added to' if item.is_favorite else 'removed from'} favorites.", "success")
    return redirect(safe_back("vault.index"))


@bp.route("/<int:item_id>/reveal", methods=["POST"])
@login_required
@vault_unlocked
def reveal(item_id):
    item = _owned_item(item_id)
    return jsonify(password=unpack(item.encrypted_payload).get("password", ""))
