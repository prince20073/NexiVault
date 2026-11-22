"""Secure notes: the body is encrypted with the vault key."""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from sqlalchemy.orm.attributes import flag_modified

from extensions import db
from helpers import clean_text, current_user, login_required, safe_back, vault_unlocked
from models import SecureNote
from services import load_notes, pack_note, unpack

bp = Blueprint("notes", __name__, url_prefix="/notes")


def _owned_note(note_id: int) -> SecureNote:
    return SecureNote.query.filter_by(id=note_id, user_id=current_user().id).first_or_404()


def _read_form():
    values = {"title": clean_text(request.form.get("title"), 100),
              "content": clean_text(request.form.get("content"), 10000, multiline=True),
              "is_favorite": request.form.get("is_favorite") == "on"}
    if not values["title"]:
        return values, "A note title is required."
    if len(request.form.get("title", "").strip()) > 100:
        return values, "The note title is too long (100 characters maximum)."
    return values, None


@bp.route("/")
@login_required
@vault_unlocked
def index():
    q = request.args.get("q", "").strip()[:100]
    notes = load_notes(current_user().id)
    if q:  # note bodies are encrypted, so search happens after decryption, in memory
        needle = q.lower()
        notes = [(n, c) for n, c in notes if needle in n.title.lower() or needle in c.lower()]
    return render_template("notes.html", notes=notes, search=q)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@vault_unlocked
def add():
    values = {"title": "", "content": "", "is_favorite": False}
    if request.method == "POST":
        values, error = _read_form()
        if error:
            flash(error, "danger")
        else:
            note = SecureNote(user_id=current_user().id, title=values["title"],
                              is_favorite=values["is_favorite"], encrypted_payload=pack_note(values["content"]))
            db.session.add(note)
            db.session.commit()
            flash("Secure note saved.", "success")
            return redirect(url_for("notes.index"))
    return render_template("note_form.html", note=None, form=values)


@bp.route("/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
@vault_unlocked
def edit(note_id):
    note = _owned_note(note_id)
    values = {"title": note.title, "content": unpack(note.encrypted_payload).get("content", ""),
              "is_favorite": note.is_favorite}
    if request.method == "POST":
        values, error = _read_form()
        if error:
            flash(error, "danger")
        else:
            note.title, note.is_favorite = values["title"], values["is_favorite"]
            note.encrypted_payload = pack_note(values["content"])
            db.session.commit()
            flash("Note updated.", "success")
            return redirect(url_for("notes.index"))
    return render_template("note_form.html", note=note, form=values)


@bp.route("/<int:note_id>/delete", methods=["POST"])
@login_required
@vault_unlocked
def delete(note_id):
    note = _owned_note(note_id)
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted.", "success")
    return redirect(url_for("notes.index"))


@bp.route("/<int:note_id>/favorite", methods=["POST"])
@login_required
@vault_unlocked
def favorite(note_id):
    note = _owned_note(note_id)
    note.is_favorite = not note.is_favorite
    flag_modified(note, "updated_at")
    db.session.commit()
    flash(f"Note {'added to' if note.is_favorite else 'removed from'} favorites.", "success")
    return redirect(safe_back("notes.index"))
