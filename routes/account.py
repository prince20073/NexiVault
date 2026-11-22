"""Profile and account settings, including changing the master password."""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy.orm.attributes import flag_modified
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from helpers import client_key, clean_text, current_user, login_required, vault_unlocked
from models import SecureNote, VaultItem
from security import decrypt_text, derive_key, encrypt_text, new_salt, password_strength

bp = Blueprint("account", __name__, url_prefix="/settings")


@bp.route("/")
@login_required
@vault_unlocked
def settings():
    user = current_user()
    counts = {"passwords": VaultItem.query.filter_by(user_id=user.id).count(),
              "notes": SecureNote.query.filter_by(user_id=user.id).count()}
    return render_template("settings.html", counts=counts)


@bp.route("/profile", methods=["POST"])
@login_required
@vault_unlocked
def update_profile():
    current_user().display_name = clean_text(request.form.get("display_name"), 60)
    db.session.commit()
    flash("Profile updated.", "success")
    return redirect(url_for("account.settings"))


@bp.route("/password", methods=["POST"])
@login_required
@vault_unlocked
def change_password():
    """Change the master password and re-encrypt every saved item with the new key."""
    user = current_user()
    limiter = current_app.extensions["limiter"]
    key = client_key(f"chpw:{user.id}")
    current, new = request.form.get("current_password", ""), request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if limiter.is_blocked(key):
        flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
    elif not check_password_hash(user.password_hash, current):
        limiter.record_failure(key)
        flash("Your current master password is incorrect.", "danger")
    elif len(new) < 12 or len(new) > 256:
        flash("Use a new master password between 12 and 256 characters.", "danger")
    elif password_strength(new)["score"] < 3:
        flash("Choose a stronger new master password - the strength meter should read “Strong” or better.", "danger")
    elif new == current:
        flash("Your new master password must be different from the current one.", "danger")
    elif new != confirm:
        flash("The new passwords do not match.", "danger")
    else:
        limiter.reset(key)
        old_key = derive_key(current, user.kdf_salt)
        salt = new_salt()
        new_key = derive_key(new, salt)
        records = VaultItem.query.filter_by(user_id=user.id).all() + SecureNote.query.filter_by(user_id=user.id).all()
        try:
            # Decrypt everything first: if anything fails, nothing has been changed.
            plain = [(r, decrypt_text(r.encrypted_payload, old_key)) for r in records]
            for record, text in plain:
                record.encrypted_payload = encrypt_text(text, new_key)
                flag_modified(record, "updated_at")  # re-encryption is not a user edit
            user.password_hash = generate_password_hash(new, method="scrypt")
            user.kdf_salt = salt
            db.session.commit()
        except Exception:  # noqa: BLE001 - never leak details; roll back and report
            db.session.rollback()
            current_app.logger.error("Master password change failed and was rolled back.")
            flash("The master password could not be changed, and nothing was modified.", "danger")
            return redirect(url_for("account.settings"))
        session["vault_key"] = new_key.decode("ascii")
        current_app.session_interface.regenerate(session)
        flash("Master password changed. All vault data was re-encrypted with your new password.", "success")
    return redirect(url_for("account.settings"))
