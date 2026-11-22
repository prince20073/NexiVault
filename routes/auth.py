"""Register, sign in, lock/unlock and sign out."""
import re
from datetime import datetime, timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from helpers import client_key, current_user, login_required, start_session
from models import User
from security import derive_key, new_salt, password_strength

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
# Used so a missing account takes about as long to reject as a wrong password.
_DUMMY_HASH = generate_password_hash("nexivault-dummy-password", method="scrypt")


def _limiter():
    return current_app.extensions["limiter"]


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        master = request.form.get("master_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            flash("Enter a valid email address.", "danger")
        elif len(master) < 12:
            flash("Use a master password with at least 12 characters.", "danger")
        elif len(master) > 256:
            flash("That master password is too long (256 characters maximum).", "danger")
        elif password_strength(master)["score"] < 3:
            flash("Choose a stronger master password - the strength meter should read “Strong” or better. "
                  "Try a longer passphrase with mixed characters.", "danger")
        elif master != confirm:
            flash("The master passwords do not match.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
        else:
            salt = new_salt()
            user = User(email=email, password_hash=generate_password_hash(master, method="scrypt"),
                        kdf_salt=salt, last_login_at=datetime.now(timezone.utc))
            db.session.add(user)
            db.session.commit()
            start_session(user, derive_key(master, salt))
            flash("Welcome to NexiVault! Your account is ready. Keep your master password safe - it can't be recovered.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("register.html", email=request.form.get("email", ""))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        master = request.form.get("master_password", "")
        key = client_key(f"login:{email}")
        if _limiter().is_blocked(key):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
        else:
            user = User.query.filter_by(email=email).first()
            valid = check_password_hash(user.password_hash if user else _DUMMY_HASH, master) and user is not None
            if valid:
                _limiter().reset(key)
                user.last_login_at = datetime.now(timezone.utc)
                db.session.commit()
                start_session(user, derive_key(master, user.kdf_salt))
                flash(f"Welcome back, {user.name}.", "success")
                return redirect(url_for("main.dashboard"))
            _limiter().record_failure(key)
            flash("Email or master password is incorrect.", "danger")
    return render_template("login.html", email=request.form.get("email", ""))


@bp.route("/unlock", methods=["GET", "POST"])
@login_required
def unlock():
    user = current_user()
    if session.get("vault_key"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        key = client_key(f"unlock:{user.id}")
        if _limiter().is_blocked(key):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
        elif check_password_hash(user.password_hash, request.form.get("master_password", "")):
            _limiter().reset(key)
            session["vault_key"] = derive_key(request.form["master_password"], user.kdf_salt).decode("ascii")
            flash("Vault unlocked.", "success")
            return redirect(url_for("main.dashboard"))
        else:
            _limiter().record_failure(key)
            flash("That master password is incorrect.", "danger")
    return render_template("unlock.html")


@bp.route("/lock", methods=["POST"])
@login_required
def lock():
    session.pop("vault_key", None)
    flash("Vault locked. Enter your master password to unlock it again.", "info")
    return redirect(url_for("auth.unlock"))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been securely signed out.", "success")
    return redirect(url_for("main.index"))
