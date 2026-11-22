"""NexiVault - a Flask password manager (college project).

Run with:  python app.py
"""
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError

from config import Config
from extensions import csrf, db, server_session
from helpers import current_user, wants_json
from security import RateLimiter
from services import as_utc, prepare_database


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    secret = app.config.get("SECRET_KEY") or ""
    if not secret or secret.startswith("replace-") or len(secret) < 16:
        raise RuntimeError("Set a long random SECRET_KEY in your .env file before starting NexiVault "
                           "(see README.md, step 'Configure the .env file').")

    Path(app.config["SESSION_FILE_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.root_path, "instance").mkdir(exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    server_session.init_app(app)
    prepare_database(app)

    app.extensions["limiter"] = RateLimiter(app.config["MAX_LOGIN_ATTEMPTS"],
                                            app.config["LOGIN_LOCK_MINUTES"] * 60)

    from routes.account import bp as account_bp
    from routes.auth import bp as auth_bp
    from routes.main import bp as main_bp
    from routes.notes import bp as notes_bp
    from routes.tools import bp as tools_bp
    from routes.vault import bp as vault_bp
    for blueprint in (main_bp, auth_bp, vault_bp, notes_bp, tools_bp, account_bp):
        app.register_blueprint(blueprint)

    register_hooks(app)
    register_error_handlers(app)
    return app


def register_hooks(app: Flask):
    @app.template_filter("timeago")
    def timeago(dt):
        dt = as_utc(dt)
        if not dt:
            return "never"
        seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
        if seconds < 60:
            return "just now"
        for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
            if seconds >= size:
                n = seconds // size
                if unit == "day" and n >= 30:
                    return dt.strftime("%d %b %Y")
                return f"{n} {unit}{'s' if n != 1 else ''} ago"
        return "just now"

    @app.template_filter("longdate")
    def longdate(dt):
        dt = as_utc(dt)
        return dt.strftime("%d %B %Y") if dt else "-"

    @app.context_processor
    def inject_globals():
        return {"current_user": current_user(), "vault_is_unlocked": bool(session.get("vault_key")),
                "auto_lock_minutes": app.config["AUTO_LOCK_MINUTES"],
                "now_year": datetime.now(timezone.utc).year}

    @app.before_request
    def enforce_session_policy():
        """Sign out after the maximum lifetime; lock the vault after inactivity."""
        if request.endpoint == "static" or "user_id" not in session:
            return None
        now = time.time()
        if now - session.get("login_at", 0) > app.config["SESSION_MAX_HOURS"] * 3600:
            session.clear()
            if wants_json():
                return jsonify(error="Your session expired."), 401
            flash("Your session expired. Please sign in again.", "info")
            return redirect(url_for("auth.login"))
        idle = now - session.get("last_active", now)
        if session.get("vault_key") and idle > app.config["AUTO_LOCK_MINUTES"] * 60:
            session.pop("vault_key", None)
            if not wants_json():
                flash("Your vault was locked after a period of inactivity.", "info")
        session["last_active"] = now
        return None

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response


def register_error_handlers(app: Flask):
    def render_error(code, title, message):
        if wants_json():
            return jsonify(error=message), code
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(CSRFError)
    def csrf_error(_):
        if wants_json():
            return jsonify(error="Your page expired. Refresh and try again."), 400
        flash("Your form expired or was invalid. Please try again.", "danger")
        return redirect(request.referrer or url_for("main.index"))

    @app.errorhandler(404)
    def not_found(_):
        return render_error(404, "Page not found", "That page doesn't exist, or you don't have access to it.")

    @app.errorhandler(403)
    def forbidden(_):
        return render_error(403, "Access denied", "You don't have permission to view this page.")

    @app.errorhandler(413)
    def too_large(_):
        return render_error(413, "Too much data", "The submitted data is too large.")

    @app.errorhandler(500)
    def server_error(_):
        return render_error(500, "Something went wrong",
                            "An unexpected error occurred. Nothing was exposed; please try again.")


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
