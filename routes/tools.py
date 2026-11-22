"""Password generator and Security Centre."""
from flask import Blueprint, flash, jsonify, render_template, request

from helpers import current_user, login_required, vault_unlocked
from security import generate_password, password_strength
from services import analyze_security, load_entries

bp = Blueprint("tools", __name__)


def _generate_from(data):
    """data: any mapping with length/upper/lower/digits/symbols. Raises ValueError on bad input."""
    try:
        length = int(data.get("length", 20))
    except (TypeError, ValueError):
        raise ValueError("Password length must be a number between 8 and 64.")
    return generate_password(length=length, upper=bool(data.get("upper")), lower=bool(data.get("lower")),
                             digits=bool(data.get("digits")), symbols=bool(data.get("symbols")))


@bp.route("/generator", methods=["GET", "POST"])
@login_required
@vault_unlocked
def generator():
    generated, options = "", {"length": 20, "upper": True, "lower": True, "digits": True, "symbols": True}
    if request.method == "POST":  # works without JavaScript too
        form = {"length": request.form.get("length", 20), "upper": request.form.get("upper") == "on",
                "lower": request.form.get("lower") == "on", "digits": request.form.get("digits") == "on",
                "symbols": request.form.get("symbols") == "on"}
        try:
            generated = _generate_from(form)
            options = {**form, "length": int(form["length"])}
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("generator.html", generated=generated, options=options,
                           strength=password_strength(generated) if generated else None)


@bp.route("/generator/api", methods=["POST"])
@login_required
@vault_unlocked
def generate_api():
    data = request.get_json(silent=True) or {}
    try:
        password = _generate_from(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(password=password, strength=password_strength(password))


@bp.route("/security")
@login_required
@vault_unlocked
def security_centre():
    entries = load_entries(current_user().id)
    return render_template("security.html", analysis=analyze_security(entries))
