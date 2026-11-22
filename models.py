from datetime import datetime, timezone

from extensions import db


def _now():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(60), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)   # scrypt hash used for sign-in
    kdf_salt = db.Column(db.LargeBinary(16), nullable=False)    # salt for deriving the vault key
    created_at = db.Column(db.DateTime, default=_now)
    last_login_at = db.Column(db.DateTime, nullable=True)

    @property
    def name(self) -> str:
        return self.display_name or self.email.split("@")[0]

    @property
    def initial(self) -> str:
        return self.name[:1].upper()


class VaultItem(db.Model):
    """A saved login. Password and notes live encrypted inside encrypted_payload."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(254), nullable=False, default="")
    website = db.Column(db.String(500), nullable=False, default="")
    category = db.Column(db.String(40), nullable=False, default="Other")
    notes = db.Column(db.Text, nullable=False, default="")  # legacy column, always empty
    is_favorite = db.Column(db.Boolean, nullable=False, default=False)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=_now)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now)
    password_changed_at = db.Column(db.DateTime, default=_now)


class SecureNote(db.Model):
    """A private note. The body is encrypted; the title stays readable so notes can be listed."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    is_favorite = db.Column(db.Boolean, nullable=False, default=False)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=_now)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now)
