"""Automated tests for NexiVault.  Run from the project folder with:  python -m unittest -v"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only-0123456789")

from app import create_app                      # noqa: E402
from extensions import db                       # noqa: E402
from models import SecureNote, User, VaultItem  # noqa: E402
from security import (derive_key, encrypt_text, generate_password, new_salt,  # noqa: E402
                      password_strength)

MASTER = "Correct-Horse-Battery-9!"
ROOT = Path(__file__).resolve().parent.parent


class Base(unittest.TestCase):
    csrf = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True, "WTF_CSRF_ENABLED": self.csrf,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{self.tmp}/test.db",
            "LEGACY_DATABASE_FILE": Path(self.tmp) / "securevault.db",
            "SESSION_FILE_DIR": self.tmp + "/sessions",
        })
        self.c = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers -----------------------------------------------------------
    def register(self, client=None, email="student@example.com", master=MASTER):
        return (client or self.c).post("/register", data={"email": email, "master_password": master,
                                                          "confirm_password": master}, follow_redirects=True)

    def add_item(self, client=None, **kw):
        data = {"title": "Gmail", "username": "me@example.com", "website": "mail.google.com",
                "category": "Email", "password": "Xk9#mP2$vL7!qR4&", "notes": "backup code 123"}
        data.update(kw)
        return (client or self.c).post("/vault/add", data=data, follow_redirects=True)

    def item(self, title):
        with self.app.app_context():
            return VaultItem.query.filter_by(title=title).first()


class TestAuth(Base):
    def test_landing_and_branding(self):
        html = self.c.get("/").get_data(as_text=True)
        self.assertIn("NexiVault", html)
        self.assertNotIn("SecureVault", html)
        self.assertIn("nexi", html)

    def test_register_login_logout(self):
        r = self.register()
        self.assertIn("Welcome back", r.get_data(as_text=True))  # dashboard heading
        self.assertEqual(self.c.get("/dashboard").status_code, 200)
        self.c.post("/logout")
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        r = self.c.post("/login", data={"email": "student@example.com", "master_password": MASTER},
                        follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.get("/dashboard").status_code, 200)

    def test_password_is_hashed_not_stored(self):
        self.register()
        with self.app.app_context():
            user = User.query.first()
            self.assertNotIn(MASTER, user.password_hash)
            self.assertTrue(user.password_hash.startswith("scrypt:"))

    def test_register_validation(self):
        for master, confirm in [("short1A!", "short1A!"), (MASTER, MASTER + "x"), ("passwordpassword", "passwordpassword"),
                                ("Password1234", "Password1234"), ("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa")]:
            r = self.c.post("/register", data={"email": "a@b.co", "master_password": master, "confirm_password": confirm})
            self.assertEqual(r.status_code, 200)
        r = self.c.post("/register", data={"email": "not-an-email", "master_password": MASTER, "confirm_password": MASTER})
        self.assertEqual(r.status_code, 200)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 0)

    def test_duplicate_email_rejected(self):
        self.register()
        other = self.app.test_client()
        self.register(other)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    def test_wrong_password_and_unknown_user(self):
        self.register()
        self.c.post("/logout")
        for email, pw in [("student@example.com", "wrong-password-123"), ("nobody@example.com", MASTER)]:
            self.c.post("/login", data={"email": email, "master_password": pw})
            self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_login_lockout_after_repeated_failures(self):
        self.register()
        self.c.post("/logout")
        for _ in range(5):
            self.c.post("/login", data={"email": "student@example.com", "master_password": "nope-nope-nope"})
        self.c.post("/login", data={"email": "student@example.com", "master_password": MASTER})
        self.assertEqual(self.c.get("/dashboard").status_code, 302, "correct password must be blocked while locked out")

    def test_all_app_pages_require_login(self):
        for path in ["/dashboard", "/vault/", "/vault/add", "/vault/1/edit", "/favorites", "/notes/", "/notes/new",
                     "/generator", "/security", "/settings/", "/unlock"]:
            r = self.c.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers["Location"], path)
        for path in ["/vault/1/delete", "/vault/1/favorite", "/vault/1/reveal", "/notes/1/delete", "/lock",
                     "/settings/password", "/settings/profile", "/generator/api"]:
            self.assertIn(self.c.post(path).status_code, (302, 401), path)

    def test_lock_and_unlock(self):
        self.register()
        self.c.post("/lock")
        r = self.c.get("/vault/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/unlock", r.headers["Location"])
        self.c.post("/unlock", data={"master_password": "wrong-password-xyz"})
        self.assertEqual(self.c.get("/vault/").status_code, 302)
        self.c.post("/unlock", data={"master_password": MASTER})
        self.assertEqual(self.c.get("/vault/").status_code, 200)

    def test_auto_lock_after_idle(self):
        self.register()
        with self.c.session_transaction() as s:
            s["last_active"] -= 60 * 60
        r = self.c.get("/vault/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/unlock", r.headers["Location"])

    def test_session_expires_after_max_lifetime(self):
        self.register()
        with self.c.session_transaction() as s:
            s["login_at"] -= 60 * 60 * 24
        r = self.c.get("/dashboard")
        self.assertIn("/login", r.headers["Location"])

    def test_security_headers(self):
        r = self.c.get("/")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertTrue(r.headers["Set-Cookie"].count("HttpOnly") >= 1 if "Set-Cookie" in r.headers else True)

    def test_error_pages_do_not_leak(self):
        r = self.c.get("/nothing-here")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.get_data(as_text=True))


class TestVault(Base):
    def setUp(self):
        super().setUp()
        self.register()

    def test_add_edit_delete(self):
        r = self.add_item()
        self.assertIn("Gmail", r.get_data(as_text=True))
        item = self.item("Gmail")
        self.assertEqual(item.website, "https://mail.google.com")
        r = self.c.post(f"/vault/{item.id}/edit", data={"title": "Gmail Work", "username": "w@example.com",
                        "website": "https://mail.google.com", "category": "Work", "password": "N3w-Passw0rd!xyz",
                        "notes": "new note", "is_favorite": "on"}, follow_redirects=True)
        self.assertIn("Gmail Work", r.get_data(as_text=True))
        self.assertTrue(self.item("Gmail Work").is_favorite)
        edit_page = self.c.get(f"/vault/{item.id}/edit").get_data(as_text=True)
        self.assertIn("N3w-Passw0rd!xyz", edit_page)
        self.assertIn("new note", edit_page)
        r = self.c.post(f"/vault/{item.id}/delete", follow_redirects=True)
        self.assertIsNone(self.item("Gmail Work"))
        self.assertNotIn(f"/vault/{item.id}/edit", r.get_data(as_text=True))   # row is gone (toast still names it)

    def test_secrets_are_encrypted_in_database(self):
        self.add_item(password="SuperSecretValue#42x", notes="private-note-text")
        with self.app.app_context():
            blob = VaultItem.query.first().encrypted_payload
            self.assertNotIn(b"SuperSecretValue#42x", blob)
            self.assertNotIn(b"private-note-text", blob)
        raw = sqlite3.connect(f"{self.tmp}/test.db")
        dump = "\n".join(raw.iterdump())
        raw.close()
        self.assertNotIn("SuperSecretValue#42x", dump)
        self.assertNotIn("private-note-text", dump)

    def test_validation(self):
        r = self.add_item(title="  ")
        self.assertIn("Account name is required", r.get_data(as_text=True))
        for bad in ["javascript:alert(1)", "JAVASCRIPT://x", "ftp://example.com", "has space.com", "mailto:a@b.co", "https://"]:
            r = self.add_item(title="Bad", website=bad)
            self.assertIn("valid website", r.get_data(as_text=True), bad)
            self.assertIsNone(self.item("Bad"), bad)
        for good, expected in [("example.com", "https://example.com"), ("http://localhost:5000/x", "http://localhost:5000/x"),
                               ("https://sub.example.co.uk/login?a=1", "https://sub.example.co.uk/login?a=1")]:
            self.add_item(title="Good", website=good)
            self.assertEqual(self.item("Good").website, expected)
            with self.app.app_context():
                db.session.delete(VaultItem.query.filter_by(title="Good").first()); db.session.commit()
        r = self.add_item(title="X" * 101)
        with self.app.app_context():
            self.assertEqual(VaultItem.query.count(), 0)

    def test_xss_is_escaped(self):
        self.add_item(title="<script>alert(1)</script>")
        html = self.c.get("/vault/").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_search_filter_sort_favorites(self):
        self.add_item(title="Gmail", username="alice@mail.com", category="Email")
        self.add_item(title="Bank App", username="bob", website="bank.example.com", category="Banking", password="Zq8!wE3#rT6$yU1%")
        self.add_item(title="100%_Sale", category="Shopping", password="Lm5^nB2&vC9*xZ4(")
        html = self.c.get("/vault/?q=bank").get_data(as_text=True)
        self.assertIn("Bank App", html); self.assertNotIn("Gmail", html)
        html = self.c.get("/vault/?q=alice").get_data(as_text=True)
        self.assertIn("Gmail", html); self.assertNotIn("Bank App", html)
        html = self.c.get("/vault/?category=Banking").get_data(as_text=True)
        self.assertIn("Bank App", html); self.assertNotIn("Gmail", html)
        html = self.c.get("/vault/?q=100%25").get_data(as_text=True)      # LIKE wildcards are escaped
        self.assertIn("100%_Sale", html); self.assertNotIn("Bank App", html)
        html = self.c.get("/vault/?q=zzzz-none").get_data(as_text=True)
        self.assertIn("No matching passwords", html)
        bank = self.item("Bank App")
        self.c.post(f"/vault/{bank.id}/favorite")
        html = self.c.get("/vault/?favorites=1").get_data(as_text=True)
        self.assertIn("Bank App", html); self.assertNotIn("Gmail", html)
        fav_page = self.c.get("/favorites").get_data(as_text=True)
        self.assertIn("Bank App", fav_page); self.assertNotIn("Gmail", fav_page)
        self.c.post(f"/vault/{bank.id}/favorite")
        self.assertFalse(self.item("Bank App").is_favorite)
        names = self.c.get("/vault/?sort=name").get_data(as_text=True)
        self.assertLess(names.index("100%_Sale"), names.index("Bank App"))

    def test_favorite_toggle_keeps_updated_at(self):
        self.add_item()
        before = self.item("Gmail").updated_at
        self.c.post(f"/vault/{self.item('Gmail').id}/favorite")
        self.assertEqual(self.item("Gmail").updated_at, before)

    def test_reveal_returns_password_post_only(self):
        self.add_item(password="RevealMe#12345xyz")
        iid = self.item("Gmail").id
        self.assertEqual(self.c.get(f"/vault/{iid}/reveal").status_code, 405)
        r = self.c.post(f"/vault/{iid}/reveal", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(r.get_json()["password"], "RevealMe#12345xyz")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_reveal_when_locked_returns_401_json(self):
        self.add_item()
        iid = self.item("Gmail").id
        self.c.post("/lock")
        r = self.c.post(f"/vault/{iid}/reveal", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(r.status_code, 401)
        self.assertTrue(r.get_json()["locked"])

    def test_item_without_password_allowed(self):
        self.add_item(title="Empty one", password="")
        self.assertIsNotNone(self.item("Empty one"))

    def test_dashboard_counts_and_recent(self):
        self.add_item(title="First", password="Aa1!Bb2@Cc3#Dd4$")
        self.add_item(title="Second", password="Ee5%Ff6^Gg7&Hh8*", is_favorite="on")
        self.c.post("/notes/new", data={"title": "Wifi", "content": "abc", "is_favorite": "on"})
        html = self.c.get("/dashboard").get_data(as_text=True)
        self.assertIn("Recently added", html); self.assertIn("Recently updated", html)
        self.assertIn("First", html); self.assertIn("Second", html)
        nums = re.findall(r'<div class="stat-number">(\d+)', html)
        self.assertEqual(nums[:3], ["2", "1", "2"])   # passwords, notes, favorites (1 password + 1 note)


class TestIsolation(Base):
    def test_users_cannot_access_each_others_data(self):
        self.register(email="alice@example.com")
        self.add_item(title="AliceSecret", password="AliceOnly#9876xyz")
        self.c.post("/notes/new", data={"title": "AliceNote", "content": "alice private"})
        alice_item = self.item("AliceSecret").id
        with self.app.app_context():
            alice_note = SecureNote.query.first().id

        bob = self.app.test_client()
        self.register(bob, email="bob@example.com", master="Another-Strong-Pass-77")
        self.assertNotIn("AliceSecret", bob.get("/vault/").get_data(as_text=True))
        self.assertNotIn("AliceNote", bob.get("/notes/").get_data(as_text=True))
        self.assertEqual(bob.get(f"/vault/{alice_item}/edit").status_code, 404)
        self.assertEqual(bob.post(f"/vault/{alice_item}/reveal").status_code, 404)
        self.assertEqual(bob.post(f"/vault/{alice_item}/delete").status_code, 404)
        self.assertEqual(bob.post(f"/vault/{alice_item}/favorite").status_code, 404)
        self.assertEqual(bob.get(f"/notes/{alice_note}/edit").status_code, 404)
        self.assertEqual(bob.post(f"/notes/{alice_note}/delete").status_code, 404)
        self.assertIsNotNone(self.item("AliceSecret"))


class TestNotes(Base):
    def setUp(self):
        super().setUp()
        self.register()

    def test_note_crud_encryption_and_search(self):
        r = self.c.post("/notes/new", data={"title": "Wi-Fi", "content": "router-password-ZZZ"}, follow_redirects=True)
        self.assertIn("Wi-Fi", r.get_data(as_text=True))
        with self.app.app_context():
            note = SecureNote.query.first()
            self.assertNotIn(b"router-password-ZZZ", note.encrypted_payload)
            nid = note.id
        self.assertIn("router-password-ZZZ", self.c.get(f"/notes/{nid}/edit").get_data(as_text=True))
        self.assertIn("Wi-Fi", self.c.get("/notes/?q=zzz").get_data(as_text=True))
        self.assertIn("No matching notes", self.c.get("/notes/?q=nothing-matches").get_data(as_text=True))
        self.c.post(f"/notes/{nid}/edit", data={"title": "Wi-Fi 2", "content": "changed", "is_favorite": "on"})
        self.assertIn("Wi-Fi 2", self.c.get("/favorites").get_data(as_text=True))
        self.c.post(f"/notes/{nid}/favorite")
        self.assertNotIn("Wi-Fi 2", self.c.get("/favorites").get_data(as_text=True))
        self.c.post(f"/notes/{nid}/delete")
        with self.app.app_context():
            self.assertEqual(SecureNote.query.count(), 0)

    def test_note_requires_title(self):
        r = self.c.post("/notes/new", data={"title": "", "content": "x"})
        self.assertIn("title is required", r.get_data(as_text=True))


class TestTools(Base):
    def setUp(self):
        super().setUp()
        self.register()

    def test_generator_function(self):
        for _ in range(50):
            pw = generate_password(24, True, True, True, True)
            self.assertEqual(len(pw), 24)
            self.assertTrue(re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw) and re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw))
        self.assertTrue(generate_password(30, False, False, True, False).isdigit())
        self.assertNotEqual(generate_password(20), generate_password(20))
        for bad in [(7,), (65,)]:
            with self.assertRaises(ValueError):
                generate_password(*bad)
        with self.assertRaises(ValueError):
            generate_password(20, False, False, False, False)

    def test_generator_api_and_page(self):
        r = self.c.post("/generator/api", json={"length": 32, "upper": True, "lower": True, "digits": False, "symbols": False})
        data = r.get_json()
        self.assertEqual(len(data["password"]), 32)
        self.assertTrue(data["password"].isalpha())
        self.assertIn("score", data["strength"])
        self.assertEqual(self.c.post("/generator/api", json={"length": 4, "upper": True}).status_code, 400)
        self.assertEqual(self.c.post("/generator/api", json={"length": 20}).status_code, 400)
        self.assertEqual(self.c.post("/generator/api", json={"length": "abc", "upper": True}).status_code, 400)
        page = self.c.get("/generator").get_data(as_text=True)
        self.assertIn("Password generator", page)
        r = self.c.post("/generator", data={"length": "16", "upper": "on", "digits": "on"})   # no-JS fallback
        self.assertEqual(r.status_code, 200)
        self.assertIn('value="16"', r.get_data(as_text=True))

    def test_strength_scoring(self):
        self.assertEqual(password_strength("password")["score"], 0)
        self.assertEqual(password_strength("Password1")["score"], 0)
        self.assertLessEqual(password_strength("abc12345")["score"], 1)
        self.assertGreaterEqual(password_strength("Xk9#mP2$vL7!qR4&")["score"], 3)
        self.assertEqual(password_strength("")["score"], 0)
        for guessable in ["Prince@123", "Sharma@2007", "Summer2024!", "P@ssw0rd123", "Welcome@1", "India@123", "Test@1234"]:
            self.assertLessEqual(password_strength(guessable)["score"], 1, guessable)
        for good in ["Correct-Horse-Battery-9!", "Xk9#mP2$vL7!qR4&", "my dog spot loves the river bank"]:
            self.assertGreaterEqual(password_strength(good)["score"], 3, good)

    def test_security_centre(self):
        html = self.c.get("/security").get_data(as_text=True)
        self.assertIn("Nothing to check yet", html)
        self.add_item(title="Weak1", password="password")
        self.add_item(title="Reuse A", password="Shared-Pass-Value#2024x")
        self.add_item(title="Reuse B", password="Shared-Pass-Value#2024x")
        self.add_item(title="Missing", password="")
        self.add_item(title="Good", password="Qw8!eR5@tY2#uI9$oP")
        html = self.c.get("/security").get_data(as_text=True)
        self.assertIn("Weak passwords", html)
        self.assertIn("Reused passwords", html)
        self.assertIn("Entries without a password", html)
        self.assertIn("2 accounts share a password", html)
        self.assertIn("Replace 1 weak password", html)
        stat = re.findall(r'<div class="stat-number">(\d+)', html)
        self.assertEqual(stat, ["1", "2", "1", "0"])            # weak, reused, missing, old
        self.assertIn("1 of 5 entry", html.replace("entries have", "entry"))  # only 'Good' is healthy

    def test_old_password_detected(self):
        from datetime import datetime, timedelta, timezone
        self.add_item(title="Ancient", password="Qw8!eR5@tY2#uI9$oP")
        with self.app.app_context():
            item = VaultItem.query.filter_by(title="Ancient").first()
            item.password_changed_at = datetime.now(timezone.utc) - timedelta(days=400)
            db.session.commit()
        self.assertIn("Old passwords", self.c.get("/security").get_data(as_text=True))


class TestAccount(Base):
    def setUp(self):
        super().setUp()
        self.register()
        self.add_item(title="Keep Me", password="KeepThisSecret#555x", notes="n1")
        self.c.post("/notes/new", data={"title": "KeepNote", "content": "note-body-xyz"})

    def test_profile_update(self):
        self.c.post("/settings/profile", data={"display_name": "Prince"})
        self.assertIn("Prince", self.c.get("/settings/").get_data(as_text=True))

    def test_change_password_reencrypts_everything(self):
        new = "Brand-New-Master-Pw-2026"
        r = self.c.post("/settings/password", data={"current_password": "wrong-current-pw1", "new_password": new, "confirm_password": new}, follow_redirects=True)
        self.assertIn("current master password is incorrect", r.get_data(as_text=True))
        r = self.c.post("/settings/password", data={"current_password": MASTER, "new_password": "short", "confirm_password": "short"}, follow_redirects=True)
        self.assertIn("between 12 and 256", r.get_data(as_text=True))
        r = self.c.post("/settings/password", data={"current_password": MASTER, "new_password": new, "confirm_password": new + "x"}, follow_redirects=True)
        self.assertIn("do not match", r.get_data(as_text=True))
        r = self.c.post("/settings/password", data={"current_password": MASTER, "new_password": new, "confirm_password": new}, follow_redirects=True)
        self.assertIn("Master password changed", r.get_data(as_text=True))
        # still readable in the same session
        iid = self.item("Keep Me").id
        self.assertEqual(self.c.post(f"/vault/{iid}/reveal").get_json()["password"], "KeepThisSecret#555x")
        # old password no longer works; new one decrypts everything
        self.c.post("/logout")
        self.c.post("/login", data={"email": "student@example.com", "master_password": MASTER})
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        self.c.post("/login", data={"email": "student@example.com", "master_password": new})
        self.assertEqual(self.c.post(f"/vault/{iid}/reveal").get_json()["password"], "KeepThisSecret#555x")
        with self.app.app_context():
            nid = SecureNote.query.first().id
        self.assertIn("note-body-xyz", self.c.get(f"/notes/{nid}/edit").get_data(as_text=True))


class TestCSRF(Base):
    csrf = True

    def token(self, path="/login"):
        return re.search(r'name="csrf-token" content="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)

    def test_post_without_token_is_rejected(self):
        r = self.c.post("/register", data={"email": "a@example.com", "master_password": MASTER, "confirm_password": MASTER})
        self.assertEqual(r.status_code, 302)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 0)

    def test_post_with_token_works_and_json_header_token(self):
        t = self.token("/register")
        self.c.post("/register", data={"csrf_token": t, "email": "a@example.com", "master_password": MASTER, "confirm_password": MASTER})
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)
        t = self.token("/dashboard")
        r = self.c.post("/generator/api", json={"length": 12, "upper": True}, headers={"X-CSRFToken": t})
        self.assertEqual(r.status_code, 200)
        r = self.c.post("/generator/api", json={"length": 12, "upper": True})
        self.assertEqual(r.status_code, 400)


class TestLegacyMigration(unittest.TestCase):
    def test_old_securevault_database_is_migrated(self):
        tmp = tempfile.mkdtemp()
        legacy = Path(tmp) / "securevault.db"
        salt = new_salt()
        key = derive_key(MASTER, salt)
        from werkzeug.security import generate_password_hash
        con = sqlite3.connect(legacy)
        con.executescript("""
            CREATE TABLE user (id INTEGER PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL,
                               kdf_salt BLOB NOT NULL, created_at DATETIME);
            CREATE TABLE vault_item (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title VARCHAR(100) NOT NULL,
                username VARCHAR(254) NOT NULL DEFAULT '', website VARCHAR(500) NOT NULL DEFAULT '',
                category VARCHAR(40) NOT NULL DEFAULT 'Other', notes TEXT NOT NULL DEFAULT '', is_favorite BOOLEAN NOT NULL DEFAULT 0,
                encrypted_payload BLOB NOT NULL, created_at DATETIME, updated_at DATETIME);
        """)
        con.execute("INSERT INTO user VALUES (1,'old@example.com',?,?,'2025-01-01 00:00:00')",
                    (generate_password_hash(MASTER, method="scrypt"), salt))
        con.execute("INSERT INTO vault_item VALUES (1,1,'Old Site','u','','Other','',0,?, '2025-01-01 00:00:00','2025-02-01 00:00:00')",
                    (encrypt_text(json.dumps({"password": "OldPassword#123abc", "notes": ""}), key),))
        con.commit(); con.close()

        app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp}/nexivault.db",
                          "LEGACY_DATABASE_FILE": legacy, "SESSION_FILE_DIR": tmp + "/s"})
        c = app.test_client()
        c.post("/login", data={"email": "old@example.com", "master_password": MASTER})
        html = c.get("/vault/").get_data(as_text=True)
        self.assertIn("Old Site", html)
        r = c.post("/vault/1/reveal")
        self.assertEqual(r.get_json()["password"], "OldPassword#123abc")
        self.assertIn("Security centre", c.get("/security").get_data(as_text=True))
        self.assertTrue(legacy.exists(), "legacy file must be left untouched as a backup")
        with app.app_context():
            db.session.remove(); db.engine.dispose()
        shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(shutil.which("node"), "Node.js not available")
class TestStrengthParity(unittest.TestCase):
    def test_python_and_javascript_agree(self):
        samples = ["", "a", "password", "Password1", "abcd1234", "aaaaaaaaaaaa", "1234567890", "Tr0ub4dor&3", "correct horse battery staple",
                   "Xk9#mP2$vL7!qR4&", "qwerty123!", "Zq8!wE3#rT6$yU1%aB", "héllo wörld 123", "ABCDEFGHIJKL", "Ab1!", "letmein!!!", "😀😀😀😀😀😀😀😀😀😀😀😀", "Prince@123", "P@ssw0rd123", "Summer2024!", "India@123", "Welcome@1", "Test@1234", "😀abc😀😀😀😀"]
        js = ("global.window={};eval(require('fs').readFileSync('static/js/strength.js','utf8'));"
              "const s=JSON.parse(require('fs').readFileSync(0,'utf8'));"
              "console.log(JSON.stringify(s.map(p=>window.NVStrength.evaluate(p))));")
        out = subprocess.run(["node", "-e", js], input=json.dumps(samples), capture_output=True, text=True, cwd=ROOT, check=True)
        js_results = json.loads(out.stdout)
        for sample, js_r in zip(samples, js_results):
            self.assertEqual(password_strength(sample), js_r, f"mismatch for {sample!r}")


if __name__ == "__main__":
    unittest.main()
