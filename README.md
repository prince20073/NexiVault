# NexiVault - Python Password Manager

NexiVault is a Flask-based password manager with a modern dashboard. It stores logins and secure notes encrypted, generates strong passwords, and includes a Security Centre that finds weak, reused, old and missing passwords.

> **Please read:** NexiVault is a college/educational project. It has **not** been independently security-audited and is **not production-ready**. Use fictional or test data only - never your real passwords.

## Features

| Area | What you can do |
|------|-----------------|
| **Dashboard** | Totals for passwords, secure notes and favorites; security score; recently added and recently updated items; quick actions; category breakdown |
| **Password vault** | Add, edit, delete; show/hide and copy passwords; search (name, username, website); filter by category; sort; favorites; website URL, username, private notes; live strength indicator |
| **Secure notes** | Create, edit, delete, search and favorite encrypted notes |
| **Password generator** | Length 8-64, upper/lower/numbers/symbols, one-click copy, strength meter (uses Python `secrets`) |
| **Security Centre** | Weak, reused, missing and old (180+ days) passwords, overall score and recommendations |
| **Account** | Profile name, change master password (re-encrypts everything), lock vault, sign out |
| **UX** | Responsive layout (desktop / tablet / mobile), toast notifications, delete confirmation dialogs, loading states, empty states |

## Security design

- **Login hashing** - the master password is hashed with **scrypt** (Werkzeug). It is never stored.
- **Encryption** - saved passwords, private notes and secure-note bodies are encrypted with **Fernet** (AES + HMAC) using a key derived from your master password with **Scrypt** and a per-user random salt. The key is never stored in the database.
- **Secrets in `.env`** - `SECRET_KEY` and settings come from environment variables; nothing sensitive is in source code.
- **Sessions** - server-side sessions (the vault key never goes into the browser cookie), HttpOnly + SameSite cookies, session ID rotated at login, **auto-lock after 15 idle minutes** and a maximum 8-hour sign-in.
- **CSRF protection** on every form and AJAX request (Flask-WTF).
- **Access control** - every query filters by the signed-in user, so one user cannot read, edit or delete another user's data.
- **Input validation** - length limits, category whitelist, only `http`/`https` website links, control characters removed, output auto-escaped (XSS).
- **Brute-force slow-down** - 5 failed sign-ins temporarily lock that email/IP for 10 minutes.
- **Headers** - strict Content-Security-Policy (no inline scripts), `X-Frame-Options`, `nosniff`, `no-store` caching.
- **No password logging** - passwords are never written to logs; errors show generic messages.

### Known limitations (be honest in your demo)
- There is **no password recovery**: if the master password is lost, the vault cannot be decrypted.
- The unlocked key lives in the server-side session files (`.flask_session/`) while you are signed in. Protect the computer.
- Titles, usernames, websites and categories are stored **unencrypted** so they can be searched. Passwords and notes are encrypted.
- The strength meter is a heuristic estimate, not a guarantee. The login lockout is in-memory and resets when the server restarts.
- For a real deployment you would additionally need HTTPS, a production server, rate limiting at the proxy, backups, dependency updates and a professional security review.

## Run on Windows with VS Code

**Requirements:** Python 3.10 or newer (from python.org - tick *"Add Python to PATH"*) and VS Code.

1. Extract the ZIP and open the **NexiVault** folder in VS Code (*File > Open Folder*).
2. Open a terminal (*Terminal > New Terminal*, PowerShell) and create a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once and retry. In VS Code choose the `.venv` interpreter if asked.
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Create your `.env` file (see next section):
   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
5. Start the website:
   ```powershell
   python app.py
   ```
6. Open **http://127.0.0.1:5000** in your browser.

The database (`instance/nexivault.db`) and session folder are created automatically on first run - there is no separate migration step.

## Configure the `.env` file

Open `.env` in VS Code. The only **required** value is `SECRET_KEY`:

```env
SECRET_KEY=paste-the-64-character-value-printed-by-the-command-above
```

The app refuses to start while `SECRET_KEY` is missing, still says `replace-with-...`, or is shorter than 16 characters.

Optional settings (defaults shown): `AUTO_LOCK_MINUTES=15`, `SESSION_MAX_HOURS=8`, `MAX_LOGIN_ATTEMPTS=5`, `LOGIN_LOCK_MINUTES=10`, `COOKIE_SECURE=0` (use `1` only behind HTTPS), `FLASK_DEBUG=0`.

Never share or commit `.env`.

## Database and upgrading from SecureVault

- Fresh install: tables are created automatically.
- **Upgrading:** if an old `instance/securevault.db` exists and no `instance/nexivault.db` does, NexiVault **copies** it to `nexivault.db` on first start (the old file is left untouched as a backup) and adds any new columns. Existing accounts, passwords and favorites keep working with the same master passwords.
- To start completely fresh, stop the app and delete the `instance/` folder.

## Running the tests

```powershell
python -m unittest -v
```

The suite covers registration/login/logout, session protection, auto-lock, add/edit/delete, search, filters, favorites, reveal/copy endpoint, secure notes, generator, Security Centre, change-password re-encryption, CSRF, cross-user isolation, encryption-at-rest and the SecureVault database upgrade.

## Suggested demo flow

1. Register with a made-up email and a strong demo master password.
2. Add a few fictional logins (use the refresh button to generate a password). Add two with the same password.
3. Search, filter by category, favorite, reveal and copy a password.
4. Create a secure note.
5. Open **Security centre** to show weak/reused detection, then fix one.
6. Show the generator, lock the vault, unlock it, and change the master password.

## Project structure

```text
NexiVault/
├── app.py            # app factory, security headers, session policy, error pages
├── config.py         # settings (reads .env)
├── extensions.py     # db, CSRF, session objects
├── models.py         # User, VaultItem, SecureNote
├── security.py       # encryption, generator, strength score, rate limiter
├── services.py       # decrypt helpers, security analysis, DB upgrade
├── helpers.py        # login decorators, validation helpers
├── routes/           # main, auth, vault, notes, tools, account
├── templates/        # Jinja pages (+ _macros.html for icons and shared parts)
├── static/           # css/style.css, js/app.js, js/strength.js, img/favicon.svg
├── tests/test_app.py
├── requirements.txt
└── .env.example
```
