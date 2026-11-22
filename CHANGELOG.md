# Changelog

## NexiVault 2.0.1
- Security centre: detects guessable "word + numbers/symbol" passwords (e.g. Prince@123), leetspeak versions of common passwords, and treats anything below "Strong" as weak. "Fix" links now return to the Security centre.
- Secure notes: line breaks are preserved in note previews.
- Notifications no longer cover the top bar buttons.

## NexiVault 2.0
- Complete UI redesign: SaaS-style dashboard, SVG icons, toasts, confirm dialogs, loading and empty states, responsive layout with mobile menu.
- New: secure notes, Security Centre, profile & settings, change master password (re-encrypts all data), lock vault, auto-lock, password strength meters.
- Generator now updates live and shows strength; passwords may be generated straight into the add/edit form.
- Dashboard: totals, favorites, security score, recently added/updated, quick actions, categories.
- Security: Content-Security-Policy, login lockout, session ID rotation, idle auto-lock, POST-only reveal endpoint, stricter master-password rules, URL validation, LIKE-wildcard escaping, safe redirects, generic error pages.
- Sign-in now unlocks the vault directly (no second master-password prompt); the unlock page appears only after locking/idle timeout.
- Project reorganised into blueprints; automatic copy/upgrade of the old `securevault.db`.
- Added automated test suite.
- Rebranded everything to NexiVault (including the logo mark, which previously showed "S").

This remains a student demonstration project, not an audited production password manager.
