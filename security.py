"""Cryptography, password generation, strength scoring and login throttling."""
import base64
import math
import re
import secrets
import string
import threading
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# ---------------------------------------------------------------- encryption
def new_salt() -> bytes:
    return secrets.token_bytes(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte vault key from the master password using Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_text(text: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(text.encode("utf-8"))


def decrypt_text(token: bytes, key: bytes) -> str:
    try:
        return Fernet(key).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Could not unlock this vault. Check your master password.") from exc


# ---------------------------------------------------------------- generator
def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
    groups = []
    if upper:
        groups.append(string.ascii_uppercase)
    if lower:
        groups.append(string.ascii_lowercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append(SYMBOLS)
    if not groups:
        raise ValueError("Select at least one character type.")
    length = int(length)
    if not 8 <= length <= 64:
        raise ValueError("Password length must be between 8 and 64.")
    chars = [secrets.choice(group) for group in groups]  # at least one of each chosen type
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------- strength
# Keep COMMON_PASSWORDS and the scoring rules in sync with static/js/strength.js
COMMON_PASSWORDS = {
    "password", "passw0rd", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwertyuiop",
    "abc123", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "baseball",
    "login", "master", "sunshine", "princess", "shadow", "superman", "trustno1", "whatever",
    "changeme", "secret", "default", "111111", "000000", "asdfgh", "zxcvbn", "starwars", "hello",
}
STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "l", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"})
# A single word with a few digits/symbols around it (Prince@123, Summer2024!) is a pattern attackers try first.
_WORD_PLUS_SUFFIX = re.compile(r"[^A-Za-z]{0,3}[A-Za-z]{3,10}[^A-Za-z]{0,6}")


def _sequence_runs(password: str) -> int:
    """Count runs of 4+ repeated or consecutive characters (aaaa, 1234, abcd)."""
    runs, i, n = 0, 0, len(password)
    while i < n - 3:
        step = ord(password[i + 1]) - ord(password[i])
        if step in (0, 1, -1):
            j = i + 1
            while j < n and ord(password[j]) - ord(password[j - 1]) == step:
                j += 1
            if j - i >= 4:
                runs += 1
                i = j
                continue
        i += 1
    return runs


def password_strength(password: str) -> dict:
    """Return {'score': 0-4, 'label': str, 'bits': int}. A heuristic estimate, not a guarantee."""
    if not password:
        return {"score": 0, "label": STRENGTH_LABELS[0], "bits": 0}
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"[0-9]", password) else 0
    pool += 33 if re.search(r"[^A-Za-z0-9]", password) else 0
    unique = len(set(password))
    effective = unique + 0.3 * (len(password) - unique)
    bits = effective * math.log2(max(pool, 2))
    bits -= 6 * min(_sequence_runs(password), 3)
    base = re.sub(r"[0-9!@#$%^&*()\-_=+.?]+$", "", password.lower())
    lower = password.lower()
    if (lower in COMMON_PASSWORDS or base in COMMON_PASSWORDS
            or lower.translate(_LEET) in COMMON_PASSWORDS or base.translate(_LEET) in COMMON_PASSWORDS):
        bits = min(bits, 10)
    elif _WORD_PLUS_SUFFIX.fullmatch(password):
        bits = min(bits, 35)
    bits = max(int(bits), 0)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    return {"score": score, "label": STRENGTH_LABELS[score], "bits": bits}


# ---------------------------------------------------------------- throttling
class RateLimiter:
    """Tiny in-memory failed-attempt limiter (resets when the server restarts)."""

    def __init__(self, max_attempts=5, window_seconds=600):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures = {}
        self._lock = threading.Lock()

    def _recent(self, key):
        cutoff = time.time() - self.window
        recent = [t for t in self._failures.get(key, []) if t > cutoff]
        self._failures[key] = recent
        return recent

    def is_blocked(self, key) -> bool:
        with self._lock:
            return len(self._recent(key)) >= self.max_attempts

    def record_failure(self, key) -> None:
        with self._lock:
            self._recent(key).append(time.time())

    def reset(self, key) -> None:
        with self._lock:
            self._failures.pop(key, None)
