"""
Authentication core — pure, stdlib-only, no DB and no framework.

AUTHN, NOT AUTHZ. OverWatch already knows what a caller may DO: `cnapp_api.Principal`
plus the `workspace_members` / `platform_admins` directory and the `_ROLE_RANK` gate.
What it has never had is a way to establish WHO the caller is — `cnapp_server` leaves
`current_principal` unset and every route 403s until a deployment injects an IdP hook.

This module is the credential half of one such hook: hashing, verification, and
session-token minting. It owns no storage and imports nothing outside the standard
library, so it is testable without a database and cannot become an egress path
(`tests/test_zero_telemetry.py`).

────────────────────────────────────────────────────────────────────────────────
THREE DECISIONS THAT ARE EASY TO GET WRONG
────────────────────────────────────────────────────────────────────────────────
1. **PBKDF2-HMAC-SHA256, not a bare hash and not bcrypt/argon2.** The wheelhouse is
   pinned and arch-portable on purpose (see `requirements.txt`), so a native
   password-hashing extension would break air-gap installs on some architectures.
   `hashlib.pbkdf2_hmac` is stdlib, has no build step, and is the same primitive the
   sibling product uses. The iteration count is stored IN the hash string, so raising
   it later re-hashes on next login instead of invalidating every password.

2. **The session table stores a FINGERPRINT, never the token.** The token is shown to
   the browser once and only its SHA-256 is persisted. A dump of `app_session` — a
   backup, a support export, a read-only SQL grant — therefore yields nothing an
   attacker can present as a live session. This is the same reason password hashes
   exist, applied to the credential that is actually sent on every request.

3. **Constant-time comparison everywhere**, including the fingerprint lookup path.
   `==` on a secret leaks its prefix through timing, and a session token is guessable
   one byte at a time if the comparison short-circuits.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple

#: Cost. Raise freely — `verify_password` reads the count from the stored string, so
#: old hashes keep verifying and `needs_rehash` reports which ones to upgrade.
PBKDF2_ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"
_SALT_BYTES = 16
_TOKEN_BYTES = 32                      # 256 bits of urandom; not a UUID (v4 has 122)

#: Deliberately modest and stated in one place. A length floor is the only password
#: rule with good evidence behind it; composition rules push people toward
#: `Password1!` and are not imposed here.
MIN_PASSWORD_LENGTH = 12


class WeakPassword(ValueError):
    """Raised on a password the policy refuses. Carries a human-readable reason."""


def check_password_policy(password: str) -> None:
    """Raise `WeakPassword` if the password is unacceptable. Silence means fine."""
    if password is None or not isinstance(password, str):
        raise WeakPassword("a password is required")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() == "":
        raise WeakPassword("a password cannot be only whitespace")


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """`pbkdf2_sha256$<iterations>$<salt-hex>$<derived-hex>`.

    Self-describing on purpose: the algorithm and cost travel WITH the hash, so the
    verifier never has to guess how an old row was produced and raising the cost is
    not a migration.
    """
    check_password_policy(password)
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify. Returns False for any malformed or unknown-algorithm
    row rather than raising: a corrupt hash must read as "wrong password", never as a
    500 that distinguishes a real account from a broken one."""
    if not password or not stored:
        return False
    try:
        algo, iters, salt_hex, want_hex = stored.split("$", 3)
        if algo != _ALGO:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), want_hex)


def needs_rehash(stored: str, *, iterations: int = PBKDF2_ITERATIONS) -> bool:
    """True when a stored hash is below the current cost, so a successful login can
    transparently upgrade it. Without this, raising the cost only protects accounts
    created afterwards."""
    try:
        algo, iters, _salt, _dk = stored.split("$", 3)
    except (ValueError, AttributeError):
        return True
    return algo != _ALGO or int(iters) < iterations


# ── session tokens ───────────────────────────────────────────────────────────

def new_session_token() -> str:
    """A fresh opaque bearer token. `token_urlsafe` draws from `os.urandom`."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def token_fingerprint(token: str) -> str:
    """What the database stores. SHA-256 is right here and PBKDF2 is not: the token is
    256 bits of urandom, so it has no guessable structure to slow an attacker down
    over, and this runs on EVERY authenticated request — a 600k-iteration KDF in that
    path would be a self-inflicted denial of service."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def tokens_match(token: str, stored_fingerprint: str) -> bool:
    """Constant-time comparison of a presented token against a stored fingerprint."""
    if not token or not stored_fingerprint:
        return False
    return hmac.compare_digest(token_fingerprint(token), stored_fingerprint)


def split_cookie(header_value: str, name: str) -> Optional[str]:
    """Pull one cookie out of a raw `Cookie:` header, or None.

    Hand-rolled because the API layer receives the header as a string and pulling in
    `http.cookies` for one lookup invites its parser quirks (it silently drops the
    whole header on a malformed pair, which would log a user out because some other
    cookie on the domain was bad).
    """
    if not header_value:
        return None
    for part in header_value.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name and value:
            return value
    return None


def parse_hash(stored: str) -> Optional[Tuple[str, int]]:
    """`(algorithm, iterations)` for diagnostics and tests. None if unparseable."""
    try:
        algo, iters, _s, _d = stored.split("$", 3)
        return (algo, int(iters))
    except (ValueError, AttributeError):
        return None
