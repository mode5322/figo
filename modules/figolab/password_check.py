"""One-way password verification for the awareness sign-in check.

Purpose
-------
An authorized assessor may want to prove, as evidence, that an employee typed
the *real* corporate Wi-Fi password into an unexpected/rogue sign-in page —
without ever storing, printing, or transmitting the password itself.

How it stays safe
-----------------
* The operator supplies the known real network password once, in a hidden
  prompt. Figo derives a salted **PBKDF2-HMAC-SHA256** digest and stores only
  the salt + digest in ``config.json``. The plaintext is never written.
* At submit time the participant's password is compared **in memory** against
  that digest using a constant-time check. Only the boolean result
  (``matched``) is kept. The submitted value is discarded immediately.
* No report, log line, or terminal output ever contains either password.

A PBKDF2 digest is one-way: it verifies "did the same password get typed?"
without being reversible into the password.
"""

from __future__ import annotations

import hashlib
import hmac
import os

# Cost parameters. High enough to resist offline guessing, cheap enough for a
# single interactive verification per sign-in.
_ITERATIONS = 200_000
_ALGO = "sha256"
_SALT_BYTES = 16


def hash_password(plaintext: str, *, salt: bytes | None = None) -> tuple[str, str]:
    """Return ``(salt_hex, digest_hex)`` for *plaintext*. Never stores the value."""
    if salt is None:
        salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(_ALGO, plaintext.encode("utf-8"), salt, _ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(plaintext: str, salt_hex: str, digest_hex: str) -> bool:
    """Constant-time check of *plaintext* against a stored salt + digest."""
    if not plaintext or not salt_hex or not digest_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac(_ALGO, plaintext.encode("utf-8"), salt, _ITERATIONS)
    try:
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    return hmac.compare_digest(candidate, expected)
