"""Verify a submitted Wi-Fi password against the authorized target network PSK.

The reference PSK is supplied by the operator at lab start (never written to
reports or config files). Submitted values are compared in memory only and
discarded immediately after the check.
"""

from __future__ import annotations

import secrets


def verify_target_password(submitted: str, reference: str) -> bool:
    """Return True when *submitted* matches the operator-provided reference PSK."""
    if not reference:
        return False
    submitted = (submitted or "").strip()
    reference = (reference or "").strip()
    if not submitted or not reference:
        return False
    return secrets.compare_digest(submitted, reference)
