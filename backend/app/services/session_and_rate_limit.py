"""
app/services/session_and_rate_limit.py

Two additive, non-cryptographic-content pieces of infrastructure:

1. Session tokens: after a client proves possession of its vault (by
   signing the server's challenge with its ML-DSA-65 key — see
   verify_signature_placeholder in main.py), the server issues a short-lived
   JWT scoped to that vault_id only. This is authorization plumbing, not
   part of the zero-knowledge boundary: the JWT never carries key material
   or plaintext, only "this bearer proved control of vault X until time Y."

2. Rate limiting: brute-force protection at the HTTP layer (independent of,
   and in addition to, the client-side VDF lockout in vdf.ts). Defends
   against high-volume automated attempts even before a client bothers
   computing a VDF proof.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Header, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

# In production, load from environment / a secrets manager — never hardcode.
JWT_SECRET = "replace-with-a-securely-generated-secret-loaded-from-env"
JWT_ALGORITHM = "HS256"
SESSION_TTL_MINUTES = 15


def issue_session_token(vault_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "vault_id": vault_id,
        "iat": now,
        "exp": now + timedelta(minutes=SESSION_TTL_MINUTES),
        "scope": "vault-session",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_session_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired. Unlock the vault again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session token.")


async def require_vault_session(
    vault_id: str,
    authorization: Optional[str] = Header(default=None),
) -> str:
    """
    FastAPI dependency: verifies the bearer token matches the vault_id in
    the URL path, so a valid session for vault A can never touch vault B.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or malformed Authorization header.")
    token = authorization.removeprefix("Bearer ").strip()
    claims = decode_session_token(token)
    if claims.get("vault_id") != vault_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Session does not grant access to this vault.")
    return vault_id


# ---------------------------------------------------------------------------
# Rate limiting (slowapi / limits, sliding-window per client IP + per vault)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

# Suggested per-route limits, applied via @limiter.limit("...") decorators
# in main.py:
#   /vault/register            -> "5/hour"        (registration abuse)
#   /vault/{id}/challenge      -> "20/minute"      (unlock attempts)
#   /vault/{id}/store          -> "60/minute"      (normal usage headroom)
#   /vault/{id}/search-encrypted -> "30/minute"
#   /vault/{id}/shred/{rid}    -> "30/minute"

_failed_attempts: dict[str, list[float]] = {}


def record_failed_unlock_attempt(vault_id: str) -> int:
    """
    Tracks failed unlock attempts server-side over a rolling 15-minute
    window, independent of the client-reported failed_unlock_attempts
    counter (which a malicious client could simply not increment).
    Returns the current count so the caller can decide on additional
    friction (e.g. requiring a longer client-side VDF before retrying).
    """
    now = time.time()
    window_start = now - 15 * 60
    attempts = [t for t in _failed_attempts.get(vault_id, []) if t > window_start]
    attempts.append(now)
    _failed_attempts[vault_id] = attempts
    return len(attempts)


def clear_failed_unlock_attempts(vault_id: str) -> None:
    _failed_attempts.pop(vault_id, None)
