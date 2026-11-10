"""
Authentication and request verification.

- Dashboard and API: HTTP Basic (APP_AUTH_USER / APP_AUTH_PASSWORD) or a
  bearer token (APP_API_TOKEN). Fails closed: if no password is configured
  the service refuses to start (see Settings.startup_problems).
- Repeated failed logins from one client address are throttled (429) for a
  few minutes. In-process and per worker: a brake on password guessing, not
  a replacement for network-level controls.
- State-changing browser requests must carry X-Requested-With: patch-ai.
  Browsers cannot add that header cross-site without a CORS preflight, which
  this app never grants, so a malicious page can't ride on cached Basic
  credentials (CSRF).
- Slack: v0 HMAC signature over timestamp + raw body, 5 minute window.
- Teams outgoing webhooks: HMAC-SHA256 over the raw body with the
  base64-decoded security token, sent as "Authorization: HMAC <b64>".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer

from app.config import get_settings

_basic = HTTPBasic(auto_error=False, realm="Patch Manager AI")
_bearer = HTTPBearer(auto_error=False)

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "patch-ai"

MAX_AUTH_FAILURES = 10
AUTH_FAILURE_WINDOW = 300.0  # seconds
_failures: dict[str, list[float]] = {}


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _recent_failures(key: str, now: float) -> list[float]:
    recent = [t for t in _failures.get(key, []) if now - t < AUTH_FAILURE_WINDOW]
    if recent:
        _failures[key] = recent
    else:
        _failures.pop(key, None)
    return recent


def _record_failure(key: str, now: float) -> None:
    if len(_failures) > 10_000:  # bound memory under a distributed flood
        _failures.clear()
    _failures.setdefault(key, []).append(now)


def reset_auth_failures() -> None:
    _failures.clear()


@dataclass
class Principal:
    name: str
    method: str  # basic | token | disabled


def _eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def require_user(
    request: Request,
    basic: HTTPBasicCredentials | None = Depends(_basic),
    bearer: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    s = get_settings()
    if s.app_auth_disabled:
        return Principal(name="anonymous", method="disabled")

    key, now = _client_key(request), time.monotonic()
    if len(_recent_failures(key, now)) >= MAX_AUTH_FAILURES:
        raise HTTPException(status_code=429, detail="Too many failed logins; try again later",
                            headers={"Retry-After": str(int(AUTH_FAILURE_WINDOW))})

    if bearer and s.app_api_token and bearer.scheme.lower() == "bearer":
        if _eq(bearer.credentials, s.app_api_token):
            return Principal(name="api-token", method="token")

    if basic and s.app_auth_password:
        user_ok = _eq(basic.username, s.app_auth_user)
        pass_ok = _eq(basic.password, s.app_auth_password)
        if user_ok and pass_ok:
            return Principal(name=basic.username, method="basic")

    # Count only real attempts; a browser's first request carries no credentials.
    if basic or bearer:
        _record_failure(key, now)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="Patch Manager AI"'},
    )


async def require_user_csrf(request: Request, user: Principal = Depends(require_user)) -> Principal:
    """require_user plus the anti-CSRF header for cookie/basic-auth callers."""
    if user.method == "basic" and request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
        raise HTTPException(status_code=403, detail=f"Missing {CSRF_HEADER} header")
    return user


# ─── Webhook signatures ─────────────────────────────────────────────────


def verify_slack_signature(
    signing_secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None
) -> bool:
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > 300:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_teams_hmac(secret_b64: str, body: bytes, authorization: str) -> bool:
    if not secret_b64 or not authorization.startswith("HMAC "):
        return False
    try:
        key = base64.b64decode(secret_b64)
    except (binascii.Error, ValueError):
        return False
    expected = base64.b64encode(hmac.new(key, body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(expected, authorization[5:].strip())
