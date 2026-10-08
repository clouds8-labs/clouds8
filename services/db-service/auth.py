"""
Clouds8 - shared request authentication

Duplicated verbatim in services/db-service/ and services/backend-api/ (see
docs/superpowers/specs/2026-10-04-admin-auth-design.md) - the two services
don't share a Python package across their separate Docker build contexts,
so this module is copied rather than factored into a shared package for
this. Keep both copies byte-identical.

Every request must carry `Authorization: Bearer <value>`, accepted if the
value is either the fixed INTERNAL_SERVICE_TOKEN (server-to-server
callers: Dash UI, lynxctl, sync.py, seed_data.py, backend-api's own calls
into db-service) or a signed, unexpired session token issued by
backend-api's POST /auth/login.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import FrozenSet, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

SESSION_TTL_SECONDS = 12 * 60 * 60


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def create_token(username: str) -> str:
    secret = os.getenv("AUTH_SECRET", "")
    payload = _b64url_encode(
        json.dumps({"sub": username, "exp": int(time.time()) + SESSION_TTL_SECONDS}).encode()
    )
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_session_token(token: str) -> bool:
    secret = os.getenv("AUTH_SECRET", "")
    if not secret:
        return False
    try:
        payload_b64, sig = token.rsplit(".", 1)
    except ValueError:
        return False
    expected_sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return False
    return payload.get("exp", 0) > time.time()


def verify_request(authorization_header: Optional[str]) -> bool:
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return False
    token = authorization_header[len("Bearer "):]
    internal_token = os.getenv("INTERNAL_SERVICE_TOKEN", "")
    if internal_token and hmac.compare_digest(token, internal_token):
        return True
    return _verify_session_token(token)


async def auth_middleware(request: Request, call_next, exempt_paths: FrozenSet[str] = frozenset({"/health"})):
    # Browser CORS preflight requests never carry credentials by design, and
    # must reach CORSMiddleware regardless of the two add_middleware calls'
    # relative order in each service's app.py (Starlette's add_middleware
    # inserts at the front of the stack, so the middleware added LAST ends
    # up outermost - relying on getting that order right is fragile; always
    # passing OPTIONS through is not).
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in exempt_paths:
        return await call_next(request)
    if not verify_request(request.headers.get("authorization")):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)
