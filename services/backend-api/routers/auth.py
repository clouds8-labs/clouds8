"""
Clouds8 Backend API - admin login

Single hardcoded admin credential checked against ADMIN_USERNAME/
ADMIN_PASSWORD env vars - no multi-user model, no second factor (see
docs/superpowers/specs/2026-10-04-admin-auth-design.md). This is the one
route (besides /health) exempted from the app-level auth middleware in
app.py, since the caller isn't authenticated yet when calling it.
"""
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import auth

router = APIRouter(tags=["auth"])
logger = logging.getLogger(__name__)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_at: str


@router.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "")
    auth_secret = os.getenv("AUTH_SECRET", "")

    if not expected_password:
        logger.warning("Login attempted but ADMIN_PASSWORD is not set - refusing all logins")
        raise HTTPException(401, "Invalid credentials")
    if not auth_secret:
        # A token issued while AUTH_SECRET is empty can never verify later
        # (auth.py's _verify_session_token fails closed on an empty
        # secret) - issuing one anyway would send the frontend into an
        # unverifiable-token redirect loop instead of a clear error.
        logger.warning("Login attempted but AUTH_SECRET is not set - refusing all logins")
        raise HTTPException(401, "Invalid credentials")

    valid = (
        hmac.compare_digest(req.username, expected_username)
        and hmac.compare_digest(req.password, expected_password)
    )
    if not valid:
        raise HTTPException(401, "Invalid credentials")
    token = auth.create_token(expected_username)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=auth.SESSION_TTL_SECONDS)).isoformat()
    return LoginResponse(token=token, expires_at=expires_at)
