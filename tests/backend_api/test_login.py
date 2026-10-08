"""
Tests for services/backend-api/routers/auth.py's POST /auth/login and the
app-level auth middleware - exercised against a minimal standalone FastAPI
app (not the real backend-api `app` module) so these tests don't need to
import collectors/playbooks or start the scheduler's background thread.
The auth logic under test is the real services/backend-api/auth.py and
routers/auth.py modules, not copies.
"""
import os
import sys
import unittest
from unittest.mock import patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

# services/db-service/ has its own same-named `auth`/`routers` modules;
# sys.modules is process-global, so if those got imported first in this
# pytest session the imports below would silently resolve to db-service's
# copies instead of this service's. Purge first so this file always gets
# its own.
for _mod_name in list(sys.modules):
    if _mod_name == "auth" or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import auth  # noqa: E402
from routers.auth import router as auth_router  # noqa: E402


def _build_test_app():
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    test_app = FastAPI()

    # Registered before CORSMiddleware below so CORS ends up outermost,
    # matching the real app.py's ordering (see that file's comment on
    # why: Starlette's add_middleware() inserts at the front of the
    # stack, so the one added LAST wraps everything added before it).
    @test_app.middleware("http")
    async def _require_auth(request, call_next):
        return await auth.auth_middleware(
            request, call_next, exempt_paths=frozenset({"/health", "/auth/login"})
        )

    test_app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @test_app.get("/health")
    def health():
        return {"status": "ok"}

    @test_app.get("/protected")
    def protected():
        return {"ok": True}

    test_app.include_router(auth_router)
    return test_app


class TestLogin(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        self.client = TestClient(_build_test_app())

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "s3cret", "AUTH_SECRET": "test-secret"},
        clear=False,
    )
    def test_correct_credentials_returns_token(self):
        resp = self.client.post("/auth/login", json={"username": "admin", "password": "s3cret"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("token", body)
        self.assertIn("expires_at", body)

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "s3cret", "AUTH_SECRET": "test-secret"},
        clear=False,
    )
    def test_wrong_password_returns_401(self):
        resp = self.client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid credentials")

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "", "AUTH_SECRET": "test-secret"},
        clear=False,
    )
    def test_login_always_fails_when_admin_password_unset(self):
        resp = self.client.post("/auth/login", json={"username": "admin", "password": ""})
        self.assertEqual(resp.status_code, 401)

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "", "AUTH_SECRET": "test-secret"},
        clear=False,
    )
    def test_login_logs_warning_when_admin_password_unset(self):
        with self.assertLogs("routers.auth", level="WARNING") as cm:
            resp = self.client.post("/auth/login", json={"username": "admin", "password": ""})
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(any("ADMIN_PASSWORD" in msg for msg in cm.output))

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "s3cret", "AUTH_SECRET": ""},
        clear=False,
    )
    def test_login_fails_when_auth_secret_unset_even_with_correct_password(self):
        # A token issued while AUTH_SECRET is empty can never verify later
        # (auth.py's _verify_session_token fails closed on an empty
        # secret) - if login still returned 200 here, the frontend would
        # store an unverifiable token, redirect to "/", immediately 401 on
        # its first data fetch, clear storage, and bounce back to
        # "/login" - forever, with no error ever surfaced.
        resp = self.client.post("/auth/login", json={"username": "admin", "password": "s3cret"})
        self.assertEqual(resp.status_code, 401)

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "s3cret", "AUTH_SECRET": ""},
        clear=False,
    )
    def test_login_logs_warning_when_auth_secret_unset(self):
        with self.assertLogs("routers.auth", level="WARNING") as cm:
            resp = self.client.post("/auth/login", json={"username": "admin", "password": "s3cret"})
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(any("AUTH_SECRET" in msg for msg in cm.output))

    @patch.dict(
        os.environ,
        {"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "s3cret", "AUTH_SECRET": "test-secret"},
        clear=False,
    )
    def test_issued_token_authenticates_a_protected_request(self):
        login_resp = self.client.post("/auth/login", json={"username": "admin", "password": "s3cret"})
        token = login_resp.json()["token"]
        resp = self.client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)

    def test_login_route_itself_requires_no_prior_auth(self):
        # No Authorization header sent. A 401 here must come from the
        # handler's own credential check ("Invalid credentials"), not the
        # middleware's generic "Unauthorized" - proving /auth/login is
        # exempt from the auth requirement it itself satisfies.
        resp = self.client.post("/auth/login", json={"username": "nope", "password": "nope"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid credentials")

    def test_protected_route_rejects_missing_header(self):
        resp = self.client.get("/protected")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Unauthorized")

    def test_cors_headers_present_on_401_response(self):
        # A browser rejects a cross-origin response that lacks
        # Access-Control-Allow-Origin, surfacing it to JS as a generic
        # network failure rather than a readable 401 - which breaks the
        # frontend's "expired token -> clear storage, redirect to /login"
        # handling. This only happens if the auth-rejecting response
        # bypasses CORSMiddleware, which depends on add_middleware order.
        resp = self.client.get(
            "/protected",
            headers={"Origin": "http://localhost:5173", "Authorization": "Bearer garbage-token"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "http://localhost:5173")


if __name__ == "__main__":
    unittest.main()
