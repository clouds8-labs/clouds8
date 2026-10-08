"""
Tests for services/db-service/auth.py - the request-authentication module
duplicated verbatim in services/backend-api/auth.py (see that module's own
docstring and docs/superpowers/specs/2026-10-04-admin-auth-design.md).
"""
import os
import sys
import unittest
from unittest.mock import patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "db-service")
)
sys.path.insert(0, _SERVICE_DIR)

# services/backend-api/ has its own same-named `auth` module; sys.modules is
# process-global, so if that one got imported first in this pytest session
# the bare `import auth` below would silently reuse it instead of this
# service's copy. Purge first so this file always gets its own.
sys.modules.pop("auth", None)
import auth  # noqa: E402


class TestCreateAndVerifyToken(unittest.TestCase):
    @patch.dict(os.environ, {"AUTH_SECRET": "test-secret"}, clear=False)
    def test_round_trip_valid_token_is_accepted(self):
        token = auth.create_token("admin")
        self.assertTrue(auth.verify_request(f"Bearer {token}"))

    @patch.dict(os.environ, {"AUTH_SECRET": "test-secret"}, clear=False)
    def test_tampered_signature_is_rejected(self):
        token = auth.create_token("admin")
        payload, sig = token.rsplit(".", 1)
        bad_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
        self.assertFalse(auth.verify_request(f"Bearer {payload}.{bad_sig}"))

    @patch.dict(os.environ, {"AUTH_SECRET": "test-secret"}, clear=False)
    def test_expired_token_is_rejected(self):
        with patch.object(auth, "time") as mock_time:
            mock_time.time.return_value = 1_000_000_000
            token = auth.create_token("admin")
        # Real clock is far past the frozen issuance time plus the 12h TTL.
        self.assertFalse(auth.verify_request(f"Bearer {token}"))

    def test_verify_fails_closed_when_auth_secret_unset(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "real-secret"}, clear=False):
            token = auth.create_token("admin")
        with patch.dict(os.environ, {"AUTH_SECRET": ""}, clear=False):
            self.assertFalse(auth.verify_request(f"Bearer {token}"))

    def test_missing_or_malformed_header_is_rejected(self):
        self.assertFalse(auth.verify_request(None))
        self.assertFalse(auth.verify_request(""))
        self.assertFalse(auth.verify_request("Basic dXNlcjpwYXNz"))
        self.assertFalse(auth.verify_request("Bearer"))

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "internal-secret-123"}, clear=False)
    def test_internal_service_token_is_accepted(self):
        self.assertTrue(auth.verify_request("Bearer internal-secret-123"))

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "internal-secret-123"}, clear=False)
    def test_wrong_internal_service_token_is_rejected(self):
        self.assertFalse(auth.verify_request("Bearer wrong-value"))


class TestAuthMiddleware(unittest.TestCase):
    def setUp(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        test_app = FastAPI()

        @test_app.middleware("http")
        async def _require_auth(request, call_next):
            return await auth.auth_middleware(request, call_next)

        @test_app.get("/health")
        def health():
            return {"status": "ok"}

        @test_app.get("/protected")
        def protected():
            return {"ok": True}

        self.client = TestClient(test_app)

    def test_health_is_exempt_without_header(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_protected_route_rejects_missing_header(self):
        resp = self.client.get("/protected")
        self.assertEqual(resp.status_code, 401)

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "internal-secret-123"}, clear=False)
    def test_protected_route_accepts_internal_token(self):
        resp = self.client.get("/protected", headers={"Authorization": "Bearer internal-secret-123"})
        self.assertEqual(resp.status_code, 200)

    def test_options_request_bypasses_auth_check(self):
        # Browser CORS preflight requests never carry an Authorization
        # header by design. If the middleware gated OPTIONS like any other
        # method, every real cross-origin browser call would fail at the
        # preflight stage before the actual request is ever sent. No
        # explicit OPTIONS handler exists for /protected, so reaching the
        # router (rather than being blocked at 401) surfaces as a 405.
        resp = self.client.options("/protected")
        self.assertEqual(resp.status_code, 405)


if __name__ == "__main__":
    unittest.main()
