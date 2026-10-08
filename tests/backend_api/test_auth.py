"""
Tests for services/backend-api/auth.py. This duplicates
tests/db_service/test_auth.py's battery against the backend-api copy of
the module (the two files must stay byte-identical - see auth.py's
docstring), plus one explicit equality check to catch future drift.
"""
import os
import sys
import unittest
from unittest.mock import patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

# services/db-service/ has its own same-named `auth` module; sys.modules is
# process-global, so if that one got imported first in this pytest session
# the bare `import auth` below would silently reuse it instead of this
# service's copy. Purge first so this file always gets its own.
sys.modules.pop("auth", None)
import auth  # noqa: E402


class TestAuthModuleMatchesDbService(unittest.TestCase):
    def test_files_are_byte_identical(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        backend_api_path = os.path.join(repo_root, "services", "backend-api", "auth.py")
        db_service_path = os.path.join(repo_root, "services", "db-service", "auth.py")
        with open(backend_api_path) as f:
            backend_api_content = f.read()
        with open(db_service_path) as f:
            db_service_content = f.read()
        self.assertEqual(backend_api_content, db_service_content)


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


if __name__ == "__main__":
    unittest.main()
