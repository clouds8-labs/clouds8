"""
Confirms the three server-to-server httpx.Client singletons (the entire
surface of non-browser callers in this codebase - see
docs/superpowers/specs/2026-10-04-admin-auth-design.md) send
INTERNAL_SERVICE_TOKEN on every request, so Dash UI, lynxctl, sync.py and
seed_data.py keep working once db-service/backend-api require auth.
"""
import importlib
import os
import sys
import unittest
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestInternalServiceTokenHeaders(unittest.TestCase):
    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-token-xyz"}, clear=False)
    def test_db_database_client_carries_internal_token(self):
        import db.database as dbmod

        importlib.reload(dbmod)
        self.assertEqual(dbmod._client.headers.get("authorization"), "Bearer test-token-xyz")

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-token-xyz"}, clear=False)
    def test_shared_db_client_carries_internal_token(self):
        import shared.client.db_client as dbclientmod

        importlib.reload(dbclientmod)
        self.assertEqual(dbclientmod._client.headers.get("authorization"), "Bearer test-token-xyz")

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-token-xyz"}, clear=False)
    def test_shared_backend_client_carries_internal_token(self):
        import shared.client.backend_client as backendclientmod

        importlib.reload(backendclientmod)
        self.assertEqual(backendclientmod._client.headers.get("authorization"), "Bearer test-token-xyz")


if __name__ == "__main__":
    unittest.main()
