"""
Tests for services/backend-api/routers/v1_profiles.py's POST
/v1/profiles/{id}/verify - the one Profile action needing the OCI SDK,
which only backend-api has access to. Mocks the OCI SDK boundary (this
codebase never hits real cloud APIs in tests) via patch.object on the
directly-held v1_profiles module object (not string-based @patch(), which
resolves against sys.modules at call time - a sibling test file's
module-collision purge, elsewhere in this same process, could otherwise
silently invalidate a string-based patch between collection and
execution; see tests/db_service/test_auth.py's identical fix for the
same class of bug).
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

for _mod_name in list(sys.modules):
    if _mod_name == "auth" or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import auth  # noqa: E402
import routers.v1_profiles as v1_profiles  # noqa: E402


def _build_test_app():
    from fastapi import FastAPI

    test_app = FastAPI()

    @test_app.middleware("http")
    async def _require_auth(request, call_next):
        return await auth.auth_middleware(request, call_next)

    test_app.include_router(v1_profiles.router)
    return test_app


class TestProfilesVerify(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        self.client = TestClient(
            _build_test_app(), headers={"Authorization": "Bearer test-internal-token"},
        )

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "db")
    def test_verify_unknown_profile_404(self, mock_db):
        mock_db.get_profile.return_value = None
        resp = self.client.post("/v1/profiles/does-not-exist/verify")
        self.assertEqual(resp.status_code, 404)

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "db")
    def test_verify_non_oci_provider_returns_failed_not_implemented(self, mock_db):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "aws", "config_profile_name": "default",
        }
        resp = self.client.post("/v1/profiles/p1/verify")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "failed")
        self.assertIn("not implemented", body["message"].lower())
        mock_db.update_profile.assert_called_once()
        self.assertEqual(mock_db.update_profile.call_args.kwargs["verify_status"], "failed")

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_verify_oci_missing_config_returns_failed(self, mock_db, mock_get_collector):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "oci", "config_profile_name": "MISSING",
        }
        fake_collector = MagicMock()
        fake_collector.config = None
        mock_get_collector.return_value = fake_collector

        resp = self.client.post("/v1/profiles/p1/verify")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "failed")

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_verify_gcp_malformed_key_surfaces_real_error(self, mock_db, mock_get_collector):
        # A key file that exists but fails to parse (e.g. malformed JSON)
        # must surface the actual init_error, not the generic "check the
        # file exists" hint - the file existing was never the problem.
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "gcp", "config_profile_name": "/tmp/bad-key.json",
        }
        fake_collector = MagicMock()
        fake_collector.config = None
        fake_collector.init_error = "Invalid control character at: line 11 column 147 (char 2344)"
        mock_get_collector.return_value = fake_collector

        resp = self.client.post("/v1/profiles/p1/verify")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "failed")
        self.assertIn("Invalid control character", body["message"])
        self.assertNotIn("check the service-account key file exists", body["message"])

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_verify_oci_success_calls_update_profile_with_ok(self, mock_db, mock_get_collector):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "oci", "config_profile_name": "PROD",
        }
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        fake_compartment = MagicMock()
        fake_compartment.name = "prod-tenancy"
        fake_collector.clients = {"identity": MagicMock()}
        fake_collector.clients["identity"].get_compartment.return_value.data = fake_compartment
        mock_get_collector.return_value = fake_collector

        resp = self.client.post("/v1/profiles/p1/verify")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ok")
        mock_db.update_profile.assert_called_once()
        self.assertEqual(mock_db.update_profile.call_args.kwargs["verify_status"], "ok")

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_verify_oci_api_call_failure_returns_failed(self, mock_db, mock_get_collector):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "oci", "config_profile_name": "PROD",
        }
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        fake_collector.clients = {"identity": MagicMock()}
        fake_collector.clients["identity"].get_compartment.side_effect = Exception("401 NotAuthenticated")
        mock_get_collector.return_value = fake_collector

        resp = self.client.post("/v1/profiles/p1/verify")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "failed")


class TestProfilesWhoami(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        self.client = TestClient(
            _build_test_app(), headers={"Authorization": "Bearer test-internal-token"},
        )
        # Endpoint is suppressed by default (WHOAMI_ENABLED = False) pending
        # UI fixes - these tests exercise the underlying logic as if it
        # were enabled; TestProfilesWhoamiDisabled below covers the
        # suppressed-by-default behavior itself.
        patcher_enabled = patch.object(v1_profiles, "WHOAMI_ENABLED", True)
        patcher_enabled.start()
        self.addCleanup(patcher_enabled.stop)

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "db")
    def test_whoami_unknown_profile_404(self, mock_db):
        mock_db.get_profile.return_value = None
        resp = self.client.post("/v1/profiles/does-not-exist/whoami")
        self.assertEqual(resp.status_code, 404)

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_whoami_missing_credentials_returns_422(self, mock_db, mock_get_collector):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "gcp", "config_profile_name": "/tmp/missing.json",
        }
        fake_collector = MagicMock()
        fake_collector.config = None
        fake_collector.init_error = "No such file or directory"
        mock_get_collector.return_value = fake_collector

        resp = self.client.post("/v1/profiles/p1/whoami")
        self.assertEqual(resp.status_code, 422)
        mock_db.update_profile.assert_not_called()

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_whoami")
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_whoami_success_persists_and_returns_result(self, mock_db, mock_get_collector, mock_get_whoami):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "oci", "config_profile_name": "PROD",
        }
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector

        fake_whoami_result = {
            "identity": {"type": "user", "id": "ocid1.user.oc1..fake", "name": "svc"},
            "method": "policy_lookup", "risk": "HIGH",
            "roles": [{"role": "Allow group Admins to manage all-resources in compartment prod", "risk": "HIGH", "scope": "compartment:prod"}],
            "permissions_confirmed": [], "permissions_denied": [], "errors": [],
        }
        mock_get_whoami.return_value.run.return_value = fake_whoami_result

        resp = self.client.post("/v1/profiles/p1/whoami")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["profile_id"], "p1")
        self.assertEqual(body["whoami"], fake_whoami_result)
        self.assertIn("whoami_checked_at", body)

        mock_db.update_profile.assert_called_once()
        call_kwargs = mock_db.update_profile.call_args.kwargs
        self.assertIn('"risk": "HIGH"', call_kwargs["whoami_result"])
        self.assertIn("whoami_checked_at", call_kwargs)
        # Pure whoami endpoint - must never touch connectivity fields.
        self.assertNotIn("verify_status", call_kwargs)
        self.assertNotIn("verify_message", call_kwargs)

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_whoami")
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_whoami_run_exception_returns_422_and_does_not_persist(self, mock_db, mock_get_collector, mock_get_whoami):
        mock_db.get_profile.return_value = {
            "id": "p1", "cloud_provider": "oci", "config_profile_name": "PROD",
        }
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector
        mock_get_whoami.return_value.run.side_effect = Exception("whoami blew up unexpectedly")

        resp = self.client.post("/v1/profiles/p1/whoami")
        self.assertEqual(resp.status_code, 422)
        mock_db.update_profile.assert_not_called()


class TestProfilesWhoamiDisabled(unittest.TestCase):
    """WHOAMI_ENABLED defaults to False (suppressed pending UI fixes) -
    the endpoint must 404 before touching db/get_collector/get_whoami at
    all, regardless of whether the profile exists."""

    def setUp(self):
        from fastapi.testclient import TestClient

        self.client = TestClient(
            _build_test_app(), headers={"Authorization": "Bearer test-internal-token"},
        )

    @patch.dict(os.environ, {"INTERNAL_SERVICE_TOKEN": "test-internal-token"}, clear=False)
    @patch.object(v1_profiles, "get_whoami")
    @patch.object(v1_profiles, "get_collector")
    @patch.object(v1_profiles, "db")
    def test_whoami_disabled_by_default_returns_404(self, mock_db, mock_get_collector, mock_get_whoami):
        resp = self.client.post("/v1/profiles/p1/whoami")
        self.assertEqual(resp.status_code, 404)
        mock_db.get_profile.assert_not_called()
        mock_get_collector.assert_not_called()
        mock_get_whoami.assert_not_called()


if __name__ == "__main__":
    unittest.main()
