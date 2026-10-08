"""
Tests for services/backend-api/collector.py's build_collector() - the
single chokepoint both the ad-hoc "Start scan" flow and the scheduler
funnel through, now responsible for resolving whichever Profile is
currently marked active for a provider and threading its
config_profile_name into the collector it builds.
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
    if _mod_name in ("auth", "collector") or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import collector  # noqa: E402


class TestBuildCollectorActiveProfile(unittest.TestCase):
    @patch("collector.get_collector")
    @patch("collector.db")
    def test_passes_active_profile_section_to_registry(self, mock_db, mock_get_collector):
        mock_db.get_active_profile.return_value = {"config_profile_name": "PROD"}
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector

        result = collector.build_collector("oci")

        mock_get_collector.assert_called_once_with("oci", config_profile_name="PROD")
        self.assertIs(result, fake_collector)

    @patch("collector.get_collector")
    @patch("collector.db")
    def test_falls_back_when_profile_lookup_fails(self, mock_db, mock_get_collector):
        mock_db.get_active_profile.side_effect = Exception("db-service unreachable")
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector

        result = collector.build_collector("oci")

        mock_get_collector.assert_called_once_with("oci", config_profile_name=None)
        self.assertIs(result, fake_collector)

    @patch("collector.get_collector")
    @patch("collector.db")
    def test_falls_back_when_no_active_profile(self, mock_db, mock_get_collector):
        mock_db.get_active_profile.return_value = None
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector

        result = collector.build_collector("oci")

        mock_get_collector.assert_called_once_with("oci", config_profile_name=None)
        self.assertIs(result, fake_collector)

    @patch("collector.get_collector")
    @patch("collector.db")
    def test_explicit_profile_id_bypasses_active_profile_lookup(self, mock_db, mock_get_collector):
        mock_db.get_profile.return_value = {"config_profile_name": "STAGING"}
        fake_collector = MagicMock()
        fake_collector.config = {"tenancy": "ocid1.tenancy.oc1..fake"}
        mock_get_collector.return_value = fake_collector

        result = collector.build_collector("oci", profile_id="profile-xyz")

        mock_db.get_profile.assert_called_once_with("profile-xyz")
        mock_db.get_active_profile.assert_not_called()
        mock_get_collector.assert_called_once_with("oci", config_profile_name="STAGING")
        self.assertIs(result, fake_collector)

    @patch("collector.get_collector")
    @patch("collector.db")
    def test_returns_none_when_not_configured(self, mock_db, mock_get_collector):
        mock_db.get_active_profile.return_value = {"config_profile_name": "PROD"}
        fake_collector = MagicMock()
        fake_collector.config = None
        mock_get_collector.return_value = fake_collector

        result = collector.build_collector("oci")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
