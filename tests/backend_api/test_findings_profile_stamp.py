"""
Tests for services/backend-api/findings.py's _import_assets() stamping
every scanned asset with the currently-active OCI profile's id/name before
it reaches import_assets() - the single chokepoint all ~14 scanner call
sites funnel through.
"""
import os
import sys
import unittest
from unittest.mock import patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

for _mod_name in list(sys.modules):
    if _mod_name in ("auth", "findings") or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import findings  # noqa: E402


class TestFindingsProfileStamp(unittest.TestCase):
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_stamps_active_profile_onto_every_asset(self, mock_get_active, mock_import_assets):
        mock_get_active.return_value = {"id": "profile-123", "name": "Prod Tenancy"}
        assets = [{"asset_id": "vm-1", "asset_type": "vm", "name": "VM 1"}]

        findings._import_assets(assets, "vm")

        mock_import_assets.assert_called_once()
        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["profile_id"], "profile-123")
        self.assertEqual(imported_assets[0]["profile_name"], "Prod Tenancy")

    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_does_not_overwrite_explicit_profile_on_asset(self, mock_get_active, mock_import_assets):
        mock_get_active.return_value = {"id": "profile-123", "name": "Prod Tenancy"}
        assets = [{"asset_id": "vm-1", "asset_type": "vm", "name": "VM 1",
                   "profile_id": "already-set", "profile_name": "Already Set"}]

        findings._import_assets(assets, "vm")

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["profile_id"], "already-set")

    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_no_active_profile_leaves_assets_unstamped(self, mock_get_active, mock_import_assets):
        mock_get_active.return_value = None
        assets = [{"asset_id": "vm-1", "asset_type": "vm", "name": "VM 1"}]

        findings._import_assets(assets, "vm")

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertNotIn("profile_id", imported_assets[0])

    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_profile_lookup_failure_does_not_block_import(self, mock_get_active, mock_import_assets):
        mock_get_active.side_effect = Exception("db-service unreachable")
        assets = [{"asset_id": "vm-1", "asset_type": "vm", "name": "VM 1"}]

        findings._import_assets(assets, "vm")

        mock_import_assets.assert_called_once()

    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_explicit_profile_bypasses_active_profile_lookup(self, mock_get_active, mock_import_assets):
        assets = [{"asset_id": "vm-1", "asset_type": "vm", "name": "VM 1"}]

        findings._import_assets(assets, "vm", profile_id="explicit-1", profile_name="Staging")

        mock_get_active.assert_not_called()
        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["profile_id"], "explicit-1")
        self.assertEqual(imported_assets[0]["profile_name"], "Staging")

    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_persist_scan_findings_threads_explicit_profile_into_imports(self, mock_get_active, mock_import_assets):
        report = {"vms": [{"instance_id": "vm-1", "display_name": "VM 1"}]}

        findings.persist_scan_findings("vm", report, profile_id="explicit-1", profile_name="Staging")

        mock_get_active.assert_not_called()
        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["profile_id"], "explicit-1")
        self.assertEqual(imported_assets[0]["profile_name"], "Staging")

    @patch("findings.insert_scan_results")
    @patch("findings.mark_assets_scanned_by_type")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_inventory_only_tags_not_scanned_and_skips_findings(
        self, mock_get_active, mock_import_assets, mock_mark_scanned, mock_insert_results,
    ):
        # A VM with a public IP would normally produce a "vm-public-ip"
        # finding - run_checks=False (inventory-only) must still import the
        # asset, but tagged not_scanned and with no rule findings persisted.
        report = {"vms": [{"instance_id": "vm-1", "display_name": "VM 1", "public_ips": ["1.2.3.4"]}]}

        findings.persist_scan_findings("vm", report, profile_id="p1", profile_name="P1", run_checks=False)

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["scan_status"], "not_scanned")
        mock_insert_results.assert_not_called()
        mock_mark_scanned.assert_called_with("vm", "not_scanned")

    @patch("findings.insert_scan_results")
    @patch("findings.mark_assets_scanned_by_type")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_full_scan_still_tags_scanned_and_persists_findings(
        self, mock_get_active, mock_import_assets, mock_mark_scanned, mock_insert_results,
    ):
        report = {"vms": [{"instance_id": "vm-1", "display_name": "VM 1", "public_ips": ["1.2.3.4"]}]}

        findings.persist_scan_findings("vm", report, profile_id="p1", profile_name="P1", run_checks=True)

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertEqual(imported_assets[0]["scan_status"], "scanned")
        mock_insert_results.assert_called_once()
        mock_mark_scanned.assert_called_with("vm", "scanned")


if __name__ == "__main__":
    unittest.main()
