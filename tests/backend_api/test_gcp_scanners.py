"""
Tests for the GCP Phase 1 scanner wiring: the gcp_* scanner_types are
registered in routers/scans.py's SCANNERS dict, and findings.py's
persist_scan_findings() correctly dispatches gcp_vm/gcp_bucket/gcp_iam/
gcp_db/gcp_cis reports into insert_scan_results() with the expected
check_id/asset_id shape.
"""
import os
import sys
import unittest
from unittest.mock import patch

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

# Purge only "routers" here (not "findings"/"auth" - unlike
# test_findings_profile_stamp.py's purge, which this file must NOT repeat,
# or it desyncs that file's @patch("findings.X") from its direct
# findings.foo() calls, see that file's own comment). "routers" still needs
# purging: db-service's test files register a same-named "routers" package
# with no "scans" submodule, and if those run first in the same pytest
# session sys.modules["routers"] would resolve to the wrong package.
for _mod_name in list(sys.modules):
    if _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import findings  # noqa: E402
import routers.scans as scans_module  # noqa: E402
from playbooks.gcp_bucket_scanner import run_gcp_bucket_scan  # noqa: E402
from playbooks.gcp_firewall_scanner import run_gcp_firewall_scan  # noqa: E402
from playbooks.gcp_functions_scanner import run_gcp_functions_scan  # noqa: E402
from playbooks.gcp_gke_scanner import run_gcp_gke_scan  # noqa: E402
from playbooks.gcp_secrets_scanner import run_gcp_secrets_scan  # noqa: E402


class TestGcpScannerRegistration(unittest.TestCase):
    def test_gcp_scanner_types_registered(self):
        for scanner_type in (
            "gcp_vm", "gcp_bucket", "gcp_iam", "gcp_db", "gcp_cis",
            "gcp_secrets", "gcp_gke", "gcp_functions", "gcp_firewall",
        ):
            self.assertIn(scanner_type, scans_module.SCANNERS)


class TestGcpBucketFindingsPersist(unittest.TestCase):
    @patch("findings.insert_activity_log")
    @patch("findings.insert_scan_results")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_gcp_bucket_mock_report_persists_findings(
        self, mock_get_active, mock_import_assets, mock_insert_results, mock_log
    ):
        mock_get_active.return_value = None
        report = run_gcp_bucket_scan()  # no collector -> mock mode

        findings.persist_scan_findings("gcp_bucket", report, provider="gcp")

        mock_insert_results.assert_called_once()
        inserted = mock_insert_results.call_args[0][0]
        self.assertTrue(inserted)
        self.assertTrue(all(row["check_id"].startswith("gcp-bucket-") for row in inserted))
        self.assertTrue(any(row["check_id"] == "gcp-bucket-public" for row in inserted))

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertTrue(any(a["asset_type"] == "gcs_bucket" for a in imported_assets))


class TestGcpSecretsFindingsPersist(unittest.TestCase):
    @patch("findings.insert_activity_log")
    @patch("findings.insert_scan_results")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_gcp_secrets_mock_report_persists_findings(
        self, mock_get_active, mock_import_assets, mock_insert_results, mock_log
    ):
        mock_get_active.return_value = None
        report = run_gcp_secrets_scan()  # no collector -> mock mode

        findings.persist_scan_findings("gcp_secrets", report, provider="gcp")

        mock_insert_results.assert_called_once()
        inserted = mock_insert_results.call_args[0][0]
        self.assertTrue(inserted)
        self.assertTrue(any(row["check_id"].startswith("gcp-secrets-") for row in inserted))
        # Mock mode grants secretmanager.versions.access -> a privesc finding.
        self.assertTrue(any(row["check_id"].startswith("gcp-secrets-privesc-") for row in inserted))

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertTrue(any(a["asset_type"] == "gcp_secret" for a in imported_assets))


class TestGcpGkeFindingsPersist(unittest.TestCase):
    @patch("findings.insert_activity_log")
    @patch("findings.insert_scan_results")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_gcp_gke_mock_report_persists_findings(
        self, mock_get_active, mock_import_assets, mock_insert_results, mock_log
    ):
        mock_get_active.return_value = None
        report = run_gcp_gke_scan()  # no collector -> mock mode

        findings.persist_scan_findings("gcp_gke", report, provider="gcp")

        mock_insert_results.assert_called_once()
        inserted = mock_insert_results.call_args[0][0]
        self.assertTrue(inserted)
        self.assertTrue(any(row["check_id"].startswith("gcp-gke-") for row in inserted))
        self.assertTrue(any(row["check_id"] == "gcp-gke-public-master" for row in inserted))
        self.assertTrue(any(row["check_id"].startswith("gcp-gke-privesc-") for row in inserted))

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertTrue(any(a["asset_type"] == "gke_cluster" for a in imported_assets))


class TestGcpFunctionsFindingsPersist(unittest.TestCase):
    @patch("findings.insert_activity_log")
    @patch("findings.insert_scan_results")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_gcp_functions_mock_report_persists_findings(
        self, mock_get_active, mock_import_assets, mock_insert_results, mock_log
    ):
        mock_get_active.return_value = None
        report = run_gcp_functions_scan()  # no collector -> mock mode

        findings.persist_scan_findings("gcp_functions", report, provider="gcp")

        mock_insert_results.assert_called_once()
        inserted = mock_insert_results.call_args[0][0]
        self.assertTrue(inserted)
        self.assertTrue(any(row["check_id"].startswith("gcp-functions-") for row in inserted))
        self.assertTrue(any(row["check_id"] == "gcp-functions-unauthenticated" for row in inserted))
        # Mock mode grants create+actAs -> the combined escalation finding.
        self.assertTrue(any(row["check_id"] == "gcp-functions-privesc-create-actas" for row in inserted))

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertTrue(any(a["asset_type"] == "cloud_function" for a in imported_assets))


class TestGcpFirewallFindingsPersist(unittest.TestCase):
    @patch("findings.insert_activity_log")
    @patch("findings.insert_scan_results")
    @patch("findings.import_assets")
    @patch("findings.get_active_profile")
    def test_gcp_firewall_mock_report_persists_findings(
        self, mock_get_active, mock_import_assets, mock_insert_results, mock_log
    ):
        mock_get_active.return_value = None
        report = run_gcp_firewall_scan()  # no collector -> mock mode

        findings.persist_scan_findings("gcp_firewall", report, provider="gcp")

        mock_insert_results.assert_called_once()
        inserted = mock_insert_results.call_args[0][0]
        self.assertTrue(inserted)
        self.assertTrue(any(row["check_id"].startswith("gcp-firewall-") for row in inserted))
        self.assertTrue(any(row["check_id"] == "gcp-firewall-critical-port-public" for row in inserted))

        imported_assets = mock_import_assets.call_args[0][0]
        self.assertTrue(any(a["asset_type"] == "gcp_firewall_rule" for a in imported_assets))


if __name__ == "__main__":
    unittest.main()
