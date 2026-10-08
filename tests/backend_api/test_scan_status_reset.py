"""
Tests for services/backend-api/jobs.py's start_scan() resetting the
relevant asset type(s) back to scan_status="not_scanned" the moment a scan
begins - without this, every asset already carries "scanned" from the
previous run (nothing else ever resets it), so Inventory's "in progress"
view is permanently empty on any re-scan, even while one is actively
running. See the comment in jobs.py's _worker() for the full rationale.
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
    if _mod_name == "jobs":
        del sys.modules[_mod_name]

import jobs  # noqa: E402


class _SyncThread:
    """Stand-in for threading.Thread that runs target() synchronously on
    .start(), so the background worker's side effects are observable
    without needing to join a real thread in the test."""

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        self._target()


class TestScanStatusResetOnStart(unittest.TestCase):
    def setUp(self):
        self.mock_create_job = MagicMock(return_value={"id": "job-1"})
        self.mock_update_job = MagicMock()
        self.mock_get_job = MagicMock(return_value={"id": "job-1", "status": "succeeded"})
        self.mock_mark_assets = MagicMock()
        self.mock_persist_findings = MagicMock()
        self.mock_save_report = MagicMock()
        self.patchers = [
            patch.object(jobs, "create_job", self.mock_create_job),
            patch.object(jobs, "update_job", self.mock_update_job),
            patch.object(jobs, "get_job", self.mock_get_job),
            patch.object(jobs, "mark_assets_scanned_by_type", self.mock_mark_assets),
            patch.object(jobs, "persist_scan_findings", self.mock_persist_findings),
            patch.object(jobs, "save_scan_report", self.mock_save_report),
            patch.object(jobs, "insert_activity_log", MagicMock()),
            patch.object(jobs, "threading", MagicMock(Thread=_SyncThread)),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_resets_each_asset_type_for_this_scanner_before_running(self):
        runner = MagicMock(return_value={"vms": []})

        jobs.start_scan("vm", runner, collector=MagicMock(), provider="oci")

        self.mock_mark_assets.assert_called_once_with("vm", "not_scanned")
        runner.assert_called_once()

    def test_resets_every_asset_type_for_a_multi_type_scanner(self):
        runner = MagicMock(return_value={"findings": []})

        jobs.start_scan("iam", runner, collector=MagicMock(), provider="oci")

        reset_types = {c.args[0] for c in self.mock_mark_assets.call_args_list}
        self.assertEqual(reset_types, {"policy", "user", "group", "dynamic_group"})
        for c in self.mock_mark_assets.call_args_list:
            self.assertEqual(c.args[1], "not_scanned")

    def test_unknown_scanner_type_resets_nothing(self):
        runner = MagicMock(return_value={})

        jobs.start_scan("not-a-real-scanner", runner, collector=MagicMock(), provider="oci")

        self.mock_mark_assets.assert_not_called()
        runner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
