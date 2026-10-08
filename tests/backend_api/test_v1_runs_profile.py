"""
Tests for services/backend-api/routers/v1_runs.py's _fire_run() explicit
profile_id resolution - a run must resolve its Profile once (explicit
override or the provider's active Profile) and thread it into every child
scan job and the parent run job, so background-job completion always tags
assets with the Profile that was active *when the run was fired*, not
whichever Profile is globally active by the time the job finishes.
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
    if _mod_name in ("auth", "jobs", "v1_runs") or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import routers.v1_runs as v1_runs  # noqa: E402


class TestFireRunProfileResolution(unittest.TestCase):
    """Patches via patch.object() on the already-held v1_runs module
    reference, not string-based @patch("routers.v1_runs...") - this
    service's `routers` package name collides with db-service's identically
    -named package when both services' test files run in one pytest
    process, so string-based patching (which re-resolves the dotted path
    through sys.modules at patch-time) can silently patch the wrong module
    or fail to find the attribute at all."""

    def _stub_job(self, job_id):
        return {"id": job_id, "status": "running"}

    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_jobs = MagicMock()
        self.mock_build_collector = MagicMock()
        patcher_db = patch.object(v1_runs, "db", self.mock_db)
        patcher_jobs = patch.object(v1_runs, "jobs", self.mock_jobs)
        patcher_build = patch.object(v1_runs, "build_collector", self.mock_build_collector)
        patcher_db.start()
        patcher_jobs.start()
        patcher_build.start()
        self.addCleanup(patcher_db.stop)
        self.addCleanup(patcher_jobs.stop)
        self.addCleanup(patcher_build.stop)

    def test_explicit_profile_id_resolved_and_threaded(self):
        self.mock_db.get_profile.return_value = {"id": "profile-abc", "name": "Staging"}
        self.mock_jobs.start_scan.return_value = self._stub_job("child-1")
        self.mock_db.create_job.return_value = self._stub_job("run-1")
        self.mock_db.get_job.return_value = {"id": "run-1", "result_ref": "[]"}

        v1_runs._fire_run(["vm"], None, "oci", "rules", profile_id="profile-abc")

        self.mock_db.get_profile.assert_called_once_with("profile-abc")
        self.mock_db.get_active_profile.assert_not_called()
        self.mock_build_collector.assert_called_once_with("oci", profile_id="profile-abc")
        _, kwargs = self.mock_jobs.start_scan.call_args
        self.assertEqual(kwargs["profile_id"], "profile-abc")
        self.assertEqual(kwargs["profile_name"], "Staging")
        self.mock_db.create_job.assert_called_once_with(
            "run", cloud_provider="oci", scan_depth="rules",
            profile_id="profile-abc", profile_name="Staging", asset_ids=None,
        )

    def test_no_profile_id_falls_back_to_active_profile(self):
        self.mock_db.get_active_profile.return_value = {"id": "profile-default", "name": "Default OCI"}
        self.mock_jobs.start_scan.return_value = self._stub_job("child-1")
        self.mock_db.create_job.return_value = self._stub_job("run-1")
        self.mock_db.get_job.return_value = {"id": "run-1", "result_ref": "[]"}

        v1_runs._fire_run(["vm"], None, "oci", "rules")

        self.mock_db.get_profile.assert_not_called()
        self.mock_db.get_active_profile.assert_called_once_with("oci")
        self.mock_build_collector.assert_called_once_with("oci", profile_id=None)
        _, kwargs = self.mock_jobs.start_scan.call_args
        self.assertEqual(kwargs["profile_id"], "profile-default")
        self.assertEqual(kwargs["profile_name"], "Default OCI")


if __name__ == "__main__":
    unittest.main()
