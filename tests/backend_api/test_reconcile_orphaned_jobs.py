"""
Tests for services/backend-api/jobs.py's reconcile_orphaned_jobs() - called
once at process startup to mark any job still "running" as "failed", since
its worker thread lived in the previous process and cannot have survived
a restart.
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
    if _mod_name == "jobs":
        del sys.modules[_mod_name]

import jobs  # noqa: E402

# patch.object(jobs, ...) below, not string-based @patch("jobs.X") - this
# service's test_v1_runs_profile.py purges+reimports "jobs" too (indirectly,
# via routers.v1_runs), and whichever file collects last wins sys.modules;
# a string-based patch resolved at call time could then silently target a
# different "jobs" module instance than the one this file's own `jobs`
# name is bound to. See test_profiles_verify.py's identical fix.


class TestReconcileOrphanedJobs(unittest.TestCase):
    @patch.object(jobs, "update_job")
    @patch.object(jobs, "list_jobs")
    def test_marks_every_running_job_failed(self, mock_list_jobs, mock_update_job):
        mock_list_jobs.return_value = [{"id": "job-1"}, {"id": "job-2"}]

        count = jobs.reconcile_orphaned_jobs()

        mock_list_jobs.assert_called_once_with(status="running", limit=500)
        self.assertEqual(count, 2)
        self.assertEqual(mock_update_job.call_count, 2)
        for call in mock_update_job.call_args_list:
            self.assertEqual(call.kwargs["status"], "failed")
            self.assertTrue(call.kwargs["finished"])
            self.assertIn("orphaned", call.kwargs["error_message"])

    @patch.object(jobs, "update_job")
    @patch.object(jobs, "list_jobs")
    def test_no_running_jobs_is_a_no_op(self, mock_list_jobs, mock_update_job):
        mock_list_jobs.return_value = []

        count = jobs.reconcile_orphaned_jobs()

        self.assertEqual(count, 0)
        mock_update_job.assert_not_called()


if __name__ == "__main__":
    unittest.main()
