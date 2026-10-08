"""
Tests for services/backend-api/routers/v1_schedules.py's create_schedule()
explicit profile_id resolution, and scheduler.py's _fire() threading a
schedule's already-resolved profile_id into _fire_run() - a scheduled scan
must always fire against the Profile it was created with, not whichever
Profile happens to be globally active when the scheduler's tick fires it.

Patches via patch.object() on the already-held module reference, not
string-based @patch("routers.v1_schedules...") / @patch("scheduler...") -
this service's `routers` package name collides with db-service's
identically-named package when both services' test files run in one
pytest process (see test_v1_runs_profile.py for the full explanation).
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
    if _mod_name in ("auth", "scheduler", "v1_schedules") or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import routers as backend_routers_pkg  # noqa: E402
import routers.v1_runs as v1_runs  # noqa: E402
import routers.v1_schedules as v1_schedules  # noqa: E402
import scheduler  # noqa: E402


class TestCreateScheduleProfileResolution(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        patcher = patch.object(v1_schedules, "db", self.mock_db)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_explicit_profile_id_resolved_and_stored(self):
        self.mock_db.get_profile.return_value = {"id": "profile-abc", "name": "Staging"}
        self.mock_db.create_schedule.return_value = {
            "id": "sched-1", "classes": "[\"vm\"]", "profile_id": "profile-abc", "profile_name": "Staging",
        }

        v1_schedules.create_schedule(v1_schedules.ScheduleCreateRequest(
            classes=["vm"], mode="interval", interval_value=1, interval_unit="days",
            profile_id="profile-abc",
        ))

        self.mock_db.get_profile.assert_called_once_with("profile-abc")
        self.mock_db.get_active_profile.assert_not_called()
        args, _ = self.mock_db.create_schedule.call_args
        self.assertEqual(args[-2:], ("profile-abc", "Staging"))

    def test_no_profile_id_falls_back_to_active_profile(self):
        self.mock_db.get_active_profile.return_value = {"id": "profile-default", "name": "Default OCI"}
        self.mock_db.create_schedule.return_value = {
            "id": "sched-1", "classes": "[\"vm\"]", "profile_id": "profile-default", "profile_name": "Default OCI",
        }

        v1_schedules.create_schedule(v1_schedules.ScheduleCreateRequest(
            classes=["vm"], mode="interval", interval_value=1, interval_unit="days",
        ))

        self.mock_db.get_profile.assert_not_called()
        self.mock_db.get_active_profile.assert_called_once_with("oci")
        args, _ = self.mock_db.create_schedule.call_args
        self.assertEqual(args[-2:], ("profile-default", "Default OCI"))


class TestSchedulerFiresWithStoredProfile(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        patcher = patch.object(scheduler, "db", self.mock_db)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_fire_passes_schedules_stored_profile_id(self):
        import json
        from datetime import datetime, timezone

        sched = {
            "id": "sched-1", "classes": json.dumps(["vm"]), "provider": "oci",
            "scan_depth": "rules", "mode": "once", "profile_id": "profile-abc",
        }
        mock_fire_run = MagicMock(return_value={"id": "run-1"})
        # scheduler._fire does a lazy `from routers.v1_runs import _fire_run`
        # at call time - pin sys.modules to this service's `routers` package
        # for the duration of the call, since another test file's identically
        # -named db-service `routers` package may currently hold that slot.
        with patch.object(v1_runs, "_fire_run", mock_fire_run), \
                patch.dict(sys.modules, {"routers": backend_routers_pkg, "routers.v1_runs": v1_runs}):
            scheduler._fire(sched, datetime.now(timezone.utc))

        _, kwargs = mock_fire_run.call_args
        self.assertEqual(kwargs["profile_id"], "profile-abc")


if __name__ == "__main__":
    unittest.main()
