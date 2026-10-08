"""
Tests for the whoami_result/whoami_checked_at columns added to `profiles`
in services/db-service/store.py - confirms the migration runs cleanly on
a fresh DB and that update_profile persists/overwrites both fields.

Runs against a temp SQLite file (not the real clouds8.db), same pattern
as tests/db_service/test_db_service.py.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_tmp_dir = tempfile.mkdtemp(prefix="clouds8_whoami_columns_test_")
os.environ["CLOUDS8_DB_PATH"] = str(Path(_tmp_dir) / "test_clouds8.db")

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "db-service")
)
sys.path.insert(0, _SERVICE_DIR)

for _mod_name in list(sys.modules):
    if _mod_name == "store":
        del sys.modules[_mod_name]

import store  # noqa: E402

store.init_database()


class TestProfilesWhoamiColumns(unittest.TestCase):
    def setUp(self):
        # UNIQUE(cloud_provider, config_profile_name) means every test
        # needs its own config_profile_name - these tests share one temp
        # DB file for the whole module, not a fresh DB per test.
        import uuid
        self._config_profile_name = f"/tmp/key-{uuid.uuid4().hex}.json"

    def test_new_profile_has_null_whoami_fields(self):
        profile = store.create_profile("test", "gcp", self._config_profile_name)
        self.assertIsNone(profile["whoami_result"])
        self.assertIsNone(profile["whoami_checked_at"])

    def test_update_profile_persists_whoami_fields(self):
        profile = store.create_profile("test", "gcp", self._config_profile_name)
        updated = store.update_profile(
            profile["id"],
            whoami_result='{"risk": "HIGH"}',
            whoami_checked_at="2026-10-08T12:00:00",
        )
        self.assertEqual(updated["whoami_result"], '{"risk": "HIGH"}')
        self.assertEqual(updated["whoami_checked_at"], "2026-10-08T12:00:00")

    def test_update_profile_overwrites_previous_whoami_result(self):
        profile = store.create_profile("test", "gcp", self._config_profile_name)
        store.update_profile(profile["id"], whoami_result='{"risk": "HIGH"}', whoami_checked_at="2026-10-08T12:00:00")
        updated = store.update_profile(
            profile["id"], whoami_result='{"risk": "LOW"}', whoami_checked_at="2026-10-08T13:00:00",
        )
        self.assertEqual(updated["whoami_result"], '{"risk": "LOW"}')
        self.assertEqual(updated["whoami_checked_at"], "2026-10-08T13:00:00")


if __name__ == "__main__":
    unittest.main()
