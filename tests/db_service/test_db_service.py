"""
Tests for services/db-service/ - the standalone FastAPI service that now owns
the sole SQLite connection to clouds8.db. These replace the old
tests/test_clouds8.py::TestDatabase class, which patched
db.database.get_connection() directly - that seam no longer exists since
db/database.py is now an HTTP client facade over this service.

Runs against a temp SQLite file (not the real clouds8.db), driven directly
via FastAPI's TestClient - no network/process needed.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_tmp_dir = tempfile.mkdtemp(prefix="clouds8_db_service_test_")
os.environ["CLOUDS8_DB_PATH"] = str(Path(_tmp_dir) / "test_clouds8.db")
os.environ["INTERNAL_SERVICE_TOKEN"] = "test-internal-token"

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "db-service")
)
sys.path.insert(0, _SERVICE_DIR)

# services/backend-api/ has its own same-named `app`/`auth`/`routers`
# modules; sys.modules is process-global, so if those got imported first in
# this pytest session (e.g. tests/backend_api/test_login.py ran earlier)
# the imports below would silently resolve to backend-api's copies instead
# of this service's. Purge first so this file always gets its own.
for _mod_name in list(sys.modules):
    if _mod_name in ("app", "auth", "store") or _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

from fastapi.testclient import TestClient  # noqa: E402
import app as db_service_app  # noqa: E402


class TestDBServiceAssets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        self.client.post("/admin/clear")

    def test_import_assets(self):
        assets = [
            {
                "asset_id": "test-vm-1",
                "asset_type": "vm",
                "name": "Production VM",
                "compartment": "Production",
                "region": "us-phoenix-1",
                "scan_status": "scanned",
                "risk_score": 50,
                "metadata": {"cpu": 4, "ram": 32},
            },
            {
                "asset_id": "test-bucket-1",
                "asset_type": "bucket",
                "name": "Logs Bucket",
                "compartment": "Audit",
                "region": "us-ashburn-1",
                "metadata": {"public_access": "NoPublicAccess"},
            },
        ]

        resp = self.client.post("/assets/import", json={"assets": assets, "source_description": "Test Import"})
        self.assertEqual(resp.status_code, 200)
        stats = resp.json()

        self.assertEqual(stats["imported"], 2)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["by_type"]["vm"], 1)
        self.assertEqual(stats["by_type"]["bucket"], 1)

        asset = self.client.get("/assets/id/test-vm-1").json()
        self.assertEqual(asset["name"], "Production VM")
        self.assertEqual(asset["risk_score"], 50)
        meta = json.loads(asset["metadata"])
        self.assertEqual(meta["cpu"], 4)

    def test_upsert_behavior(self):
        assets_v1 = [{
            "asset_id": "test-vm-1", "asset_type": "vm", "name": "Old Name",
            "compartment": "Dev", "risk_score": 10,
        }]
        self.client.post("/assets/import", json={"assets": assets_v1, "source_description": "Import V1"})

        assets_v2 = [{
            "asset_id": "test-vm-1", "asset_type": "vm", "name": "New Name",
            "compartment": "Prod", "risk_score": 90,
        }]
        resp = self.client.post("/assets/import", json={"assets": assets_v2, "source_description": "Import V2"})
        self.assertEqual(resp.json()["imported"], 1)

        asset = self.client.get("/assets/id/test-vm-1").json()
        self.assertEqual(asset["name"], "New Name")
        self.assertEqual(asset["compartment"], "Prod")
        self.assertEqual(asset["risk_score"], 90)

    def test_risk_score_only_increases(self):
        """Documented upsert rule: risk_score never decreases on re-import."""
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "a1", "asset_type": "vm", "name": "A", "risk_score": 80}
        ]})
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "a1", "asset_type": "vm", "name": "A", "risk_score": 20}
        ]})
        asset = self.client.get("/assets/id/a1").json()
        self.assertEqual(asset["risk_score"], 80)

    def test_composite_uniqueness_across_providers(self):
        """Same asset_id under two different cloud providers must NOT collide -
        this is the multi-cloud schema fix (composite UNIQUE(asset_id, cloud_provider))."""
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "shared-id-1", "asset_type": "vm", "name": "OCI VM", "cloud_provider": "oci"}
        ]})
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "shared-id-1", "asset_type": "vm", "name": "AWS VM", "cloud_provider": "aws"}
        ]})
        all_assets = self.client.get("/assets", params={"limit": 100}).json()
        matching = [a for a in all_assets if a["asset_id"] == "shared-id-1"]
        self.assertEqual(len(matching), 2)
        providers = {a["cloud_provider"] for a in matching}
        self.assertEqual(providers, {"oci", "aws"})

    def test_scope_fields_backfilled_from_compartment(self):
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "a2", "asset_type": "vm", "name": "A2", "compartment": "Prod"}
        ]})
        asset = self.client.get("/assets/id/a2").json()
        self.assertEqual(asset["scope_type"], "compartment")
        self.assertEqual(asset["scope_id"], "Prod")

    def test_composite_uniqueness_across_profiles(self):
        """Same asset_id + cloud_provider under two different profiles must
        NOT collide - a bucket named the same way in two different OCI
        tenancies (profiles) are different resources."""
        profile_a = self.client.post("/v1/profiles", json={
            "name": "Uniqueness Profile A", "cloud_provider": "oci", "config_profile_name": "UNIQ_A",
        }).json()
        profile_b = self.client.post("/v1/profiles", json={
            "name": "Uniqueness Profile B", "cloud_provider": "oci", "config_profile_name": "UNIQ_B",
        }).json()
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "shared-bucket-name", "asset_type": "bucket", "name": "Bucket A",
             "cloud_provider": "oci", "profile_id": profile_a["id"], "profile_name": profile_a["name"]}
        ]})
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "shared-bucket-name", "asset_type": "bucket", "name": "Bucket B",
             "cloud_provider": "oci", "profile_id": profile_b["id"], "profile_name": profile_b["name"]}
        ]})
        all_assets = self.client.get("/assets", params={"limit": 500}).json()
        matching = [a for a in all_assets if a["asset_id"] == "shared-bucket-name"]
        self.assertEqual(len(matching), 2)
        profile_ids = {a["profile_id"] for a in matching}
        self.assertEqual(profile_ids, {profile_a["id"], profile_b["id"]})

    def test_import_assets_backfills_profile_when_missing(self):
        """An asset imported with no profile_id at all still gets tagged
        with the provider's earliest profile (the seeded default on a
        fresh DB), rather than being left with a NULL profile forever."""
        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "no-profile-asset", "asset_type": "vm", "name": "No Profile VM", "cloud_provider": "oci"}
        ]})
        asset = self.client.get("/assets/id/no-profile-asset").json()
        self.assertIsNotNone(asset.get("profile_id"))
        self.assertIsNotNone(asset.get("profile_name"))


class TestDBServiceJobs(unittest.TestCase):
    """Covers the persisted jobs table that replaces api/jobs.py's in-memory
    dict and the UI's module-global threading dicts."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def test_job_lifecycle(self):
        created = self.client.post("/jobs", json={"job_type": "sync", "cloud_provider": "oci"}).json()
        self.assertEqual(created["status"], "pending")
        job_id = created["id"]

        running = self.client.patch(f"/jobs/{job_id}", json={"status": "running", "started": True}).json()
        self.assertEqual(running["status"], "running")
        self.assertIsNotNone(running["started_at"])

        done = self.client.patch(f"/jobs/{job_id}", json={
            "status": "succeeded", "progress_pct": 100, "finished": True,
        }).json()
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(done["progress_pct"], 100)
        self.assertIsNotNone(done["finished_at"])

        fetched = self.client.get(f"/jobs/{job_id}").json()
        self.assertEqual(fetched["id"], job_id)

    def test_job_not_found(self):
        resp = self.client.get("/jobs/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_job_carries_explicit_profile(self):
        created = self.client.post("/jobs", json={
            "job_type": "scan", "cloud_provider": "oci",
            "profile_id": "profile-abc", "profile_name": "Prod Tenancy",
        }).json()
        self.assertEqual(created["profile_id"], "profile-abc")
        self.assertEqual(created["profile_name"], "Prod Tenancy")

        fetched = self.client.get(f"/jobs/{created['id']}").json()
        self.assertEqual(fetched["profile_id"], "profile-abc")


class TestDBServiceSchedules(unittest.TestCase):
    """Covers the persisted schedules table's explicit profile_id/profile_name
    columns, mirroring jobs' - a scheduled scan must carry the same explicit
    profile override an ad-hoc run can."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def test_schedule_carries_explicit_profile(self):
        created = self.client.post("/schedules", json={
            "classes": ["vm"], "provider": "oci", "mode": "once",
            "next_run_at": "2030-01-01T00:00:00",
            "profile_id": "profile-abc", "profile_name": "Prod Tenancy",
        }).json()
        self.assertEqual(created["profile_id"], "profile-abc")
        self.assertEqual(created["profile_name"], "Prod Tenancy")

        fetched = self.client.get(f"/schedules/{created['id']}").json()
        self.assertEqual(fetched["profile_id"], "profile-abc")

    def test_schedule_without_profile_defaults_to_null(self):
        created = self.client.post("/schedules", json={
            "classes": ["vm"], "provider": "oci", "mode": "once",
            "next_run_at": "2030-01-01T00:00:00",
        }).json()
        self.assertIsNone(created["profile_id"])


class TestDBServiceProfiles(unittest.TestCase):
    """Profiles = one persisted cloud account/tenancy, one cloud_provider
    each, referencing a local SDK config file section by name - no secrets
    stored. Replaces the old live-probe-only /v1/connections stub."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def test_create_profile(self):
        resp = self.client.post("/v1/profiles", json={
            "name": "Prod Tenancy", "cloud_provider": "oci", "config_profile_name": "PROD",
        })
        self.assertEqual(resp.status_code, 201)
        body = resp.json()
        self.assertEqual(body["name"], "Prod Tenancy")
        self.assertFalse(body["is_active"])
        self.assertEqual(body["verify_status"], "unverified")

    def test_is_active_serializes_as_real_json_boolean(self):
        # SQLite stores is_active as INTEGER 0/1 - if a route ever returns
        # the raw row without converting it, the API sends a JSON number
        # instead of a boolean. React then renders `{0 && <Badge/>}` as the
        # literal text "0" instead of nothing (0 is falsy but still a
        # renderable JSX child, unlike false/null/undefined) - a real bug
        # caught via live browser testing, not by assertFalse(0), which
        # passes for both 0 and False.
        created = self.client.post("/v1/profiles", json={
            "name": "Boolean Check Profile", "cloud_provider": "oci", "config_profile_name": "BOOLCHECK",
        }).json()
        self.assertIs(created["is_active"], False)

        fetched = self.client.get(f"/v1/profiles/{created['id']}").json()
        self.assertIs(fetched["is_active"], False)

        listed = self.client.get("/v1/profiles", params={"cloud_provider": "oci"}).json()["items"]
        listed_match = next(p for p in listed if p["id"] == created["id"])
        self.assertIs(listed_match["is_active"], False)

        activated = self.client.post(f"/v1/profiles/{created['id']}/activate").json()
        self.assertIs(activated["is_active"], True)

    def test_activate_profile_deactivates_siblings(self):
        a = self.client.post("/v1/profiles", json={
            "name": "Tenancy A", "cloud_provider": "oci", "config_profile_name": "TENANCY_A",
        }).json()
        b = self.client.post("/v1/profiles", json={
            "name": "Tenancy B", "cloud_provider": "oci", "config_profile_name": "TENANCY_B",
        }).json()

        self.client.post(f"/v1/profiles/{a['id']}/activate")
        active = self.client.get("/v1/profiles/active", params={"cloud_provider": "oci"}).json()
        self.assertEqual(active["id"], a["id"])

        self.client.post(f"/v1/profiles/{b['id']}/activate")
        active = self.client.get("/v1/profiles/active", params={"cloud_provider": "oci"}).json()
        self.assertEqual(active["id"], b["id"])
        a_refetched = self.client.get(f"/v1/profiles/{a['id']}").json()
        self.assertFalse(a_refetched["is_active"])

    def test_update_profile_name_and_section(self):
        created = self.client.post("/v1/profiles", json={
            "name": "Old Name", "cloud_provider": "oci", "config_profile_name": "OLD_SECTION",
        }).json()
        updated = self.client.patch(f"/v1/profiles/{created['id']}", json={
            "name": "New Name", "config_profile_name": "NEW_SECTION",
        }).json()
        self.assertEqual(updated["name"], "New Name")
        self.assertEqual(updated["config_profile_name"], "NEW_SECTION")
        self.assertEqual(updated["cloud_provider"], "oci")  # immutable, unchanged

    def test_delete_profile(self):
        created = self.client.post("/v1/profiles", json={
            "name": "Throwaway", "cloud_provider": "oci", "config_profile_name": "THROWAWAY",
        }).json()
        resp = self.client.delete(f"/v1/profiles/{created['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.get(f"/v1/profiles/{created['id']}").status_code, 404)

    def test_delete_profile_cleans_engagement_membership(self):
        profile = self.client.post("/v1/profiles", json={
            "name": "Member Profile", "cloud_provider": "oci", "config_profile_name": "MEMBER",
        }).json()
        engagement = self.client.post("/v1/engagements", json={
            "name": "Engagement With Member", "profile_ids": [profile["id"]],
        }).json()
        self.client.delete(f"/v1/profiles/{profile['id']}")
        refetched = self.client.get(f"/v1/engagements/{engagement['id']}").json()
        self.assertEqual(refetched["profiles"], [])

    def test_list_profiles_filter_by_cloud_provider(self):
        self.client.post("/v1/profiles", json={
            "name": "AWS Test Profile", "cloud_provider": "aws", "config_profile_name": "default",
        })
        items = self.client.get("/v1/profiles", params={"cloud_provider": "aws"}).json()["items"]
        self.assertTrue(all(p["cloud_provider"] == "aws" for p in items))
        self.assertTrue(any(p["name"] == "AWS Test Profile" for p in items))


class TestDBServiceEngagements(unittest.TestCase):
    """Engagements are a minimal many-to-many grouping of Profiles - no
    members/roles/audit trail, matching the deliberately narrowed scope."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def _make_profile(self, name, config_profile_name, cloud_provider="oci"):
        return self.client.post("/v1/profiles", json={
            "name": name, "cloud_provider": cloud_provider, "config_profile_name": config_profile_name,
        }).json()

    def test_create_engagement_with_profiles(self):
        p1 = self._make_profile("Engagement Profile 1", "ENG_P1")
        p2 = self._make_profile("Engagement Profile 2", "ENG_P2")
        created = self.client.post("/v1/engagements", json={
            "name": "Q4 External Pentest", "profile_ids": [p1["id"], p2["id"]],
        }).json()
        self.assertEqual(created["name"], "Q4 External Pentest")
        names = {p["name"] for p in created["profiles"]}
        self.assertEqual(names, {"Engagement Profile 1", "Engagement Profile 2"})

    def test_add_remove_profile_from_engagement(self):
        p1 = self._make_profile("Add Remove P1", "ADDRM_P1")
        engagement = self.client.post("/v1/engagements", json={
            "name": "Add Remove Engagement", "profile_ids": [],
        }).json()
        self.assertEqual(engagement["profiles"], [])

        added = self.client.post(
            f"/v1/engagements/{engagement['id']}/profiles", json={"profile_id": p1["id"]}
        ).json()
        self.assertEqual([p["id"] for p in added["profiles"]], [p1["id"]])

        removed = self.client.delete(f"/v1/engagements/{engagement['id']}/profiles/{p1['id']}").json()
        self.assertEqual(removed["profiles"], [])

    def test_update_engagement_scope_fields(self):
        engagement = self.client.post("/v1/engagements", json={
            "name": "Scoped Engagement", "profile_ids": [], "asset_classes": ["vm"], "regions": ["us-phoenix-1"],
        }).json()
        self.assertEqual(engagement["asset_classes"], ["vm"])
        updated = self.client.patch(f"/v1/engagements/{engagement['id']}", json={
            "asset_classes": ["vm", "bucket"],
        }).json()
        self.assertEqual(updated["asset_classes"], ["vm", "bucket"])
        self.assertEqual(updated["regions"], ["us-phoenix-1"])  # untouched field preserved

    def test_delete_engagement_removes_join_rows(self):
        p1 = self._make_profile("Delete Engagement P1", "DELENG_P1")
        engagement = self.client.post("/v1/engagements", json={
            "name": "Deletable Engagement", "profile_ids": [p1["id"]],
        }).json()
        resp = self.client.delete(f"/v1/engagements/{engagement['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.get(f"/v1/engagements/{engagement['id']}").status_code, 404)

    def test_v1_list_assets_filters_by_engagement(self):
        """/v1/assets?engagement_id=... should only return assets whose
        profile is a member of that engagement, across however many
        profiles the engagement groups - not just the active one."""
        p1 = self._make_profile("Engagement Filter P1", "ENGFILT_P1")
        p2 = self._make_profile("Engagement Filter P2", "ENGFILT_P2")
        engagement = self.client.post("/v1/engagements", json={
            "name": "Filter Engagement", "profile_ids": [p1["id"]],
        }).json()

        self.client.post("/assets/import", json={"assets": [
            {"asset_id": "eng-asset-in", "asset_type": "vm", "name": "In Engagement",
             "profile_id": p1["id"], "profile_name": p1["name"]},
            {"asset_id": "eng-asset-out", "asset_type": "vm", "name": "Outside Engagement",
             "profile_id": p2["id"], "profile_name": p2["name"]},
        ]})

        resp = self.client.get("/v1/assets", params={"engagement_id": engagement["id"]}).json()
        ids = {item["id"] for item in resp["items"]}
        self.assertIn("eng-asset-in", ids)
        self.assertNotIn("eng-asset-out", ids)


class TestDBServiceAuthWiring(unittest.TestCase):
    def test_request_without_token_is_rejected(self):
        with TestClient(db_service_app.app) as client:
            resp = client.get("/assets")
            self.assertEqual(resp.status_code, 401)

    def test_cors_headers_present_on_401_response(self):
        # A browser rejects a cross-origin response that lacks
        # Access-Control-Allow-Origin, surfacing it to JS as a generic
        # network failure rather than a readable 401 - which breaks the
        # frontend's "expired token -> clear storage, redirect to /login"
        # handling (it never sees a status at all). This only happens if
        # the auth-rejecting response bypasses CORSMiddleware, which
        # depends on add_middleware registration order.
        with TestClient(db_service_app.app) as client:
            resp = client.get(
                "/assets",
                headers={"Origin": "http://localhost:5173", "Authorization": "Bearer garbage-token"},
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.headers.get("access-control-allow-origin"), "http://localhost:5173")

    def test_health_does_not_require_token(self):
        with TestClient(db_service_app.app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)


class TestDBServiceFindingsDetail(unittest.TestCase):
    """Covers the description/remediation/PoC/affected-assets additions to
    the /v1/findings surface."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(
            db_service_app.app,
            headers={"Authorization": "Bearer test-internal-token"},
        )
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        self.client.post("/admin/clear")
        self.client.post("/assets/import", json={
            "assets": [
                {"asset_id": f"vm-{i}", "asset_type": "vm", "name": f"vm-{i}", "compartment": "Prod"}
                for i in range(1, 3)
            ],
            "source_description": "test",
        })
        self.client.post("/scan-results/bulk", json={"findings": [
            {
                "asset_id": f"vm-{i}", "check_id": "vm-public-ip", "check_name": "Public IP Exposure",
                "status": "WARNING", "severity": "HIGH",
                "message": "VM instance accessible via Public IP",
                "remediation": "Move VM to private subnet and use Bastion",
            }
            for i in range(1, 3)
        ]})

    def test_grouped_findings_include_description_and_remediation(self):
        resp = self.client.get("/v1/findings", params={"group_by": "rule"})
        self.assertEqual(resp.status_code, 200)
        items = resp.json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["description"], "VM instance accessible via Public IP")
        self.assertEqual(items[0]["remediation"], "Move VM to private subnet and use Bastion")

    def test_individual_findings_include_proof_of_concept(self):
        resp = self.client.get("/v1/findings")
        self.assertEqual(resp.status_code, 200)
        items = resp.json()["items"]
        self.assertTrue(items)
        self.assertIn("vm-1", items[0]["proof_of_concept"])

    def test_rule_assets_txt_download(self):
        resp = self.client.get("/v1/findings/rule/vm-public-ip/assets.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.headers["content-type"])
        self.assertIn('filename="vm-public-ip-affected-assets.txt"', resp.headers["content-disposition"])
        lines = resp.text.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("(vm-" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
