"""
Tests for collectors/whoami.py - GCPWhoAmI/OCIWhoAmI identify a Profile's
credential and enumerate its effective permissions/risk. Mocks the SDK
boundary only (googleapiclient / oci clients) - never hits real cloud APIs.
"""
import unittest
from unittest.mock import MagicMock

from collectors.whoami import _classify_error, _max_risk, BaseWhoAmI, GCPWhoAmI


class _FakeHttpError(Exception):
    """Stands in for googleapiclient.errors.HttpError's .resp.status shape."""
    def __init__(self, status, message="denied"):
        super().__init__(message)
        self.resp = type("Resp", (), {"status": status})()


class _FakeServiceError(Exception):
    """Stands in for oci.exceptions.ServiceError's .status/.code shape."""
    def __init__(self, status, message="denied", code=None):
        super().__init__(message)
        self.status = status
        self.code = code


class TestMaxRisk(unittest.TestCase):
    def test_empty_list_is_none(self):
        self.assertEqual(_max_risk([]), "NONE")

    def test_picks_highest_severity(self):
        self.assertEqual(_max_risk(["LOW", "CRITICAL", "MEDIUM"]), "CRITICAL")

    def test_single_value(self):
        self.assertEqual(_max_risk(["HIGH"]), "HIGH")

    def test_unknown_mixed_with_known_risk_prefers_known(self):
        self.assertEqual(_max_risk(["UNKNOWN", "LOW"]), "LOW")
        self.assertEqual(_max_risk(["UNKNOWN", "CRITICAL"]), "CRITICAL")

    def test_all_unknown_returns_unknown(self):
        self.assertEqual(_max_risk(["UNKNOWN"]), "UNKNOWN")


class TestClassifyError(unittest.TestCase):
    def test_gcp_403_is_permission_denied(self):
        err = _classify_error("policy_lookup", "cloudresourcemanager.projects.getIamPolicy", _FakeHttpError(403))
        self.assertEqual(err["error_type"], "PermissionDenied")
        self.assertEqual(err["http_status"], 403)
        self.assertEqual(err["stage"], "policy_lookup")
        self.assertEqual(err["call"], "cloudresourcemanager.projects.getIamPolicy")

    def test_oci_403_is_permission_denied(self):
        err = _classify_error("probe", "identity.list_users", _FakeServiceError(403))
        self.assertEqual(err["error_type"], "PermissionDenied")

    def test_404_is_not_found(self):
        err = _classify_error("policy_lookup", "identity.list_policies", _FakeServiceError(404))
        self.assertEqual(err["error_type"], "NotFound")

    def test_oci_404_not_authorized_or_not_found_is_permission_denied(self):
        # OCI's IAM API deliberately returns 404 NotAuthorizedOrNotFound for
        # both "doesn't exist" and "you lack permission" - a real
        # permission denial must still trigger the probe-fallback path,
        # not be swallowed as a plain 404.
        err = _classify_error(
            "policy_lookup", "identity.list_user_group_memberships",
            _FakeServiceError(404, code="NotAuthorizedOrNotFound"),
        )
        self.assertEqual(err["error_type"], "PermissionDenied")

    def test_unrecognized_exception_is_unknown(self):
        err = _classify_error("identity", "oauth2.userinfo.get", ValueError("boom"))
        self.assertEqual(err["error_type"], "Unknown")
        self.assertIsNone(err["http_status"])

    def test_timeout_message_is_classified_timeout(self):
        err = _classify_error("probe", "compute.instances.list", TimeoutError("The read operation timed out"))
        self.assertEqual(err["error_type"], "Timeout")

    def test_message_is_truncated_to_500_chars(self):
        err = _classify_error("probe", "compute.instances.list", ValueError("x" * 1000))
        self.assertEqual(len(err["message"]), 500)


class TestBaseWhoAmI(unittest.TestCase):
    def test_run_not_implemented(self):
        base = BaseWhoAmI(collector=object())
        with self.assertRaises(NotImplementedError):
            base.run()


def _fake_gcp_collector(sa_email="sa@c0c0n-project-123.iam.gserviceaccount.com", project_id="c0c0n-project-123"):
    collector = MagicMock()
    collector.credentials.service_account_email = sa_email
    collector.project_id = project_id
    return collector


class TestGCPWhoAmI(unittest.TestCase):
    def test_identity_is_service_account(self):
        collector = _fake_gcp_collector()
        collector.clients = {"cloudresourcemanager": MagicMock()}
        collector.clients["cloudresourcemanager"].projects().getIamPolicy().execute.return_value = {"bindings": []}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["identity"], {
            "type": "service_account",
            "id": "sa@c0c0n-project-123.iam.gserviceaccount.com",
            "name": "sa",
        })

    def test_nice_path_finds_owner_role_as_critical(self):
        collector = _fake_gcp_collector()
        crm = MagicMock()
        crm.projects().getIamPolicy().execute.return_value = {
            "bindings": [
                {"role": "roles/owner", "members": ["serviceAccount:sa@c0c0n-project-123.iam.gserviceaccount.com"]},
                {"role": "roles/viewer", "members": ["user:someone-else@example.com"]},
            ]
        }
        collector.clients = {"cloudresourcemanager": crm}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["method"], "policy_lookup")
        self.assertEqual(result["risk"], "CRITICAL")
        self.assertEqual(result["roles"], [{"role": "roles/owner", "risk": "CRITICAL", "scope": "project:c0c0n-project-123"}])
        self.assertEqual(result["errors"], [])

    def test_nice_path_no_matching_bindings_is_none_risk(self):
        collector = _fake_gcp_collector()
        crm = MagicMock()
        crm.projects().getIamPolicy().execute.return_value = {
            "bindings": [{"role": "roles/viewer", "members": ["user:someone-else@example.com"]}]
        }
        collector.clients = {"cloudresourcemanager": crm}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["risk"], "NONE")
        self.assertEqual(result["roles"], [])

    def test_unknown_role_defaults_to_low_risk(self):
        collector = _fake_gcp_collector()
        crm = MagicMock()
        crm.projects().getIamPolicy().execute.return_value = {
            "bindings": [{"role": "roles/some.new.role", "members": ["serviceAccount:sa@c0c0n-project-123.iam.gserviceaccount.com"]}]
        }
        collector.clients = {"cloudresourcemanager": crm}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["roles"], [{"role": "roles/some.new.role", "risk": "LOW", "scope": "project:c0c0n-project-123"}])
        self.assertEqual(result["risk"], "LOW")

    def test_permission_denied_falls_back_to_probe(self):
        collector = _fake_gcp_collector()
        crm = MagicMock()
        crm.projects().getIamPolicy().execute.side_effect = _FakeHttpError(403)
        crm.projects().testIamPermissions().execute.return_value = {
            "permissions": ["compute.instances.create", "storage.objects.list"]
        }
        collector.clients = {"cloudresourcemanager": crm}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["method"], "permission_probe")
        self.assertEqual(sorted(result["permissions_confirmed"]), ["compute.instances.create", "storage.objects.list"])
        self.assertIn("resourcemanager.projects.setIamPolicy", result["permissions_denied"])
        self.assertEqual(result["risk"], "MEDIUM")  # compute.instances.create is MEDIUM, storage.objects.list defaults LOW
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["error_type"], "PermissionDenied")

    def test_non_permission_error_does_not_trigger_probe(self):
        collector = _fake_gcp_collector()
        crm = MagicMock()
        crm.projects().getIamPolicy().execute.side_effect = TimeoutError("The read operation timed out")
        collector.clients = {"cloudresourcemanager": crm}
        result = GCPWhoAmI(collector).run()
        self.assertEqual(result["method"], "policy_lookup")
        self.assertEqual(result["risk"], "UNKNOWN")
        crm.projects().testIamPermissions.assert_not_called()


from collectors.whoami import OCIWhoAmI, get_whoami


def _fake_group(group_id, name):
    g = MagicMock()
    g.id = group_id
    g.name = name
    return g


def _fake_membership(group_id):
    m = MagicMock()
    m.group_id = group_id
    return m


def _fake_policy(statements):
    p = MagicMock()
    p.statements = statements
    return p


def _full_oci_probe_clients(identity):
    """All 9 service clients PROBE_CALLS covers, as fresh MagicMocks that
    succeed by default - callers override specific methods with
    side_effect to simulate a denial."""
    return {
        "identity": identity, "compute": MagicMock(), "network": MagicMock(),
        "database": MagicMock(), "kms_vault": MagicMock(), "load_balancer": MagicMock(),
        "container_engine": MagicMock(), "functions_management": MagicMock(), "secrets": MagicMock(),
    }


def _fake_oci_collector(user_id="ocid1.user.oc1..fakeuser", tenancy_id="ocid1.tenancy.oc1..faketenancy"):
    collector = MagicMock()
    collector.config = {"tenancy": tenancy_id, "user": user_id}
    return collector


class TestOCIWhoAmI(unittest.TestCase):
    def test_identity_uses_get_user_name(self):
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "jane.doe@example.com"
        identity.list_user_group_memberships.return_value.data = []
        identity.list_groups.return_value.data = []
        identity.list_policies.return_value.data = []
        collector.clients = {"identity": identity}
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["identity"], {
            "type": "user", "id": "ocid1.user.oc1..fakeuser", "name": "jane.doe@example.com",
        })

    def test_tenancy_admin_statement_is_critical(self):
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "admin-sa"
        identity.list_user_group_memberships.return_value.data = [_fake_membership("grp-1")]
        identity.list_groups.return_value.data = [_fake_group("grp-1", "Administrators")]
        identity.list_policies.return_value.data = [
            _fake_policy(["Allow group Administrators to manage all-resources in tenancy"])
        ]
        collector.clients = {"identity": identity}
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["method"], "policy_lookup")
        self.assertEqual(result["risk"], "CRITICAL")
        self.assertEqual(len(result["roles"]), 1)
        self.assertEqual(result["roles"][0]["risk"], "CRITICAL")

    def test_compartment_scoped_manage_all_resources_is_high_not_critical(self):
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "svc-sa"
        identity.list_user_group_memberships.return_value.data = [_fake_membership("grp-1")]
        identity.list_groups.return_value.data = [_fake_group("grp-1", "ComputeAdmins")]
        identity.list_policies.return_value.data = [
            _fake_policy(["Allow group ComputeAdmins to manage all-resources in compartment prod"])
        ]
        collector.clients = {"identity": identity}
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["risk"], "HIGH")

    def test_statement_for_a_group_the_caller_is_not_in_is_ignored(self):
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "read-only-sa"
        identity.list_user_group_memberships.return_value.data = [_fake_membership("grp-2")]
        identity.list_groups.return_value.data = [
            _fake_group("grp-1", "Administrators"), _fake_group("grp-2", "Auditors"),
        ]
        identity.list_policies.return_value.data = [
            _fake_policy([
                "Allow group Administrators to manage all-resources in tenancy",
                "Allow group Auditors to inspect all-resources in tenancy",
            ])
        ]
        collector.clients = {"identity": identity}
        result = OCIWhoAmI(collector).run()
        self.assertEqual(len(result["roles"]), 1)
        self.assertEqual(result["roles"][0]["risk"], "LOW")

    def test_group_memberships_denied_falls_back_to_probe(self):
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "probe-sa"
        identity.list_user_group_memberships.side_effect = _FakeServiceError(403)
        identity.list_users.return_value = MagicMock()
        identity.list_groups.return_value = MagicMock()
        identity.list_policies.side_effect = _FakeServiceError(403)
        identity.list_dynamic_groups.side_effect = _FakeServiceError(403)
        collector.clients = _full_oci_probe_clients(identity)
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["method"], "permission_probe")
        self.assertIn("identity.list_users", result["permissions_confirmed"])
        self.assertIn("identity.list_groups", result["permissions_confirmed"])
        self.assertIn("identity.list_policies", result["permissions_denied"])
        self.assertIn("identity.list_dynamic_groups", result["permissions_denied"])
        # Some probes denied -> falls back to the per-call heuristic, not
        # the all-confirmed HIGH escalation.
        self.assertEqual(result["risk"], "MEDIUM")

    def test_all_probes_confirmed_is_high_risk(self):
        # Every probed call across every service succeeding is the signal
        # for a broad tenancy-wide read grant (e.g. "read all-resources in
        # tenancy") - must escalate past the narrow identity-only MEDIUM.
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "broad-read-sa"
        identity.list_user_group_memberships.side_effect = _FakeServiceError(403)
        collector.clients = _full_oci_probe_clients(identity)
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["method"], "permission_probe")
        self.assertEqual(result["permissions_denied"], [])
        self.assertEqual(result["risk"], "HIGH")

    def test_policies_denied_after_memberships_succeed_falls_back_to_probe(self):
        # Review Focus: partial success on the nice path (memberships OK,
        # policies denied) must still trigger the probe fallback, not
        # return an empty roles list as if the identity has zero access.
        collector = _fake_oci_collector()
        identity = MagicMock()
        identity.get_user.return_value.data.name = "partial-sa"
        identity.list_user_group_memberships.return_value.data = [_fake_membership("grp-1")]
        identity.list_groups.return_value.data = [_fake_group("grp-1", "SomeGroup")]
        identity.list_policies.side_effect = _FakeServiceError(403)
        identity.list_users.return_value = MagicMock()
        identity.list_dynamic_groups.side_effect = _FakeServiceError(403)
        compute = MagicMock()
        network = MagicMock()
        database = MagicMock()
        kms_vault = MagicMock()
        collector.clients = {
            "identity": identity, "compute": compute, "network": network,
            "database": database, "kms_vault": kms_vault,
        }
        result = OCIWhoAmI(collector).run()
        self.assertEqual(result["method"], "permission_probe")
        self.assertIn("identity.list_users", result["permissions_confirmed"])


class TestGetWhoAmI(unittest.TestCase):
    def test_gcp_provider_returns_gcp_whoami(self):
        self.assertIsInstance(get_whoami("gcp", _fake_gcp_collector()), GCPWhoAmI)

    def test_oci_provider_returns_oci_whoami(self):
        self.assertIsInstance(get_whoami("oci", _fake_oci_collector()), OCIWhoAmI)

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_whoami("aws", MagicMock())


if __name__ == "__main__":
    unittest.main()
