"""
Clouds8 - WhoAmI

Identifies a Profile's credential and enumerates its effective
permissions/risk for both GCP and OCI, on top of an already-constructed
collector's live clients (never rebuilds auth). Deliberately kept out of
GCPCollector/OCICollector - those stay focused on inventory/scanning;
this is a separate concern that happens to need their clients.

Two paths per provider:
  - "policy_lookup": read the identity's actual role/policy bindings.
  - "permission_probe": falls back to this when policy_lookup itself is
    denied - GCP's testIamPermissions (a dedicated "what can I do" API
    needing no special grant) or, for OCI (which has no such API),
    brute-forcing a curated list of cheap read-only calls and recording
    which succeed.
"""
import re
from typing import Any, Dict, List, Optional

_RISK_ORDER = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _max_risk(risks: List[str]) -> str:
    if not risks:
        return "NONE"
    return max(risks, key=lambda r: _RISK_ORDER.index(r))


def _classify_error(stage: str, call: str, exc: Exception) -> Dict[str, Any]:
    """Turn an SDK exception into a structured error entry. Duck-types
    both googleapiclient.errors.HttpError (.resp.status) and
    oci.exceptions.ServiceError (.status/.code) without importing either
    SDK here - whoami.py stays importable even where one SDK isn't
    installed.

    OCI's IAM API deliberately returns 404 NotAuthorizedOrNotFound for
    both "resource doesn't exist" and "you lack permission to see it" -
    conflating the two on purpose so a caller can't use the error to probe
    which OCIDs exist. Without checking `.code`, a genuine permission
    denial gets classified as NotFound instead of PermissionDenied, so the
    probe-fallback decision (which only fires on PermissionDenied) never
    triggers and a profile that actually has broader access downstream
    gets reported as UNKNOWN risk instead of being probed."""
    status: Optional[int] = None
    resp = getattr(exc, "resp", None)
    if resp is not None and hasattr(resp, "status"):
        status = resp.status
    elif hasattr(exc, "status") and isinstance(getattr(exc, "status"), int):
        status = exc.status

    message = str(exc)
    if status == 403 or getattr(exc, "code", None) == "NotAuthorizedOrNotFound":
        error_type = "PermissionDenied"
    elif status == 404:
        error_type = "NotFound"
    elif isinstance(exc, TimeoutError) or "timed out" in message.lower():
        error_type = "Timeout"
    else:
        error_type = "Unknown"

    return {
        "stage": stage,
        "call": call,
        "error_type": error_type,
        "http_status": status,
        "message": message[:500],
    }


class BaseWhoAmI:
    def __init__(self, collector):
        self.collector = collector

    def run(self) -> Dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        return {
            "identity": {},
            "method": "policy_lookup",
            "risk": "NONE",
            "roles": [],
            "permissions_confirmed": [],
            "permissions_denied": [],
            "errors": [],
        }


HIGH_RISK_ROLES = {
    "roles/owner": "CRITICAL",
    "roles/editor": "HIGH",
    "roles/iam.securityAdmin": "HIGH",
    "roles/iam.roleAdmin": "HIGH",
    "roles/resourcemanager.organizationAdmin": "CRITICAL",
    "roles/resourcemanager.projectIamAdmin": "HIGH",
    "roles/iam.serviceAccountAdmin": "HIGH",
    "roles/iam.serviceAccountTokenCreator": "HIGH",
    "roles/iam.serviceAccountKeyAdmin": "HIGH",
    "roles/storage.admin": "MEDIUM",
    "roles/bigquery.admin": "MEDIUM",
    "roles/secretmanager.admin": "HIGH",
    "roles/compute.admin": "MEDIUM",
    "roles/container.admin": "MEDIUM",
    "roles/cloudfunctions.admin": "MEDIUM",
    "roles/run.admin": "MEDIUM",
}

PROBE_PERMISSIONS = [
    "resourcemanager.projects.setIamPolicy", "resourcemanager.projects.getIamPolicy",
    "iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt",
    "iam.serviceAccountKeys.create", "iam.roles.create",
    "compute.instances.create", "compute.firewalls.create",
    "storage.buckets.setIamPolicy", "storage.objects.list",
    "secretmanager.secrets.list", "secretmanager.versions.access",
    "cloudsql.instances.create", "container.clusters.create", "cloudfunctions.functions.create",
]

PROBE_RISK = {
    "resourcemanager.projects.setIamPolicy": "CRITICAL",
    "iam.serviceAccounts.actAs": "CRITICAL",
    "iam.serviceAccounts.signJwt": "CRITICAL",
    "iam.serviceAccountKeys.create": "HIGH",
    "iam.roles.create": "HIGH",
    "storage.buckets.setIamPolicy": "HIGH",
    "compute.instances.create": "MEDIUM",
    "compute.firewalls.create": "MEDIUM",
    "cloudsql.instances.create": "MEDIUM",
    "container.clusters.create": "MEDIUM",
    "cloudfunctions.functions.create": "MEDIUM",
}


class GCPWhoAmI(BaseWhoAmI):
    def run(self) -> Dict[str, Any]:
        result = self._empty_result()
        sa_email = getattr(self.collector.credentials, "service_account_email", None) or ""
        result["identity"] = {
            "type": "service_account",
            "id": sa_email,
            "name": sa_email.split("@")[0] if sa_email else "",
        }

        crm = self.collector.clients.get("cloudresourcemanager")
        project_id = self.collector.project_id

        try:
            policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                members = binding.get("members", [])
                if any(sa_email and sa_email.lower() in m.lower() for m in members):
                    risk = HIGH_RISK_ROLES.get(role, "LOW")
                    result["roles"].append({"role": role, "risk": risk, "scope": f"project:{project_id}"})
            result["risk"] = _max_risk([r["risk"] for r in result["roles"]])
            return result
        except Exception as e:
            err = _classify_error("policy_lookup", "cloudresourcemanager.projects.getIamPolicy", e)
            result["errors"].append(err)
            if err["error_type"] != "PermissionDenied":
                result["risk"] = "UNKNOWN"
                return result

        result["method"] = "permission_probe"
        try:
            resp = crm.projects().testIamPermissions(
                resource=project_id, body={"permissions": PROBE_PERMISSIONS}
            ).execute()
            confirmed = resp.get("permissions", [])
            result["permissions_confirmed"] = confirmed
            result["permissions_denied"] = [p for p in PROBE_PERMISSIONS if p not in confirmed]
            result["risk"] = _max_risk([PROBE_RISK.get(p, "LOW") for p in confirmed])
        except Exception as e:
            result["errors"].append(
                _classify_error("probe", "cloudresourcemanager.projects.testIamPermissions", e)
            )
            result["risk"] = "UNKNOWN"
        return result


OCI_IAM_FAMILIES = {"groups", "policies", "users", "dynamic-groups"}

OCI_STATEMENT_RE = re.compile(
    r"allow group (\S+) to (\w+) ([\w-]+) in (tenancy|compartment)\s*(\S+)?",
    re.IGNORECASE,
)

# ponytail: object_storage's list_buckets needs a namespace_name (an extra
# discovery call away) that doesn't fit this probe's single-kwarg shape -
# skipped for now; add a namespace-aware special case if object storage
# visibility specifically needs confirming later.
PROBE_CALLS = [
    ("identity", "list_users", "compartment_id"),
    ("identity", "list_groups", "compartment_id"),
    ("identity", "list_policies", "compartment_id"),
    ("identity", "list_dynamic_groups", "compartment_id"),
    ("compute", "list_instances", "compartment_id"),
    ("network", "list_vcns", "compartment_id"),
    ("database", "list_autonomous_databases", "compartment_id"),
    ("kms_vault", "list_vaults", "compartment_id"),
    ("load_balancer", "list_load_balancers", "compartment_id"),
    ("container_engine", "list_clusters", "compartment_id"),
    ("functions_management", "list_applications", "compartment_id"),
    ("secrets", "list_secrets", "compartment_id"),
]


class OCIWhoAmI(BaseWhoAmI):
    def run(self) -> Dict[str, Any]:
        result = self._empty_result()
        tenancy_id = self.collector.config.get("tenancy")
        user_id = self.collector.config.get("user")
        identity_client = self.collector.clients.get("identity")

        result["identity"] = self._identity(identity_client, user_id)

        group_names = set()
        try:
            memberships = identity_client.list_user_group_memberships(
                compartment_id=tenancy_id, user_id=user_id
            ).data
            group_ids = {m.group_id for m in memberships}
            groups = identity_client.list_groups(compartment_id=tenancy_id).data
            group_names = {g.name for g in groups if g.id in group_ids}
        except Exception as e:
            err = _classify_error("policy_lookup", "identity.list_user_group_memberships", e)
            result["errors"].append(err)
            if err["error_type"] != "PermissionDenied":
                result["risk"] = "UNKNOWN"
                return result
            return self._probe_fallback(result, tenancy_id)

        try:
            policies = identity_client.list_policies(compartment_id=tenancy_id).data
            for policy in policies:
                for statement in policy.statements:
                    m = OCI_STATEMENT_RE.match(statement.strip())
                    if not m:
                        continue
                    group, verb, family, scope_type, scope_name = m.groups()
                    if group.lower() not in {g.lower() for g in group_names}:
                        continue
                    verb, family, scope_type = verb.lower(), family.lower(), scope_type.lower()
                    if family == "all-resources" and verb == "manage":
                        risk = "CRITICAL" if scope_type == "tenancy" else "HIGH"
                    elif verb == "manage" and family in OCI_IAM_FAMILIES:
                        risk = "HIGH"
                    elif verb == "manage":
                        risk = "MEDIUM"
                    else:
                        risk = "LOW"
                    result["roles"].append({
                        "role": statement.strip(),
                        "risk": risk,
                        "scope": f"{scope_type}:{scope_name or tenancy_id}",
                    })
        except Exception as e:
            err = _classify_error("policy_lookup", "identity.list_policies", e)
            result["errors"].append(err)
            if err["error_type"] != "PermissionDenied":
                result["risk"] = "UNKNOWN"
                return result
            return self._probe_fallback(result, tenancy_id)

        result["risk"] = _max_risk([r["risk"] for r in result["roles"]])
        return result

    def _probe_fallback(self, result: Dict[str, Any], tenancy_id: str) -> Dict[str, Any]:
        result["method"] = "permission_probe"
        confirmed: List[str] = []
        denied: List[str] = []
        for client_name, method_name, param_name in PROBE_CALLS:
            label = f"{client_name}.{method_name}"
            client = self.collector.clients.get(client_name)
            if client is None:
                denied.append(label)
                continue
            try:
                getattr(client, method_name)(**{param_name: tenancy_id})
                confirmed.append(label)
            except Exception as e:
                result["errors"].append(_classify_error("probe", label, e))
                denied.append(label)
        result["permissions_confirmed"] = confirmed
        result["permissions_denied"] = denied
        if confirmed and not denied:
            # Every probed call across every service succeeded - can't
            # literally confirm "read all-resources in tenancy" (OCI has no
            # single API for that), but broad read access across every
            # service this probe covers is itself the signal: full tenancy
            # visibility is a major reconnaissance/blast-radius finding for
            # a pentest tool even though it's read-only, and capping at
            # MEDIUM just because one identity.* call succeeded understates
            # it next to a narrower grant that only clears identity calls.
            result["risk"] = "HIGH"
        else:
            result["risk"] = _max_risk(["MEDIUM" if c.startswith("identity.") else "LOW" for c in confirmed])
        return result

    def _identity(self, identity_client, user_id: str) -> Dict[str, Any]:
        try:
            user = identity_client.get_user(user_id).data
            name = getattr(user, "name", None) or getattr(user, "description", None) or user_id
            return {"type": "user", "id": user_id, "name": name}
        except Exception:
            return {"type": "user", "id": user_id or "", "name": user_id or ""}


def get_whoami(provider: str, collector) -> BaseWhoAmI:
    if provider == "gcp":
        return GCPWhoAmI(collector)
    if provider == "oci":
        return OCIWhoAmI(collector)
    raise ValueError(f"No WhoAmI implementation for provider '{provider}'")
