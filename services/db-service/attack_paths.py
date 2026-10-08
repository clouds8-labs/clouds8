"""
Clouds8 DB Service - attack path derivation

Builds real attack paths from the three concrete edges that are actually
derivable from stored data today - not a generic graph framework, because
only three edge types exist:

  1. VM --(SSRF via legacy IMDSv1 + internet exposure)--> dynamic-group
     membership, evaluated against the dynamic group's OCI matching-rule
     text. Nothing else in this codebase ever evaluates a matching rule
     against a real instance - iam_policy_audit.py only has a shallow
     "does this rule look broad" heuristic over the rule's raw text.
  2. group/dynamic-group/user --(any risky IAM policy grant)--> target
     compartment (or tenancy-wide), via scan_results.subject/
     resource_compartment_id. These two columns are only ever populated by
     the `iam` scanner's policy findings (see findings.py's iam branch +
     store.py's schema). Every one of iam_policy_audit.py's finding types
     is reachable this way, not just the secret-specific ones - a
     MANAGE_ALL_COMPARTMENT grant reaches every asset in that compartment,
     not only vaults.
  3. compartment (or tenancy) --(contains)--> any asset whose type the
     grant's wording implies (secret-bundles -> vault, dynamic-groups ->
     dynamic_group, groups -> group; an unqualified "all-resources" grant
     has no type restriction), via that asset's own metadata.compartment_id
     or, where that's not captured, a name-match against the `compartments`
     table.

Entry points: vm, user, group, dynamic_group - the only asset types with
real principal/membership data captured. Functions, OKE, storage buckets,
and GCP assets are not supported yet: no attached-principal data exists
for them in the DB.
"""
import json
import re
from typing import Any, Dict, List, Optional

from store import get_connection, _LATEST_FINDINGS_CTE, _EXPOSURE_CHECK_IDS

_SEVERITY_SCORE = {"critical": 95, "high": 75, "medium": 50, "warning": 50, "low": 25, "info": 10}

# iam_policy_audit.py's finding_type -> the asset types its grant's wording
# implies ("secret-bundles", "dynamic-groups", "groups" keywords). A
# finding_type absent here (e.g. MANAGE_ALL_TENANCY, MANAGE_ALL_COMPARTMENT)
# is an unqualified "all-resources" grant - no type restriction, any asset
# in scope is a valid target.
_FINDING_TARGET_CLASSES: Dict[str, List[str]] = {
    "EXPLICIT_SECRET_ACCESS": ["vault"],
    "READ_ALL_TENANCY_SECRETS_EXPOSED": ["vault"],
    "MANAGE_DYNAMIC_GROUPS": ["dynamic_group"],
    "MANAGE_GROUPS": ["group"],
}

# finding_types whose statement grants "... in tenancy" rather than being
# scoped to the policy's own attachment compartment (matches the wording
# each check in iam_policy_audit.py's _audit_statement looks for).
_TENANCY_WIDE_FINDING_TYPES = {"MANAGE_ALL_TENANCY", "READ_ALL_TENANCY_SECRETS_EXPOSED", "ANY_USER_BROAD_ACCESS"}

# A compartment/tenancy-wide "any asset" grant can match thousands of rows -
# cap and bias toward the kinds of resources worth showing in a path.
_MAX_TARGETS_PER_FINDING = 8
_TARGET_PRIORITY = {"vault": 0, "adb": 1, "gcp_secret": 0, "cloudsql_instance": 1}

_RULE_PATTERN = re.compile(r"\s*(ALL|ANY)\s*\{(.+)\}\s*$", re.IGNORECASE)
_CLAUSE_PATTERN = re.compile(r"([\w.]+)\s*=\s*'([^']*)'")


def _parse_metadata(raw: Optional[str]) -> Dict[str, Any]:
    try:
        return json.loads(raw) if raw else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _matches_rule(rule: str, compartment_id: Optional[str], instance_id: str,
                   freeform_tags: Dict[str, str]) -> bool:
    """Evaluate a common subset of OCI dynamic-group matching-rule grammar
    against one instance's known attributes: ALL/ANY of one or more
    `{...}` equality clauses, or a single bare clause with no wrapper at
    all (valid OCI syntax for a one-condition rule - unlike an ALL/ANY
    wrapper omitted around *multiple* clauses, which is genuinely
    ambiguous, one clause has no ALL-vs-ANY distinction to guess at), over
    `instance.compartment.id`, `instance.id`, or
    `tag.<ns>.<key>.value`/`freeform_tag.<key>.value`. Anything else
    (resource.*, nested boolean groups, `!=`) is treated as non-matching
    rather than guessed - a false negative just omits a path; a false
    positive would fabricate one in a security tool, which is worse.
    """
    if not rule:
        return False
    rule = rule.strip()
    m = _RULE_PATTERN.match(rule)
    if m:
        combinator = m.group(1).upper()
        clauses = [c.strip() for c in m.group(2).split(",")]
    else:
        bare = _CLAUSE_PATTERN.fullmatch(rule)
        if not bare:
            return False
        combinator = "ALL"
        clauses = [rule]
    results = []
    for clause in clauses:
        cm = _CLAUSE_PATTERN.match(clause)
        if not cm:
            results.append(False)
            continue
        attr, value = cm.group(1).lower(), cm.group(2)
        if attr == "instance.compartment.id":
            results.append(bool(compartment_id) and compartment_id == value)
        elif attr == "instance.id":
            results.append(instance_id == value)
        elif attr.startswith("tag.") or attr.startswith("freeform_tag."):
            key = attr.split(".")[-2] if attr.startswith("tag.") else attr.split(".")[1]
            tag_value = next((v for k, v in freeform_tags.items() if k.lower() == key), "")
            results.append(str(tag_value) == value)
        else:
            results.append(False)
    if not results:
        return False
    return all(results) if combinator == "ALL" else any(results)


def _get_asset(conn, asset_id: str) -> Optional[Dict]:
    row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    return dict(row) if row else None


def _dynamic_groups_for_instance(conn, compartment_id: Optional[str], instance_id: str,
                                  freeform_tags: Dict[str, str]) -> List[Dict]:
    rows = conn.execute("SELECT * FROM assets WHERE asset_type = 'dynamic_group'").fetchall()
    members = []
    for r in rows:
        meta = _parse_metadata(r["metadata"])
        if _matches_rule(meta.get("matching_rule") or "", compartment_id, instance_id, freeform_tags):
            members.append(dict(r))
    return members


def _policy_findings_for_subject(conn, subject_name: str) -> List[Dict]:
    """Every latest, open IAM policy finding whose subject matches
    (case-insensitive) the given group/dynamic-group/user name - any
    finding_type, not just secret-access ones (a MANAGE_ALL_COMPARTMENT
    grant is just as real a path as an EXPLICIT_SECRET_ACCESS one)."""
    rows = conn.execute(
        f"""WITH {_LATEST_FINDINGS_CTE}
            SELECT * FROM latest_findings
            WHERE state != 'resolved' AND subject IS NOT NULL AND subject != ''
              AND LOWER(subject) = LOWER(?)""",
        (subject_name,),
    ).fetchall()
    return [dict(r) for r in rows]


def _compartment_name(conn, compartment_id: str) -> Optional[str]:
    row = conn.execute("SELECT name FROM compartments WHERE compartment_id = ?", (compartment_id,)).fetchone()
    return row["name"] if row else None


def _assets_in_scope(conn, compartment_id: Optional[str], asset_types: Optional[List[str]]) -> List[Dict]:
    """Assets a policy grant reaches: filtered by type when the grant's
    wording implies one, filtered by compartment unless the grant is
    tenancy-wide. Matches compartment by metadata.compartment_id where an
    asset has it; falls back to a name-match against the `compartments`
    table for asset types that only carry a compartment name (most of them -
    see findings.py's per-scanner metadata shape)."""
    type_clause = ""
    params: List[Any] = []
    if asset_types:
        type_clause = f"AND asset_type IN ({','.join('?' for _ in asset_types)})"
        params.extend(asset_types)
    rows = conn.execute(f"SELECT * FROM assets WHERE 1=1 {type_clause}", params).fetchall()
    if not compartment_id:
        return [dict(r) for r in rows]
    comp_name = _compartment_name(conn, compartment_id)
    out = []
    for r in rows:
        meta_comp_id = _parse_metadata(r["metadata"]).get("compartment_id")
        if meta_comp_id == compartment_id:
            out.append(dict(r))
        elif meta_comp_id is None and comp_name and r["compartment"] == comp_name:
            out.append(dict(r))
    return out


def _rank_targets(assets: List[Dict]) -> List[Dict]:
    ranked = sorted(assets, key=lambda a: (_TARGET_PRIORITY.get(a["asset_type"], 2), a["name"]))
    return ranked[:_MAX_TARGETS_PER_FINDING]


def _is_internet_exposed_with_imds_v1(conn, vm_asset_id: str) -> bool:
    placeholders = ",".join("?" for _ in _EXPOSURE_CHECK_IDS)
    rows = conn.execute(
        f"""WITH {_LATEST_FINDINGS_CTE}
            SELECT check_id FROM latest_findings
            WHERE asset_id = ? AND state != 'resolved'
              AND check_id IN ({placeholders}, 'vm-imds-v1')""",
        (vm_asset_id, *_EXPOSURE_CHECK_IDS),
    ).fetchall()
    found = {r["check_id"] for r in rows}
    return bool(found & set(_EXPOSURE_CHECK_IDS)) and "vm-imds-v1" in found


def _hop(asset: Dict, label: str) -> Dict:
    return {"asset_id": asset["asset_id"], "name": asset["name"], "type": asset["asset_type"], "label": label}


def compute_attack_paths(entry_asset_id: str) -> List[Dict]:
    """Reachable secret-exposure paths from one chosen entry-point asset."""
    with get_connection() as conn:
        entry = _get_asset(conn, entry_asset_id)
        if not entry:
            return []

        lead_hops: List[Dict] = []
        principals: List[Dict] = []

        if entry["asset_type"] == "vm":
            if not _is_internet_exposed_with_imds_v1(conn, entry_asset_id):
                return []
            meta = _parse_metadata(entry["metadata"])
            dgs = _dynamic_groups_for_instance(
                conn, meta.get("compartment_id"), entry_asset_id, meta.get("freeform_tags") or {},
            )
            if not dgs:
                return []
            lead_hops = [_hop(
                entry,
                "Internet-exposed with legacy IMDSv1 enabled - SSRF/RCE can steal the instance principal's credentials",
            )]
            principals = dgs
        elif entry["asset_type"] in ("user", "group", "dynamic_group"):
            principals = [entry]
        else:
            return []

        principal_label = (
            "Member of this dynamic group (matching rule evaluated against the VM above)"
            if lead_hops else "Entry point"
        )

        paths: List[Dict] = []
        for principal in principals:
            for finding in _policy_findings_for_subject(conn, principal["name"]):
                finding_type = finding.get("check_id") or ""
                comp_id = finding.get("resource_compartment_id")
                tenancy_wide = finding_type in _TENANCY_WIDE_FINDING_TYPES
                if not comp_id and not tenancy_wide:
                    continue  # compartment-scoped grant but no compartment captured - can't resolve a target
                target_classes = _FINDING_TARGET_CLASSES.get(finding_type)  # None = any asset type
                in_scope = _assets_in_scope(conn, None if tenancy_wide else comp_id, target_classes)
                # Reaching yourself isn't an attack path - an unqualified
                # "all-resources" grant always includes the granted
                # principal's own asset row.
                in_scope = [a for a in in_scope if a["asset_id"] not in (entry_asset_id, principal["asset_id"])]
                targets = _rank_targets(in_scope)
                severity = (finding.get("severity") or "high").lower()
                for target in targets:
                    hops = lead_hops + [
                        _hop(principal, principal_label),
                        {
                            "asset_id": finding["asset_id"], "name": finding["check_name"],
                            "type": "policy", "label": finding["message"],
                        },
                        _hop(target, "Reachable via this policy grant" + (" (tenancy-wide)" if tenancy_wide else "")),
                    ]
                    paths.append({
                        "id": f"{entry_asset_id}:{principal['asset_id']}:{finding['id']}:{target['asset_id']}",
                        "score": _SEVERITY_SCORE.get(severity, 50),
                        "severity": "critical" if severity == "critical" else "high",
                        "title": f"{entry['name']} → {target['name']}",
                        "hops": hops,
                    })

        paths.sort(key=lambda p: -p["score"])
        return paths


def _demo():
    assert _matches_rule("ALL {instance.compartment.id = 'c1'}", "c1", "i1", {}) is True
    assert _matches_rule("ALL {instance.compartment.id = 'c1'}", "c2", "i1", {}) is False
    assert _matches_rule("ANY {instance.id = 'i1', instance.id = 'i2'}", "c1", "i2", {}) is True
    assert _matches_rule("ALL {instance.id = 'i1', tag.CI.Role.value = 'runner'}", "c1", "i1", {"Role": "runner"}) is True
    assert _matches_rule("ALL {instance.id = 'i1', tag.CI.Role.value = 'runner'}", "c1", "i1", {"Role": "other"}) is False
    assert _matches_rule("", "c1", "i1", {}) is False
    assert _matches_rule("instance.id = 'i1'", "c1", "i1", {}) is True  # bare single clause, no wrapper needed
    assert _matches_rule("instance.id = 'i1'", "c1", "i2", {}) is False  # bare clause, no match
    assert _matches_rule("instance.id = 'i1', instance.id = 'i2'", "c1", "i1", {}) is False  # two bare clauses - genuinely ambiguous (ALL vs ANY), not guessed

    _demo_targets()
    print("attack_paths self-check OK")


def _demo_targets():
    """End-to-end check of the generalized (non-secret-only) target
    resolution against a throwaway in-memory DB: a compartment-scoped
    MANAGE_ALL_COMPARTMENT grant must reach a plain bucket (no type
    restriction), and a tenancy-wide grant must reach a target outside
    the granting policy's own compartment."""
    import os
    import tempfile
    import store

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    orig_db_file = store.DB_FILE
    store.DB_FILE = type(orig_db_file)(path)
    try:
        store.init_database()
        with store.get_connection() as conn:
            conn.execute(
                "INSERT INTO assets (asset_id, asset_type, name, compartment, metadata, cloud_provider) VALUES (?,?,?,?,?,?)",
                ("dg-1", "dynamic_group", "demo-dg", "CompA", json.dumps({"compartment_id": "comp-a"}), "oci"),
            )
            conn.execute(
                "INSERT INTO assets (asset_id, asset_type, name, compartment, metadata, cloud_provider) VALUES (?,?,?,?,?,?)",
                ("bucket-1", "bucket", "demo-bucket", "CompA", json.dumps({}), "oci"),
            )
            conn.execute(
                "INSERT INTO assets (asset_id, asset_type, name, compartment, metadata, cloud_provider) VALUES (?,?,?,?,?,?)",
                ("vault-other-comp", "vault", "other-comp-vault", "CompB", json.dumps({"compartment_id": "comp-b"}), "oci"),
            )
            conn.execute("INSERT INTO compartments (compartment_id, name) VALUES (?,?)", ("comp-a", "CompA"))
            conn.execute(
                "INSERT INTO scan_results (asset_id, check_id, check_name, status, severity, message, remediation, state, subject, resource_compartment_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("policy-1", "MANAGE_ALL_COMPARTMENT", "MANAGE_ALL_COMPARTMENT", "MEDIUM", "MEDIUM",
                 "Group 'demo-dg' can manage all resources in compartment.", "Review", "open", "demo-dg", "comp-a"),
            )
            conn.execute(
                "INSERT INTO scan_results (asset_id, check_id, check_name, status, severity, message, remediation, state, subject, resource_compartment_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("policy-2", "READ_ALL_TENANCY_SECRETS_EXPOSED", "READ_ALL_TENANCY_SECRETS_EXPOSED", "CRITICAL", "CRITICAL",
                 "Group 'demo-dg' can read ALL resources in the tenancy.", "Review", "open", "demo-dg", "comp-a"),
            )
            conn.commit()

        paths = compute_attack_paths("dg-1")
        targets = {p["title"].split(" → ")[1] for p in paths}
        assert "demo-bucket" in targets, "MANAGE_ALL_COMPARTMENT should reach a non-vault asset in its compartment"
        assert "other-comp-vault" in targets, "tenancy-wide grant should reach an asset outside its own compartment"
        assert "demo-dg" not in targets, "an unqualified grant must not produce a self-loop (principal reaching itself)"
    finally:
        store.DB_FILE = orig_db_file
        os.unlink(path)


if __name__ == "__main__":
    _demo()
