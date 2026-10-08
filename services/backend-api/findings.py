"""
Clouds8 Backend API - scan finding extraction

Ported from ui/pages/playbooks.py's _save_findings_to_db(), which used to run
UI-side inside each scanner's background thread. This is squarely Backend
API domain logic (interpreting a scanner's report shape), so it now runs
here as part of job completion - meaning any caller that triggers a scan
through this service (Dash UI, future CLI) gets findings persisted
automatically, not just the one UI page that used to embed this logic.

"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db.database import (
    get_active_profile, import_assets, insert_activity_log, insert_scan_results, mark_assets_scanned_by_type,
)

logger = logging.getLogger("Clouds8-BackendAPI")

_SCANNER_TO_ASSET_TYPES = {
    "vm": ["vm"],
    "bucket": ["bucket"],
    "secret": ["bucket"],
    "vault": ["vault"],
    "cis": ["vcn", "subnet", "nsg", "security_list", "lb"],
    "iam": ["policy", "user", "group", "dynamic_group"],
    "db": ["adb"],
    "volume": ["volume"],
    "image": ["image"],
    "oke": ["oke_cluster"],
    "functions": ["function_app"],
    "gcp_vm": ["gcp_vm"],
    "gcp_bucket": ["gcs_bucket"],
    "gcp_iam": ["gcp_service_account"],
    "gcp_db": ["cloudsql_instance"],
    "gcp_cis": [],
    "gcp_secrets": ["gcp_secret"],
    "gcp_gke": ["gke_cluster"],
    "gcp_functions": ["cloud_function"],
    "gcp_firewall": ["gcp_firewall_rule"],
}


def _import_assets(assets: List[Dict[str, Any]], scanner_type: str,
                    profile_id: Optional[str] = None, profile_name: Optional[str] = None,
                    provider: str = "oci") -> None:
    """Upsert asset rows straight from a scan report.

    Two distinct gaps this closes, across every scanner that has a usable
    per-resource list with name/compartment identity attached:
      - OKE clusters, Functions applications, Vaults, Block Volumes, Custom
        Images, and IAM Dynamic Groups have no `/sync` collection path at
        all (collectors/oci_collector.py doesn't enumerate them) - without
        this, their assets would never exist, and findings for them would be
        orphaned with nothing to join against in Inventory.
      - VM, Bucket, IAM Users, and IAM Groups assets *do* get a row from
        `/sync`, but only with a handful of coarse fields - IP addresses,
        real public-access-type, API key age, group membership counts, etc.
        are collected by the scanner and previously only ever used to derive
        a handful of findings, then discarded. This writes that richer
        per-resource detail into the asset's `metadata` (parsed into
        `properties` by the asset read API) so it's visible on the asset
        detail page's Raw configuration tab, not just as findings.
    Deliberately NOT extended to every scanner: `secret` has no resource
    list of its own (it only flags findings against bucket names already
    covered by the `bucket` scanner); `cis`'s check results only carry bare
    resource-id strings in `affected_resources`, with no name/compartment/
    region to build a correct asset row from; IAM `policy` has the same gap
    (the full policy list is collected internally but never reaches the
    report's to_dict()) - faking rows with placeholder identity would be
    worse than leaving them as-is.
    `import_assets`'s upsert merges metadata rather than replacing it, so
    this never clobbers what `/sync` (or a previous scan) already wrote.
    Runs regardless of scan_depth/findings, since inventory-only scans still
    collect the resource even when they skip checks.
    """
    if not assets:
        return
    if profile_id is None:
        try:
            active_profile = get_active_profile(provider)
        except Exception:
            active_profile = None
        if active_profile:
            profile_id, profile_name = active_profile["id"], active_profile["name"]
    for asset in assets:
        asset.setdefault("cloud_provider", provider)
        if profile_id:
            asset.setdefault("profile_id", profile_id)
            asset.setdefault("profile_name", profile_name)
    try:
        import_assets(assets, source_description=f"{scanner_type}-scanner")
    except Exception as e:
        logger.error(f"Failed to import {scanner_type} assets: {e}")


def persist_scan_findings(scanner_type: str, report: dict,
                           profile_id: Optional[str] = None, profile_name: Optional[str] = None,
                           provider: str = "oci", run_checks: bool = True) -> None:
    """Normalize and persist a scan report's actionable findings, and mark
    the relevant asset types as scanned.

    ``run_checks=False`` (inventory-only scans) still imports/updates asset
    rows from the report, but skips persisting rule-violation findings and
    tags assets "not_scanned" rather than "scanned" - they were listed, not
    checked against any rule.
    """
    if not report:
        return

    asset_scan_status = "scanned" if run_checks else "not_scanned"

    _import_assets_module = globals()["_import_assets"]

    def _import_assets(assets: List[Dict[str, Any]], scanner_type: str) -> None:
        return _import_assets_module(assets, scanner_type, profile_id=profile_id,
                                      profile_name=profile_name, provider=provider)

    findings: List[Tuple[str, ...]] = []  # 7-tuple for most scanners; iam's policy findings append 2 extra fields (subject, resource_compartment_id)

    if scanner_type == "vm":
        _import_assets([
            {
                "asset_id": vm.get("instance_id", ""),
                "asset_type": "vm",
                "name": vm.get("display_name", ""),
                "compartment": vm.get("compartment_name"),
                "region": vm.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "public_ips": vm.get("public_ips"),
                    "private_ips": vm.get("private_ips"),
                    "vnic_names": vm.get("vnic_names"),
                    "subnet_ids": vm.get("subnet_ids"),
                    "agent_monitoring": vm.get("agent_monitoring"),
                    "legacy_imds_disabled": vm.get("legacy_imds_disabled"),
                    "has_cloud_init": bool(vm.get("cloud_init_data")),
                    "freeform_tags": vm.get("freeform_tags"),
                    "compartment_id": vm.get("compartment_id"),
                    # Already redacted by VMDetail.to_dict() in vm_scanner.py
                    # before this report ever reaches us - never raw here.
                    "cloud_init_data": vm.get("cloud_init_data"),
                    "user_metadata": vm.get("user_metadata"),
                    "extended_metadata": vm.get("extended_metadata"),
                },
            }
            for vm in report.get("vms", [])
        ], scanner_type)
        for vm in report.get("vms", []):
            if vm.get("public_ips"):
                findings.append((
                    vm.get("instance_id", ""), "vm-public-ip", "Public IP Exposure",
                    "WARNING", "HIGH", "VM instance accessible via Public IP",
                    "Move VM to private subnet and use Bastion"
                ))
            if not vm.get("legacy_imds_disabled", True):
                findings.append((
                    vm.get("instance_id", ""), "vm-imds-v1", "Legacy IMDSv1 Enabled",
                    "CRITICAL", "CRITICAL", "Legacy IMDSv1 leaves VM vulnerable to SSRF credential theft",
                    "Update instance options to disable legacy IMDS endpoints"
                ))
            if vm.get("cloud_init_data"):
                findings.append((
                    vm.get("instance_id", ""), "vm-cloud-init", "Cleartext Cloud-Init",
                    "WARNING", "MEDIUM", "Cloud-init contains cleartext which may contain secrets",
                    "Use Vault secrets in cloud-init and use strict IAM policies"
                ))
            for mf in vm.get("metadata_findings", []):
                sev = (mf.get("severity") or "high").upper()
                findings.append((
                    vm.get("instance_id", ""),
                    f"vm-meta-{mf.get('source', 'metadata')}",
                    mf.get("finding_type", "Sensitive Metadata"),
                    "CRITICAL" if sev == "CRITICAL" else "WARNING",
                    sev,
                    f"Sensitive data in {mf.get('source', 'metadata')}: {mf.get('snippet', '?')}",
                    "Remove secrets from metadata and use OCI Vault instead"
                ))

    elif scanner_type == "secret":
        for f in report.get("findings", []):
            findings.append((
                f.get("bucket", "unknown"), f.get("finding_type", "secret-key"),
                f"Hardcoded {f.get('finding_type', 'Secret')}",
                "CRITICAL", "CRITICAL",
                f"Secret detected in object {f.get('file_name')}",
                "Rotate secret immediately and use OCI Vault"
            ))

    elif scanner_type == "bucket":
        _import_assets([
            {
                "asset_id": b.get("bucket_name", b.get("name", "")),
                "asset_type": "bucket",
                "name": b.get("bucket_name", b.get("name", "")),
                "compartment": b.get("compartment_name"),
                "region": b.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "public_access_type": b.get("public_access_type"),
                    "storage_tier": b.get("storage_tier"),
                    "versioning": b.get("versioning"),
                    "kms_key_id": b.get("kms_key_id"),
                    "approximate_count": b.get("approximate_count"),
                    "approximate_size": b.get("approximate_size"),
                    "replication_enabled": b.get("replication_enabled"),
                    "freeform_tags": b.get("freeform_tags"),
                },
            }
            for b in report.get("buckets", [])
        ], scanner_type)
        for b in report.get("buckets", []):
            bname = b.get("bucket_name", b.get("name", ""))
            if b.get("public_access_type") != "NoPublicAccess":
                findings.append((
                    bname, "bucket-public", "Public Bucket Exposure",
                    "CRITICAL", "CRITICAL", f"Bucket allows {b.get('public_access_type')}",
                    "Restrict bucket visibility to NoPublicAccess"
                ))
            for sf in b.get("sensitive_findings", []):
                sev = (sf.get("severity") or "high").upper()
                findings.append((
                    bname, f"bucket-secret-{sf.get('source', 'file')}",
                    sf.get("finding_type", "Sensitive Data"),
                    "CRITICAL" if sev == "CRITICAL" else "WARNING",
                    sev,
                    f"Sensitive object: {sf.get('object_name', '?')} in bucket {bname}",
                    "Remove or encrypt sensitive data and rotate exposed credentials"
                ))

    elif scanner_type == "cis":
        for check in report.get("results", []):
            if check.get("status") == "FAIL":
                asset_id = "tenancy" if not check.get("failing_resources") else str(check["failing_resources"][0])
                findings.append((
                    asset_id, check.get("check_id", "cis-check"), check.get("title", "CIS Policy Failure"),
                    "FAIL", check.get("severity", "HIGH"), check.get("description", "Failed CIS Benchmark"),
                    check.get("remediation", "Review IAM and Network Policies")
                ))

    elif scanner_type == "vault":
        _import_assets([
            {
                "asset_id": v.get("vault_id", ""),
                "asset_type": "vault",
                "name": v.get("display_name", ""),
                "compartment": v.get("compartment_name"),
                "region": report.get("region"),  # VaultDetail has no per-resource region
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": v.get("lifecycle_state"),
                    "vault_type": v.get("vault_type"),
                    "management_endpoint": v.get("management_endpoint"),
                    "compartment_id": v.get("compartment_id"),
                },
            }
            for v in report.get("vaults", [])
        ], scanner_type)
        now = datetime.now(timezone.utc)
        for v in report.get("vaults", []):
            if v.get("lifecycle_state") != "ACTIVE":
                continue
            for k in v.get("keys", []):
                if k.get("time_created"):
                    try:
                        created = datetime.fromisoformat(k["time_created"].replace("Z", "+00:00"))
                        if (now - created).days > 90:
                            findings.append((
                                k.get("id", ""), "vault-key-rotation", "Overdue Key Rotation",
                                "WARNING", "HIGH", f"Key {k.get('name')} is older than 90 days",
                                "Rotate encryption key version"
                            ))
                    except Exception:
                        pass

    elif scanner_type == "db":
        for adb in report.get("databases", []):
            for f in adb.get("findings", []):
                findings.append((
                    f.get("db_id", ""), f.get("check_id", "adb-check"),
                    f.get("title", "DB Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review database configuration")
                ))

    elif scanner_type == "volume":
        _import_assets([
            {
                "asset_id": vol.get("volume_id", ""),
                "asset_type": "volume",
                "name": vol.get("display_name", ""),
                "compartment": vol.get("compartment_name"),
                "region": vol.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": vol.get("lifecycle_state"),
                    "size_in_gbs": vol.get("size_in_gbs"),
                    "kms_key_id": vol.get("kms_key_id"),
                    "is_attached": vol.get("is_attached"),
                    "has_backup_policy": vol.get("has_backup_policy"),
                    "availability_domain": vol.get("availability_domain"),
                },
            }
            for vol in report.get("volumes", [])
        ], scanner_type)
        for vol in report.get("volumes", []):
            for f in vol.get("findings", []):
                findings.append((
                    f.get("volume_id", ""), f.get("check_id", "volume-check"),
                    f.get("title", "Volume Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review volume configuration")
                ))

    elif scanner_type == "image":
        _import_assets([
            {
                "asset_id": img.get("image_id", ""),
                "asset_type": "image",
                "name": img.get("display_name", ""),
                "compartment": img.get("compartment_name"),
                "region": img.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": img.get("lifecycle_state"),
                    "operating_system": img.get("operating_system"),
                    "operating_system_version": img.get("operating_system_version"),
                    "firmware": img.get("firmware"),
                    "is_pv_encryption_in_transit_enabled": img.get("is_pv_encryption_in_transit_enabled"),
                    "size_in_mbs": img.get("size_in_mbs"),
                    "base_image_id": img.get("base_image_id"),
                },
            }
            for img in report.get("images", [])
        ], scanner_type)
        for img in report.get("images", []):
            for f in img.get("findings", []):
                findings.append((
                    f.get("image_id", ""), f.get("check_id", "image-check"),
                    f.get("title", "Image Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review image configuration")
                ))

    elif scanner_type == "iam":
        # Policies aren't upserted here: the report's to_dict() never exposes
        # the full policy list (_run_live collects it internally as
        # `all_policies`, but only statement-level `findings` reach the
        # report) - no name/compartment/region is available to build a
        # correct asset row from, unlike users/groups/dynamic-groups below.
        _import_assets([
            {
                "asset_id": u.get("user_id", ""),
                "asset_type": "user",
                "name": u.get("user_name", ""),
                "compartment": u.get("compartment_name"),
                "region": report.get("region"),  # IAM is tenancy-wide, not regional
                "scan_status": asset_scan_status,
                "metadata": {
                    "email": u.get("email"),
                    "lifecycle_state": u.get("lifecycle_state"),
                    "is_mfa_activated": u.get("is_mfa_activated"),
                    "active_api_key_count": u.get("active_api_key_count"),
                    "oldest_active_api_key_age_days": u.get("oldest_active_api_key_age_days"),
                    "compartment_id": u.get("compartment_id"),
                },
            }
            for u in report.get("users", [])
        ], scanner_type)
        _import_assets([
            {
                "asset_id": g.get("group_id", ""),
                "asset_type": "group",
                "name": g.get("group_name", ""),
                "compartment": g.get("compartment_name"),
                "region": report.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": g.get("lifecycle_state"),
                    "member_count": g.get("member_count"),
                    "compartment_id": g.get("compartment_id"),
                },
            }
            for g in report.get("groups", [])
        ], scanner_type)
        _import_assets([
            {
                "asset_id": dg.get("dynamic_group_id", ""),
                "asset_type": "dynamic_group",
                "name": dg.get("dynamic_group_name", ""),
                "compartment": dg.get("compartment_name"),
                "region": report.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": dg.get("lifecycle_state"),
                    "matching_rule": dg.get("matching_rule"),
                    "compartment_id": dg.get("compartment_id"),
                },
            }
            for dg in report.get("dynamic_groups", [])
        ], scanner_type)
        # (a) existing PolicyFinding-shaped entries — closes the pre-existing
        # gap noted above: this scanner's findings were never persisted here.
        for f in report.get("findings", []):
            findings.append((
                f.get("policy_id", ""), f.get("finding_type", "iam-policy-check"),
                f.get("finding_type", "IAM Policy Finding"),
                f.get("risk_level", "HIGH"), f.get("risk_level", "HIGH"),
                f.get("description", ""),
                f.get("recommendation", "Review IAM policy configuration"),
                # subject/resource_compartment_id - attack_paths.py's edge
                # derivation needs these; every other scanner's findings
                # leave them unset (tuple stays 7-long, see the dict-mapper
                # below).
                f.get("affected_group", ""), f.get("compartment_id", ""),
            ))
        # (b) Users/Groups/Dynamic-Groups — image/volume-style nested findings
        for u in report.get("users", []):
            for f in u.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "iam-user-check"),
                    f.get("title", "User Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review user configuration")
                ))
        for g in report.get("groups", []):
            for f in g.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "iam-group-check"),
                    f.get("title", "Group Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review group configuration")
                ))
        for dg in report.get("dynamic_groups", []):
            for f in dg.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "iam-dynamicgroup-check"),
                    f.get("title", "Dynamic Group Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review dynamic group configuration")
                ))

    elif scanner_type == "oke":
        _import_assets([
            {
                "asset_id": c.get("cluster_id", ""),
                "asset_type": "oke_cluster",
                "name": c.get("display_name", ""),
                "compartment": c.get("compartment_name"),
                "region": c.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": c.get("lifecycle_state"),
                    "kubernetes_version": c.get("kubernetes_version"),
                    "compartment_id": c.get("compartment_id"),
                    "vcn_id": c.get("vcn_id"),
                    "node_pool_count": c.get("node_pool_count"),
                    "is_public_ip_enabled": c.get("is_public_ip_enabled"),
                    "is_image_policy_enabled": c.get("is_image_policy_enabled"),
                },
            }
            for c in report.get("clusters", [])
        ], scanner_type)
        for cluster in report.get("clusters", []):
            for f in cluster.get("findings", []):
                findings.append((
                    f.get("cluster_id", ""), f.get("check_id", "oke-check"),
                    f.get("title", "OKE Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review OKE cluster configuration")
                ))

    elif scanner_type == "functions":
        _import_assets([
            {
                "asset_id": a.get("application_id", ""),
                "asset_type": "function_app",
                "name": a.get("display_name", ""),
                "compartment": a.get("compartment_name"),
                "region": a.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "lifecycle_state": a.get("lifecycle_state"),
                    "function_count": a.get("function_count"),
                    "compartment_id": a.get("compartment_id"),
                    "subnet_count": a.get("subnet_count"),
                    "network_security_group_count": a.get("network_security_group_count"),
                    "image_policy_enabled": a.get("image_policy_enabled"),
                },
            }
            for a in report.get("applications", [])
        ], scanner_type)
        for app in report.get("applications", []):
            for f in app.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "functions-check"),
                    f.get("title", "Functions Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review Functions application configuration")
                ))

    elif scanner_type == "gcp_vm":
        _import_assets([
            {
                "asset_id": vm.get("instance_id", ""),
                "asset_type": "gcp_vm",
                "name": vm.get("name", ""),
                "compartment": vm.get("project_id"),
                "region": vm.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "zone": vm.get("zone"),
                    "machine_type": vm.get("machine_type"),
                    "status": vm.get("status"),
                    "has_external_ip": vm.get("has_external_ip"),
                    "external_ips": vm.get("external_ips"),
                },
            }
            for vm in report.get("vms", [])
        ], scanner_type)
        for vm in report.get("vms", []):
            for f in vm.get("findings", []):
                findings.append((
                    f.get("instance_id", ""), f.get("check_id", "gcp-vm-check"),
                    f.get("title", "GCP VM Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review GCP Compute instance configuration")
                ))

    elif scanner_type == "gcp_bucket":
        _import_assets([
            {
                "asset_id": b.get("bucket_name", ""),
                "asset_type": "gcs_bucket",
                "name": b.get("bucket_name", ""),
                "compartment": b.get("project_id"),
                "region": b.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "location": b.get("location"),
                    "storage_class": b.get("storage_class"),
                    "has_public_access": b.get("has_public_access"),
                    "uniform_bucket_level_access": b.get("uniform_bucket_level_access"),
                    "versioning_enabled": b.get("versioning_enabled"),
                },
            }
            for b in report.get("buckets", [])
        ], scanner_type)
        for b in report.get("buckets", []):
            for f in b.get("findings", []):
                findings.append((
                    f.get("bucket_name", ""), f.get("check_id", "gcp-bucket-check"),
                    f.get("title", "GCS Bucket Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review GCS bucket configuration")
                ))

    elif scanner_type == "gcp_iam":
        _import_assets([
            {
                "asset_id": sa.get("unique_id", ""),
                "asset_type": "gcp_service_account",
                "name": sa.get("email", ""),
                "compartment": sa.get("project_id"),
                "region": "global",
                "scan_status": asset_scan_status,
                "metadata": {
                    "disabled": sa.get("disabled"),
                    "has_user_keys": sa.get("has_user_keys"),
                    "has_public_binding": sa.get("has_public_binding"),
                },
            }
            for sa in report.get("service_accounts", [])
        ], scanner_type)
        for sa in report.get("service_accounts", []):
            for f in sa.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "gcp-iam-check"),
                    f.get("title", "GCP IAM Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review GCP IAM configuration")
                ))
        # Project-level privesc findings aren't tied to one service account.
        for f in report.get("findings", []):
            findings.append((
                f.get("resource_id", ""), f.get("check_id", "gcp-privesc-check"),
                f.get("title", "GCP Privilege Escalation Finding"),
                f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                f.get("detail", ""),
                f.get("remediation", "Review IAM permissions granted to this principal")
            ))

    elif scanner_type == "gcp_db":
        _import_assets([
            {
                "asset_id": d.get("db_id", ""),
                "asset_type": "cloudsql_instance",
                "name": d.get("name", ""),
                "compartment": d.get("project_id"),
                "region": d.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "database_version": d.get("database_version"),
                    "state": d.get("state"),
                    "has_public_ip": d.get("has_public_ip"),
                    "ssl_required": d.get("ssl_required"),
                },
            }
            for d in report.get("databases", [])
        ], scanner_type)
        for d in report.get("databases", []):
            for f in d.get("findings", []):
                findings.append((
                    f.get("db_id", ""), f.get("check_id", "gcp-db-check"),
                    f.get("title", "GCP Cloud SQL Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review Cloud SQL instance configuration")
                ))

    elif scanner_type == "gcp_cis":
        for check in report.get("results", []):
            if check.get("status") == "FAIL":
                affected = check.get("affected_resources") or []
                asset_id = str(affected[0]) if affected else "gcp"
                findings.append((
                    asset_id, check.get("check_id", "gcp-cis-check"), check.get("title", "GCP CIS Policy Failure"),
                    "FAIL", check.get("severity", "HIGH"), check.get("description", "Failed GCP CIS Benchmark"),
                    check.get("remediation", "Review GCP IAM and network policies")
                ))

    elif scanner_type == "gcp_secrets":
        _import_assets([
            {
                "asset_id": s.get("secret_id", ""),
                "asset_type": "gcp_secret",
                "name": s.get("secret_id", ""),
                "compartment": s.get("project_id"),
                "region": s.get("region", "global"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "replication_type": s.get("replication_type"),
                    "encryption_type": s.get("encryption_type"),
                    "rotation_enabled": s.get("rotation_enabled"),
                    "has_expiration": s.get("has_expiration"),
                    "has_public_access": s.get("has_public_access"),
                    "version_count": s.get("version_count"),
                },
            }
            for s in report.get("secrets", [])
        ], scanner_type)
        for s in report.get("secrets", []):
            for f in s.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "gcp-secrets-check"),
                    f.get("title", "GCP Secret Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review Secret Manager configuration")
                ))
        # Project-level privesc findings aren't tied to one secret.
        for f in report.get("findings", []):
            findings.append((
                f.get("resource_id", ""), f.get("check_id", "gcp-secrets-privesc-check"),
                f.get("title", "GCP Secrets Privilege Escalation Finding"),
                f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                f.get("detail", ""),
                f.get("remediation", "Review IAM permissions granted to this principal")
            ))

    elif scanner_type == "gcp_gke":
        _import_assets([
            {
                "asset_id": c.get("cluster_name", ""),
                "asset_type": "gke_cluster",
                "name": c.get("cluster_name", ""),
                "compartment": c.get("project_id"),
                "region": c.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "status": c.get("status"),
                    "k8s_version": c.get("k8s_version"),
                    "is_autopilot": c.get("is_autopilot"),
                    "has_public_master": c.get("has_public_master"),
                    "workload_identity_enabled": c.get("workload_identity_enabled"),
                    "network_policy_enabled": c.get("network_policy_enabled"),
                    "binary_auth_enabled": c.get("binary_auth_enabled"),
                },
            }
            for c in report.get("clusters", [])
        ], scanner_type)
        for c in report.get("clusters", []):
            for f in c.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "gcp-gke-check"),
                    f.get("title", "GCP GKE Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review GKE cluster configuration")
                ))
        # Project-level privesc findings aren't tied to one cluster.
        for f in report.get("findings", []):
            findings.append((
                f.get("resource_id", ""), f.get("check_id", "gcp-gke-privesc-check"),
                f.get("title", "GCP GKE Privilege Escalation Finding"),
                f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                f.get("detail", ""),
                f.get("remediation", "Review IAM permissions granted to this principal")
            ))

    elif scanner_type == "gcp_functions":
        _import_assets([
            {
                "asset_id": fn.get("function_name", ""),
                "asset_type": "cloud_function",
                "name": fn.get("function_name", ""),
                "compartment": fn.get("project_id"),
                "region": fn.get("region"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "runtime": fn.get("runtime"),
                    "state": fn.get("state"),
                    "trigger_type": fn.get("trigger_type"),
                    "allow_unauthenticated": fn.get("allow_unauthenticated"),
                    "sensitive_env_vars": fn.get("sensitive_env_vars"),
                    "uses_default_sa": fn.get("uses_default_sa"),
                },
            }
            for fn in report.get("functions", [])
        ], scanner_type)
        for fn in report.get("functions", []):
            for f in fn.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "gcp-functions-check"),
                    f.get("title", "GCP Cloud Function Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review Cloud Function configuration")
                ))
        # Project-level privesc findings aren't tied to one function.
        for f in report.get("findings", []):
            findings.append((
                f.get("resource_id", ""), f.get("check_id", "gcp-functions-privesc-check"),
                f.get("title", "GCP Functions Privilege Escalation Finding"),
                f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                f.get("detail", ""),
                f.get("remediation", "Review IAM permissions granted to this principal")
            ))

    elif scanner_type == "gcp_firewall":
        _import_assets([
            {
                "asset_id": r.get("rule_name", ""),
                "asset_type": "gcp_firewall_rule",
                "name": r.get("rule_name", ""),
                "compartment": r.get("project_id"),
                "region": r.get("region", "global"),
                "scan_status": asset_scan_status,
                "metadata": {
                    "network": r.get("network"),
                    "direction": r.get("direction"),
                    "disabled": r.get("disabled"),
                    "is_public_ingress": r.get("is_public_ingress"),
                    "has_all_traffic": r.get("has_all_traffic"),
                    "dangerous_ports": r.get("dangerous_ports"),
                },
            }
            for r in report.get("rules", [])
        ], scanner_type)
        for r in report.get("rules", []):
            for f in r.get("findings", []):
                findings.append((
                    f.get("resource_id", ""), f.get("check_id", "gcp-firewall-check"),
                    f.get("title", "GCP Firewall Finding"),
                    f.get("severity", "HIGH"), f.get("severity", "HIGH"),
                    f.get("detail", ""),
                    f.get("remediation", "Review VPC firewall rule configuration")
                ))

    if findings and run_checks:
        try:
            finding_dicts = [
                {
                    "asset_id": f[0], "check_id": f[1], "check_name": f[2],
                    "status": f[3], "severity": f[4], "message": f[5], "remediation": f[6],
                    **({"subject": f[7], "resource_compartment_id": f[8]} if len(f) > 7 else {}),
                }
                for f in findings
            ]
            insert_scan_results(finding_dicts)
            insert_activity_log("INFO", "system", f"Persisted {len(findings)} actionable threat findings to database")
        except Exception as e:
            logger.error(f"Failed to persist findings: {e}")

    try:
        for atype in _SCANNER_TO_ASSET_TYPES.get(scanner_type, []):
            mark_assets_scanned_by_type(atype, asset_scan_status)
    except Exception as e:
        logger.error(f"Failed to update scan_status: {e}")
