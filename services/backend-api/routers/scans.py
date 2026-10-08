"""
Clouds8 Backend API - Security scan endpoints

Triggers the playbook scanners as background jobs and exposes their status,
persisted reports and recent findings. Job state is persisted in the DB
service's `jobs` table (via db.database) rather than an in-memory registry.
"""
from typing import List, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import jobs
from collector import build_collector
from db import database as db
from playbooks.bucket_scanner import run_bucket_scan
from playbooks.cis_benchmark import run_cis_benchmark
from playbooks.db_scanner import run_db_scan
from playbooks.functions_scanner import run_functions_scan
from playbooks.gcp_bucket_scanner import run_gcp_bucket_scan
from playbooks.gcp_cis_benchmark import run_gcp_cis_scan
from playbooks.gcp_db_scanner import run_gcp_db_scan
from playbooks.gcp_firewall_scanner import run_gcp_firewall_scan
from playbooks.gcp_functions_scanner import run_gcp_functions_scan
from playbooks.gcp_gke_scanner import run_gcp_gke_scan
from playbooks.gcp_iam_scanner import run_gcp_iam_scan
from playbooks.gcp_secrets_scanner import run_gcp_secrets_scan
from playbooks.gcp_vm_scanner import run_gcp_vm_scan
from playbooks.iam_policy_audit import run_iam_audit
from playbooks.image_scanner import run_image_scan
from playbooks.oke_scanner import run_oke_scan
from playbooks.secret_scanner import run_secret_scan
from playbooks.vault_scanner import run_vault_scan
from playbooks.vm_scanner import run_vm_scan
from playbooks.volume_scanner import run_volume_scan

router = APIRouter(prefix="/scans", tags=["scans"])

# scanner_type -> (run function, supports_compartments, supports_regions, supports_assets)
# supports_regions: whether the scanner has a region concept at all (OCI
# per-region client loop, or a GCP-derived-region field) - iam/gcp_iam are
# genuinely global, gcp_cis has no region loop or derived region anywhere.
# supports_assets: whether a single-resource scan target makes sense -
# cis/gcp_cis are whole-tenancy benchmark checks with no single-resource seam.
SCANNERS = {
    "secret": (run_secret_scan, True, True, True),
    "cis": (run_cis_benchmark, False, True, False),
    "vm": (run_vm_scan, True, True, True),
    "vault": (run_vault_scan, True, True, True),
    "bucket": (run_bucket_scan, True, True, True),
    "iam": (run_iam_audit, True, False, True),
    "db": (run_db_scan, True, True, True),
    "volume": (run_volume_scan, True, True, True),
    "image": (run_image_scan, True, True, True),
    "oke": (run_oke_scan, True, True, True),
    "functions": (run_functions_scan, True, True, True),
    "gcp_vm": (run_gcp_vm_scan, True, True, True),
    "gcp_bucket": (run_gcp_bucket_scan, True, True, True),
    "gcp_iam": (run_gcp_iam_scan, True, False, True),
    "gcp_db": (run_gcp_db_scan, True, True, True),
    "gcp_cis": (run_gcp_cis_scan, True, False, False),
    # gcp_secrets: Secret Manager secrets are global/multi-region resources
    # with no per-secret region field - not region-scoped.
    "gcp_secrets": (run_gcp_secrets_scan, True, False, True),
    "gcp_gke": (run_gcp_gke_scan, True, True, True),
    "gcp_functions": (run_gcp_functions_scan, True, True, True),
    # gcp_firewall: VPC firewall rules are global to the network, not
    # regional (region defaults to the literal string "global").
    "gcp_firewall": (run_gcp_firewall_scan, True, False, True),
}


class ScanRequest(BaseModel):
    compartment_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None
    provider: str = "oci"
    scan_depth: Literal["inventory", "rules", "full"] = "rules"


@router.get("/scanners")
def list_scanners():
    """List the available scanner types."""
    return {"scanners": sorted(SCANNERS.keys())}


@router.post("/{scanner_type}", status_code=202)
def start_scan(scanner_type: str, req: ScanRequest = ScanRequest()):
    """Launch a scan in the background. Returns a job to poll for status."""
    entry = SCANNERS.get(scanner_type)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scanner '{scanner_type}'. Available: {sorted(SCANNERS)}",
        )
    runner, supports_compartments, supports_regions, supports_assets = entry
    collector = build_collector(req.provider)
    return jobs.start_scan(
        scanner_type,
        runner,
        collector=collector,
        provider=req.provider,
        compartment_ids=req.compartment_ids,
        supports_compartments=supports_compartments,
        regions=req.regions,
        supports_regions=supports_regions,
        asset_ids=req.asset_ids,
        supports_assets=supports_assets,
        scan_depth=req.scan_depth,
    )


@router.get("/jobs")
def list_scan_jobs():
    """List persisted scan jobs."""
    return db.list_jobs(job_type="scan")


@router.get("/jobs/{job_id}")
def get_scan_job(job_id: str):
    """Poll a scan job's status/progress. Once finished, fetch the report via /scans/reports/{scanner_type}."""
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return job


@router.get("/findings")
def recent_findings(limit: int = Query(20, ge=1, le=200)):
    """Most recent actionable scan findings across all scanners."""
    return db.get_recent_scan_findings(limit=limit)


@router.get("/reports/{scanner_type}")
def latest_report(scanner_type: str):
    """Return the most recent persisted report for a scanner type."""
    report = db.get_latest_scan_report(scanner_type)
    if report is None:
        raise HTTPException(
            status_code=404, detail=f"No saved report for scanner '{scanner_type}'"
        )
    return report
