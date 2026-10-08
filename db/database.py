"""
Clouds8 - Database client facade

This module used to own the sqlite3 connection directly. It is now a thin
HTTP client for the standalone DB service (services/db-service/), which is
the ONLY process that opens clouds8.db. Every function here keeps its
original signature so existing callers (api/, ui/, sync.py, seed_data.py,
playbooks/, tests/) don't need to change - this facade is what "repoints
them to HTTP" transparently.

Raw-SQL callers that used to import `get_connection()` directly cannot be
preserved this way (there is no local SQLite connection anymore) - those
call sites were updated to use the new named functions below instead
(get_compartments_list, insert_scan_results, get_sync_progress,
get_assets_by_types).
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

import httpx

DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://localhost:8001")

_client = httpx.Client(
    base_url=DB_SERVICE_URL, timeout=30.0,
    headers={"Authorization": f"Bearer {os.getenv('INTERNAL_SERVICE_TOKEN', '')}"},
)


def _get(path: str, **params) -> Any:
    params = {k: v for k, v in params.items() if v is not None}
    r = _client.get(path, params=params)
    r.raise_for_status()
    return r.json()


def _post(path: str, json_body: Optional[dict] = None, **params) -> Any:
    params = {k: v for k, v in params.items() if v is not None}
    r = _client.post(path, json=json_body, params=params)
    r.raise_for_status()
    return r.json()


def _put(path: str, json_body: Optional[dict] = None) -> Any:
    r = _client.put(path, json=json_body)
    r.raise_for_status()
    return r.json()


def _patch(path: str, json_body: Optional[dict] = None, **params) -> Any:
    params = {k: v for k, v in params.items() if v is not None}
    r = _client.patch(path, json=json_body, params=params)
    r.raise_for_status()
    return r.json()


def get_db_path() -> Path:
    """Kept for compatibility; the DB is now owned by the db-service process."""
    return Path(f"remote:{DB_SERVICE_URL}")


def init_database():
    _post("/admin/init")


def import_assets(assets: List[Dict], source_description: str = "API Import") -> Dict[str, Any]:
    return _post("/assets/import", {"assets": assets, "source_description": source_description})


def import_from_json(json_path: str) -> Dict[str, Any]:
    with open(json_path, 'r') as f:
        data = json.load(f)
    assets = data if isinstance(data, list) else data.get('assets', [])
    return import_assets(assets, source_description=json_path)


def get_asset_summary() -> Dict[str, int]:
    return _get("/assets/summary")


def get_assets_by_type(asset_type: str, limit: int = 100, offset: int = 0) -> List[Dict]:
    return _get(f"/assets/by-type/{asset_type}", limit=limit, offset=offset)


def get_compartment_summary() -> Dict[str, int]:
    return _get("/assets/compartment-summary")


def get_scope_summary(scope_type: Optional[str] = None) -> Dict[str, int]:
    return _get("/assets/scope-summary", scope_type=scope_type)


def get_region_summary() -> Dict[str, int]:
    return _get("/assets/region-summary")


def get_region_type_summary() -> Dict[str, Dict[str, int]]:
    return _get("/assets/region-type-summary")


def upsert_service_costs(services: Dict[str, float], scannable_set: Optional[set] = None):
    _post("/costs", {"services": services, "scannable": list(scannable_set or [])})


def get_service_costs() -> List[Dict]:
    return _get("/costs")


def get_all_assets(limit: int = 1000, offset: int = 0) -> List[Dict]:
    return _get("/assets", limit=limit, offset=offset)


def get_assets_by_provider(provider: str, limit: int = 1000, offset: int = 0) -> List[Dict]:
    return _get(f"/assets/by-provider/{provider}", limit=limit, offset=offset)


def get_assets_by_types(asset_types: List[str], query: str = "", limit: int = 20) -> List[Dict]:
    return _get("/assets/by-types", types=",".join(asset_types), query=query, limit=limit)


def update_asset_scan_status(asset_id: str, status: str = "scanned", risk_score: Optional[int] = None):
    _patch(f"/assets/id/{asset_id}/scan-status", {"status": status, "risk_score": risk_score})


def mark_assets_scanned_by_type(asset_type: str, status: str = "scanned"):
    _patch(f"/assets/by-type/{asset_type}/scan-status", status=status)


def get_total_asset_count() -> int:
    return _get("/assets/count")["count"]


def get_sync_progress() -> Dict[str, int]:
    return _get("/assets/sync-progress")


def search_assets(query: str, limit: int = 50) -> List[Dict]:
    return _get("/assets/search", q=query, limit=limit)


def get_hierarchy_data() -> Dict:
    return _get("/assets/hierarchy")


def clear_database():
    _post("/admin/clear")


def import_compartments_from_csv(csv_path: str) -> int:
    import csv
    compartments = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            compartments.append({
                'name': row.get('Name', ''),
                'compartment_id': row.get('CompartmentId', ''),
                'parent_id': row.get('ParentCompartment', ''),
            })
    return import_compartments(compartments)


def import_compartments(compartments: List[Dict]) -> int:
    return _post("/compartments/import", {"compartments": compartments})["count"]


def get_compartments_list() -> List[Dict]:
    return _get("/compartments")


def get_compartments_for_sunburst() -> Dict[str, Any]:
    return _get("/compartments/sunburst")


def get_assets_by_compartment_label(compartment_label: str) -> List[Dict]:
    return _get(f"/compartments/{compartment_label}/assets")


def get_asset_counts_by_compartment(compartment_label: str) -> Dict[str, int]:
    return _get(f"/compartments/{compartment_label}/asset-counts")


def get_assets_by_compartment_and_type(compartment_label: str, asset_type: str) -> List[Dict]:
    return _get(f"/compartments/{compartment_label}/assets/{asset_type}")


def get_asset_by_id(asset_id: str) -> Optional[Dict]:
    r = _client.get(f"/assets/id/{asset_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_asset_by_name(name: str) -> Optional[Dict]:
    r = _client.get(f"/assets/name/{name}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def calculate_blast_radius(asset: Dict) -> Dict[str, Any]:
    return _post("/blast-radius/calculate", {"asset": asset})


def get_blast_radius_graph_data(asset: Dict) -> Dict[str, Any]:
    return _post("/blast-radius/graph", {"asset": asset})


def search_assets_for_blast_radius(query: str, limit: int = 20) -> List[Dict]:
    return _get("/blast-radius/search", q=query, limit=limit)


def insert_activity_log(level: str, source: str, message: str, ip: Optional[str] = None,
                         metadata: Optional[str] = None, timestamp: Optional[str] = None):
    _post("/logs", {
        "level": level, "source": source, "message": message,
        "ip": ip, "metadata": metadata, "timestamp": timestamp,
    })


def get_activity_logs(level: Optional[str] = None, source: Optional[str] = None,
                       search: Optional[str] = None, limit: int = 200) -> List[Dict]:
    return _get("/logs", level=level, source=source, search=search, limit=limit)


def get_log_stats() -> Dict[str, Any]:
    return _get("/logs/stats")


def save_config(key: str, value: str):
    _put(f"/config/{key}", {"value": value})


def get_config(key: str, default: Optional[str] = None) -> Optional[str]:
    return _get(f"/config/{key}", default=default)["value"]


def get_all_configs() -> Dict[str, str]:
    return _get("/config")


def get_recent_scan_findings(limit: int = 20) -> List[Dict]:
    return _get("/scan-results/recent", limit=limit)


def get_scan_results_by_asset_ids(asset_ids: List[str]) -> Dict[str, List[Dict]]:
    return _get("/scan-results/by-asset-ids", asset_ids=",".join(asset_ids))


def insert_scan_results(findings: List[Dict]) -> int:
    return _post("/scan-results/bulk", {"findings": findings})["inserted"]


def save_scan_report(scanner_type: str, report: dict):
    _put(f"/scan-reports/{scanner_type}", {"report": report})


def get_latest_scan_report(scanner_type: str) -> Optional[dict]:
    r = _client.get(f"/scan-reports/{scanner_type}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_most_recent_scanner_type() -> Optional[str]:
    return _get("/scan-reports/most-recent-type")["scanner_type"]


# ── Jobs ──────────────────────────────────────────────────────────────────────

def create_job(job_type: str, cloud_provider: Optional[str] = None, scope_id: Optional[str] = None,
                scan_depth: str = "rules", profile_id: Optional[str] = None,
                profile_name: Optional[str] = None, asset_ids: Optional[List[str]] = None) -> Dict:
    return _post("/jobs", {
        "job_type": job_type, "cloud_provider": cloud_provider, "scope_id": scope_id,
        "scan_depth": scan_depth, "profile_id": profile_id, "profile_name": profile_name,
        "asset_ids": asset_ids,
    })


def update_job(job_id: str, status: Optional[str] = None, progress_pct: Optional[int] = None,
                progress_message: Optional[str] = None, error_message: Optional[str] = None,
                result_ref: Optional[str] = None, started: bool = False, finished: bool = False) -> Dict:
    return _patch(f"/jobs/{job_id}", {
        "status": status, "progress_pct": progress_pct, "progress_message": progress_message,
        "error_message": error_message, "result_ref": result_ref, "started": started, "finished": finished,
    })


def get_job(job_id: str) -> Optional[Dict]:
    r = _client.get(f"/jobs/{job_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def list_jobs(
    job_type: Optional[str] = None, status: Optional[str] = None, limit: int = 100,
    profile_id: Optional[str] = None, engagement_id: Optional[str] = None,
) -> List[Dict]:
    return _get("/jobs", job_type=job_type, status=status, limit=limit, profile_id=profile_id, engagement_id=engagement_id)


# ── Schedules ─────────────────────────────────────────────────────────────────

def create_schedule(classes: List[str], provider: str, mode: str, next_run_at: str,
                     interval_value: Optional[int] = None, interval_unit: Optional[str] = None,
                     run_at: Optional[str] = None, scan_depth: str = "rules",
                     profile_id: Optional[str] = None, profile_name: Optional[str] = None,
                     compartment_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None,
                     asset_ids: Optional[List[str]] = None) -> Dict:
    return _post("/schedules", {
        "classes": classes, "provider": provider, "mode": mode, "next_run_at": next_run_at,
        "interval_value": interval_value, "interval_unit": interval_unit, "run_at": run_at,
        "scan_depth": scan_depth, "profile_id": profile_id, "profile_name": profile_name,
        "compartment_ids": compartment_ids, "regions": regions, "asset_ids": asset_ids,
    })


def update_schedule(schedule_id: str, status: Optional[str] = None, next_run_at: Optional[str] = None,
                     last_run_at: Optional[str] = None, last_run_id: Optional[str] = None) -> Optional[Dict]:
    return _patch(f"/schedules/{schedule_id}", {
        "status": status, "next_run_at": next_run_at, "last_run_at": last_run_at, "last_run_id": last_run_id,
    })


def get_schedule(schedule_id: str) -> Optional[Dict]:
    r = _client.get(f"/schedules/{schedule_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def list_schedules(status: Optional[str] = None, limit: int = 100) -> List[Dict]:
    return _get("/schedules", status=status, limit=limit)


def list_due_schedules(before: Optional[str] = None) -> List[Dict]:
    return _get("/schedules/due", before=before)


def delete_schedule(schedule_id: str) -> bool:
    r = _client.delete(f"/schedules/{schedule_id}")
    if r.status_code == 404:
        return False
    r.raise_for_status()
    return True


# ── V1 API facade — used by backend-api's routers/v1_runs.py ────────────────

def v1_list_assets(**params) -> Dict[str, Any]:
    return _get("/v1/assets", **params)


def v1_get_asset(asset_id: str) -> Optional[Dict]:
    r = _client.get(f"/v1/assets/{asset_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def v1_get_asset_findings(asset_id: str) -> List[Dict]:
    return _get(f"/v1/assets/{asset_id}/findings")


def v1_list_findings(**params) -> Dict[str, Any]:
    return _get("/v1/findings", **params)


def v1_patch_finding_state(finding_id: int, state: str) -> Optional[Dict]:
    r = _client.patch(f"/v1/findings/{finding_id}", json={"state": state})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_profile(profile_id: str) -> Optional[Dict]:
    r = _client.get(f"/v1/profiles/{profile_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_active_profile(cloud_provider: str) -> Optional[Dict]:
    r = _client.get("/v1/profiles/active", params={"cloud_provider": cloud_provider})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def update_profile(profile_id: str, **fields) -> Optional[Dict]:
    fields = {k: v for k, v in fields.items() if v is not None}
    r = _client.patch(f"/v1/profiles/{profile_id}", json=fields)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    init_database()
    print("Database initialized.")
