"""
Clouds8 shared client - typed HTTP client for the DB service.

Used by the Integration Service (Dash UI + future CLI) instead of importing
db/database.py's facade directly - that facade exists for Backend-API-side
and script (sync.py/seed_data.py) use. Functions are added here as pages
migrate off the facade; see services/db-service/app.py for the endpoints
still to cover.
"""
import os
from typing import Any, Dict, List, Optional

import httpx

from .config import DB_SERVICE_URL
from .schemas import Job, LogEntry, LogStats

_client = httpx.Client(
    base_url=DB_SERVICE_URL, timeout=30.0,
    headers={"Authorization": f"Bearer {os.getenv('INTERNAL_SERVICE_TOKEN', '')}"},
)


def get_activity_logs(level: Optional[str] = None, source: Optional[str] = None,
                       search: Optional[str] = None, limit: int = 200) -> List[LogEntry]:
    params = {k: v for k, v in {
        "level": level, "source": source, "search": search, "limit": limit,
    }.items() if v is not None}
    r = _client.get("/logs", params=params)
    r.raise_for_status()
    return [LogEntry(**row) for row in r.json()]


def get_log_stats() -> LogStats:
    r = _client.get("/logs/stats")
    r.raise_for_status()
    return LogStats(**r.json())


def get_total_asset_count() -> int:
    r = _client.get("/assets/count")
    r.raise_for_status()
    return r.json()["count"]


# ── Asset/compartment/cost reads (plain dict/list - shapes are heavily used
# by chart-building code with .get() access, not worth Pydantic-wrapping) ──

def get_asset_summary() -> Dict[str, int]:
    r = _client.get("/assets/summary")
    r.raise_for_status()
    return r.json()


def get_compartment_summary() -> Dict[str, int]:
    r = _client.get("/assets/compartment-summary")
    r.raise_for_status()
    return r.json()


def get_region_summary() -> Dict[str, int]:
    r = _client.get("/assets/region-summary")
    r.raise_for_status()
    return r.json()


def get_region_type_summary() -> Dict[str, Dict[str, int]]:
    r = _client.get("/assets/region-type-summary")
    r.raise_for_status()
    return r.json()


def get_assets_by_provider(provider: str, limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
    r = _client.get(f"/assets/by-provider/{provider}", params={"limit": limit, "offset": offset})
    r.raise_for_status()
    return r.json()


def get_all_assets(limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
    r = _client.get("/assets", params={"limit": limit, "offset": offset})
    r.raise_for_status()
    return r.json()


def get_assets_by_type(asset_type: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    r = _client.get(f"/assets/by-type/{asset_type}", params={"limit": limit, "offset": offset})
    r.raise_for_status()
    return r.json()


def get_assets_by_types(asset_types: List[str], query: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    r = _client.get("/assets/by-types", params={"types": ",".join(asset_types), "query": query, "limit": limit})
    r.raise_for_status()
    return r.json()


def get_sync_progress() -> Dict[str, int]:
    r = _client.get("/assets/sync-progress")
    r.raise_for_status()
    return r.json()


def get_recent_scan_findings(limit: int = 20) -> List[Dict[str, Any]]:
    r = _client.get("/scan-results/recent", params={"limit": limit})
    r.raise_for_status()
    return r.json()


def get_compartments_for_sunburst() -> Dict[str, Any]:
    r = _client.get("/compartments/sunburst")
    r.raise_for_status()
    return r.json()


def get_asset_counts_by_compartment(compartment_label: str) -> Dict[str, int]:
    r = _client.get(f"/compartments/{compartment_label}/asset-counts")
    r.raise_for_status()
    return r.json()


def get_assets_by_compartment_and_type(compartment_label: str, asset_type: str) -> List[Dict[str, Any]]:
    r = _client.get(f"/compartments/{compartment_label}/assets/{asset_type}")
    r.raise_for_status()
    return r.json()


def get_service_costs() -> List[Dict[str, Any]]:
    r = _client.get("/costs")
    r.raise_for_status()
    return r.json()


# ── Jobs (generic status polling - job state lives in the DB service
# regardless of which service triggered the job) ───────────────────────────

def get_job(job_id: str) -> Optional[Job]:
    r = _client.get(f"/jobs/{job_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return Job(**r.json())
