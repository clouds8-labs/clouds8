"""
Clouds8 DB Service

Owns the sole SQLite connection to clouds8.db. Every other service/process
(Backend API, Dash UI, sync.py, seed_data.py, CLI) talks to this over HTTP
instead of importing sqlite3 directly - this is what fixes the historical
"three uncoordinated writers" concurrency bug.

Run with:
    uvicorn app:app --port 8001 --reload   (from services/db-service/)
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import auth
import store
from routers import engagements, profiles, v1

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_database()
    yield


app = FastAPI(title="Clouds8 DB Service", version="1.0.0", lifespan=lifespan)


# Registered before CORSMiddleware below so CORS ends up outermost in the
# final stack: Starlette's add_middleware() inserts at the front of the
# middleware list, so the middleware added LAST wraps everything added
# before it. CORS must be outermost so it can both answer preflight
# OPTIONS requests and attach Access-Control-Allow-Origin to every
# response this middleware returns - including its own 401s - not just
# responses that reach the router.
@app.middleware("http")
async def _require_auth(request: Request, call_next):
    return await auth.auth_middleware(request, call_next)


# CORS: the Dash UI/lynxctl are server-side Python (never subject to CORS),
# but the new React frontend runs in the browser and calls this service's
# /v1 endpoints directly - so its dev/build origins need to be allowed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(v1.router)
app.include_router(profiles.router)
app.include_router(engagements.router)


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Admin ──────────────────────────────────────────────────────────────────

@app.post("/admin/init")
def admin_init():
    store.init_database()
    return {"status": "ok"}


@app.post("/admin/clear")
def admin_clear():
    store.clear_database()
    return {"status": "ok"}


# ── Assets ─────────────────────────────────────────────────────────────────

class ImportAssetsRequest(BaseModel):
    assets: List[Dict[str, Any]]
    source_description: str = "API Import"


@app.post("/assets/import")
def import_assets(req: ImportAssetsRequest):
    return store.import_assets(req.assets, req.source_description)


@app.get("/assets")
def get_all_assets(limit: int = 1000, offset: int = 0):
    return store.get_all_assets(limit, offset)


@app.get("/assets/count")
def get_total_asset_count():
    return {"count": store.get_total_asset_count()}


@app.get("/assets/summary")
def get_asset_summary():
    return store.get_asset_summary()


@app.get("/assets/compartment-summary")
def get_compartment_summary(profile_id: Optional[str] = None, engagement_id: Optional[str] = None):
    return store.get_compartment_summary(profile_id=profile_id, engagement_id=engagement_id)


@app.get("/assets/scope-summary")
def get_scope_summary(scope_type: Optional[str] = None):
    return store.get_scope_summary(scope_type)


@app.get("/assets/region-summary")
def get_region_summary():
    return store.get_region_summary()


@app.get("/assets/region-type-summary")
def get_region_type_summary():
    return store.get_region_type_summary()


@app.get("/assets/by-type/{asset_type}")
def get_assets_by_type(asset_type: str, limit: int = 100, offset: int = 0):
    return store.get_assets_by_type(asset_type, limit, offset)


@app.get("/assets/by-provider/{provider}")
def get_assets_by_provider(provider: str, limit: int = 1000, offset: int = 0):
    return store.get_assets_by_provider(provider, limit, offset)


@app.get("/assets/by-types")
def get_assets_by_types(types: str, query: str = "", limit: int = 20):
    """`types` is a comma-separated list, e.g. 'vm,adb,lb'."""
    return store.get_assets_by_types(types.split(","), query, limit)


@app.get("/assets/search")
def search_assets(q: str, limit: int = 50):
    return store.search_assets(q, limit)


@app.get("/assets/hierarchy")
def get_hierarchy_data():
    return store.get_hierarchy_data()


@app.get("/assets/sync-progress")
def get_sync_progress():
    return store.get_sync_progress()


@app.get("/assets/id/{asset_id:path}")
def get_asset_by_id(asset_id: str):
    asset = store.get_asset_by_id(asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    return asset


@app.get("/assets/name/{name}")
def get_asset_by_name(name: str):
    asset = store.get_asset_by_name(name)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    return asset


class ScanStatusUpdate(BaseModel):
    status: str = "scanned"
    risk_score: Optional[int] = None


@app.patch("/assets/id/{asset_id:path}/scan-status")
def update_asset_scan_status(asset_id: str, req: ScanStatusUpdate):
    store.update_asset_scan_status(asset_id, req.status, req.risk_score)
    return {"status": "ok"}


@app.patch("/assets/by-type/{asset_type}/scan-status")
def mark_assets_scanned_by_type(asset_type: str, status: str = "scanned"):
    store.mark_assets_scanned_by_type(asset_type, status)
    return {"status": "ok"}


# ── Compartments / scopes ────────────────────────────────────────────────────

class ImportCompartmentsRequest(BaseModel):
    compartments: List[Dict[str, Any]]


@app.post("/compartments/import")
def import_compartments(req: ImportCompartmentsRequest):
    return {"count": store.import_compartments(req.compartments)}


@app.get("/compartments")
def get_compartments_list(cloud_provider: Optional[str] = None):
    return store.get_compartments_list(cloud_provider)


@app.get("/regions")
def get_regions_list(cloud_provider: Optional[str] = None):
    return store.get_regions_list(cloud_provider)


@app.get("/compartments/sunburst")
def get_compartments_for_sunburst():
    return store.get_compartments_for_sunburst()


@app.get("/compartments/{label}/assets")
def get_assets_by_compartment_label(label: str):
    return store.get_assets_by_compartment_label(label)


@app.get("/compartments/{label}/asset-counts")
def get_asset_counts_by_compartment(label: str, profile_id: Optional[str] = None, engagement_id: Optional[str] = None):
    return store.get_asset_counts_by_compartment(label, profile_id=profile_id, engagement_id=engagement_id)


@app.get("/compartments/{label}/assets/{asset_type}")
def get_assets_by_compartment_and_type(label: str, asset_type: str):
    return store.get_assets_by_compartment_and_type(label, asset_type)


# ── Blast radius ──────────────────────────────────────────────────────────────

class AssetPayload(BaseModel):
    asset: Dict[str, Any]


@app.post("/blast-radius/calculate")
def calculate_blast_radius(req: AssetPayload):
    return store.calculate_blast_radius(req.asset)


@app.post("/blast-radius/graph")
def get_blast_radius_graph_data(req: AssetPayload):
    return store.get_blast_radius_graph_data(req.asset)


@app.get("/blast-radius/search")
def search_assets_for_blast_radius(q: str, limit: int = 20):
    return store.search_assets_for_blast_radius(q, limit)


# ── Service costs ─────────────────────────────────────────────────────────────

class UpsertCostsRequest(BaseModel):
    services: Dict[str, float]
    scannable: List[str] = []


@app.post("/costs")
def upsert_service_costs(req: UpsertCostsRequest):
    store.upsert_service_costs(req.services, set(req.scannable))
    return {"status": "ok"}


@app.get("/costs")
def get_service_costs():
    return store.get_service_costs()


# ── Activity logs ──────────────────────────────────────────────────────────────

class LogEntryRequest(BaseModel):
    level: str = "INFO"
    source: str = "system"
    message: str
    ip: Optional[str] = None
    metadata: Optional[str] = None
    timestamp: Optional[str] = None


@app.post("/logs")
def insert_activity_log(req: LogEntryRequest):
    store.insert_activity_log(req.level, req.source, req.message, req.ip, req.metadata, req.timestamp)
    return {"status": "ok"}


@app.get("/logs")
def get_activity_logs(level: Optional[str] = None, source: Optional[str] = None,
                       search: Optional[str] = None, limit: int = 200):
    return store.get_activity_logs(level, source, search, limit)


@app.get("/logs/stats")
def get_log_stats():
    return store.get_log_stats()


# ── Config ─────────────────────────────────────────────────────────────────────

class ConfigValue(BaseModel):
    value: str


@app.get("/config")
def get_all_configs():
    return store.get_all_configs()


@app.get("/config/{key}")
def get_config(key: str, default: Optional[str] = None):
    return {"key": key, "value": store.get_config(key, default)}


@app.put("/config/{key}")
def save_config(key: str, req: ConfigValue):
    store.save_config(key, req.value)
    return {"key": key, "value": req.value}


# ── Scan findings / reports ───────────────────────────────────────────────────

@app.get("/scan-results/recent")
def get_recent_scan_findings(limit: int = 20):
    return store.get_recent_scan_findings(limit)


@app.get("/scan-results/by-asset-ids")
def get_scan_results_by_asset_ids(asset_ids: str):
    """`asset_ids` is a comma-separated list."""
    return store.get_scan_results_by_asset_ids(asset_ids.split(","))


class ScanResultsBulk(BaseModel):
    findings: List[Dict[str, Any]]


@app.post("/scan-results/bulk")
def insert_scan_results(req: ScanResultsBulk):
    return {"inserted": store.insert_scan_results(req.findings)}


class ScanReportPayload(BaseModel):
    report: Dict[str, Any]


# NOTE: static-path routes (most-recent-type) must be registered before the
# /scan-reports/{scanner_type} path-param route below, otherwise FastAPI
# matches them as a literal scanner_type and 404s.
@app.get("/scan-reports/most-recent-type")
def get_most_recent_scanner_type():
    return {"scanner_type": store.get_most_recent_scanner_type()}


@app.put("/scan-reports/{scanner_type}")
def save_scan_report(scanner_type: str, req: ScanReportPayload):
    store.save_scan_report(scanner_type, req.report)
    return {"status": "ok"}


@app.get("/scan-reports/{scanner_type}")
def get_latest_scan_report(scanner_type: str):
    report = store.get_latest_scan_report(scanner_type)
    if report is None:
        raise HTTPException(404, "No report found for this scanner type")
    return report


# ── Jobs ───────────────────────────────────────────────────────────────────────

class CreateJobRequest(BaseModel):
    job_type: str
    cloud_provider: Optional[str] = None
    scope_id: Optional[str] = None
    scan_depth: Optional[str] = "rules"
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    asset_ids: Optional[List[str]] = None


@app.post("/jobs")
def create_job(req: CreateJobRequest):
    return store.create_job(req.job_type, req.cloud_provider, req.scope_id, req.scan_depth or "rules",
                             req.profile_id, req.profile_name, req.asset_ids)


class UpdateJobRequest(BaseModel):
    status: Optional[str] = None
    progress_pct: Optional[int] = None
    progress_message: Optional[str] = None
    error_message: Optional[str] = None
    result_ref: Optional[str] = None
    started: bool = False
    finished: bool = False


@app.patch("/jobs/{job_id}")
def update_job(job_id: str, req: UpdateJobRequest):
    job = store.update_job(
        job_id, status=req.status, progress_pct=req.progress_pct,
        progress_message=req.progress_message, error_message=req.error_message,
        result_ref=req.result_ref, started=req.started, finished=req.finished,
    )
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/jobs")
def list_jobs(
    job_type: Optional[str] = None, status: Optional[str] = None, limit: int = 100,
    profile_id: Optional[str] = None, engagement_id: Optional[str] = None,
):
    return store.list_jobs(job_type, status, limit, profile_id=profile_id, engagement_id=engagement_id)


# ── Schedules ────────────────────────────────────────────────────────────────

class CreateScheduleRequest(BaseModel):
    classes: List[str]
    provider: str = "oci"
    mode: str
    next_run_at: str
    interval_value: Optional[int] = None
    interval_unit: Optional[str] = None
    run_at: Optional[str] = None
    scan_depth: Optional[str] = "rules"
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    compartment_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None


@app.post("/schedules")
def create_schedule(req: CreateScheduleRequest):
    return store.create_schedule(
        req.classes, req.provider, req.mode, req.next_run_at,
        req.interval_value, req.interval_unit, req.run_at,
        req.scan_depth or "rules", req.profile_id, req.profile_name,
        req.compartment_ids, req.regions, req.asset_ids,
    )


class UpdateScheduleRequest(BaseModel):
    status: Optional[str] = None
    next_run_at: Optional[str] = None
    last_run_at: Optional[str] = None
    last_run_id: Optional[str] = None


@app.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: str, req: UpdateScheduleRequest):
    sched = store.update_schedule(
        schedule_id, status=req.status, next_run_at=req.next_run_at,
        last_run_at=req.last_run_at, last_run_id=req.last_run_id,
    )
    if sched is None:
        raise HTTPException(404, "Schedule not found")
    return sched


# Must be declared before /schedules/{schedule_id} below, same reasoning as
# /scan-reports/most-recent-type above /scan-reports/{scanner_type}.
@app.get("/schedules/due")
def list_due_schedules(before: Optional[str] = None):
    # backend-api always passes `before` explicitly (UTC-aware, see
    # scheduler.py); this fallback exists only for manual/ad-hoc calls.
    return store.list_due_schedules(before or datetime.now(timezone.utc).isoformat())


@app.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: str):
    sched = store.get_schedule(schedule_id)
    if sched is None:
        raise HTTPException(404, "Schedule not found")
    return sched


@app.get("/schedules")
def list_schedules(status: Optional[str] = None, limit: int = 100):
    return store.list_schedules(status, limit)


@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    if not store.delete_schedule(schedule_id):
        raise HTTPException(404, "Schedule not found")
    return {"status": "ok"}
