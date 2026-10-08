"""
Clouds8 Backend API - System endpoints (health, dashboard overview, provider sync)
"""
from fastapi import APIRouter
from pydantic import BaseModel

import jobs
import sync_runner
from collector import build_collector
from collectors.registry import list_providers
from db import database as db

router = APIRouter(tags=["system"])


@router.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/providers")
def providers():
    """List the cloud providers with a registered collector."""
    return {"providers": list_providers()}


@router.get("/providers/{provider}/status")
def provider_status(provider: str):
    """Whether a provider's SDK/credentials are configured, vs. falling back
    to mock data. Lets clients (e.g. the Configuration page) show a health
    indicator without instantiating a cloud SDK collector themselves."""
    collector = build_collector(provider)
    return {"provider": provider, "configured": collector is not None}


@router.get("/overview")
def overview():
    """Top-level dashboard numbers: asset, finding and log totals."""
    return {
        "total_assets": db.get_total_asset_count(),
        "by_type": db.get_asset_summary(),
        "by_region": db.get_region_summary(),
        "recent_findings": db.get_recent_scan_findings(limit=10),
        "log_stats": db.get_log_stats(),
        "last_scanner": db.get_most_recent_scanner_type(),
    }


class SyncRequest(BaseModel):
    provider: str = "oci"
    cost_driven: bool = False


@router.post("/sync", status_code=202)
def trigger_sync(req: SyncRequest = SyncRequest()):
    """Trigger a provider sync in the background. Returns a job to poll."""
    return jobs.start_sync(sync_runner.sync, cost_driven=req.cost_driven, provider=req.provider)
