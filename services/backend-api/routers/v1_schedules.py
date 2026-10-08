"""
Clouds8 Backend API — /v1/schedules REST surface

Manages persisted `schedules` rows (see db-service's store.py). Firing is
owned by scheduler.py's background thread, not this router - this file is
pure CRUD + validation for the scheduler to act on.

Unlike the rest of this codebase (which stores naive local-server-time
timestamps in `jobs`), schedule timestamps are timezone-aware UTC
throughout - the browser/host and the backend-api container are not
guaranteed to share a timezone (e.g. a UTC container with a non-UTC host),
so "due" comparisons must be anchored to an absolute instant, not a naive
wall-clock string. The frontend sends `run_at` as a `.toISOString()` UTC
string and renders `next_run_at`/`last_run_at` via `new Date(iso).
toLocaleString()`, which correctly converts an aware ISO string to the
viewer's local time.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import database as db
from routers.scans import SCANNERS

router = APIRouter(prefix="/v1", tags=["v1"])


class ScheduleCreateRequest(BaseModel):
    classes: List[str]
    mode: Literal["interval", "once"]
    interval_value: Optional[int] = None
    interval_unit: Optional[Literal["hours", "days"]] = None
    run_at: Optional[datetime] = None
    provider: str = "oci"
    scan_depth: Literal["inventory", "rules", "full"] = "rules"
    profile_id: Optional[str] = None
    compartment_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None


class ScheduleUpdateRequest(BaseModel):
    status: Literal["active", "disabled"]


def _serialize(row: Dict) -> Dict:
    return {
        **row,
        "classes": json.loads(row["classes"]),
        "compartment_ids": json.loads(row["compartment_ids"]) if row.get("compartment_ids") else None,
        "regions": json.loads(row["regions"]) if row.get("regions") else None,
        "asset_ids": json.loads(row["asset_ids"]) if row.get("asset_ids") else None,
    }


def _validate_classes(classes: List[str]) -> None:
    if not classes:
        raise HTTPException(422, "At least one asset class (scanner) must be selected")
    unknown = [c for c in classes if c not in SCANNERS]
    if unknown:
        raise HTTPException(404, f"Unknown scanner class(es): {unknown}. Available: {sorted(SCANNERS)}")


def _as_utc(dt: datetime) -> datetime:
    """Treat a naive datetime as already-UTC (shouldn't happen - the
    frontend always sends an offset) rather than silently reinterpreting it
    in the server's local zone."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@router.post("/schedules", status_code=201)
def create_schedule(req: ScheduleCreateRequest):
    _validate_classes(req.classes)
    now = datetime.now(timezone.utc)

    if req.mode == "interval":
        if not req.interval_value or req.interval_value < 1 or not req.interval_unit:
            raise HTTPException(422, "interval mode requires interval_value >= 1 and interval_unit")
        delta = timedelta(days=req.interval_value) if req.interval_unit == "days" else timedelta(hours=req.interval_value)
        next_run_at = now + delta
        run_at_str = None
    else:  # once
        if req.run_at is None or _as_utc(req.run_at) <= now:
            raise HTTPException(422, "once mode requires run_at to be a future datetime")
        next_run_at = _as_utc(req.run_at)
        run_at_str = next_run_at.isoformat()

    profile = db.get_profile(req.profile_id) if req.profile_id else db.get_active_profile(req.provider)
    row = db.create_schedule(
        req.classes, req.provider, req.mode, next_run_at.isoformat(),
        req.interval_value, req.interval_unit, run_at_str, req.scan_depth,
        profile.get("id") if profile else None, profile.get("name") if profile else None,
        compartment_ids=req.compartment_ids, regions=req.regions, asset_ids=req.asset_ids,
    )
    return _serialize(row)


@router.get("/schedules")
def list_schedules(status: Optional[str] = None, limit: int = 100):
    rows = db.list_schedules(status, limit)
    return {"items": [_serialize(r) for r in rows], "total": len(rows)}


@router.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: str):
    row = db.get_schedule(schedule_id)
    if row is None:
        raise HTTPException(404, "Schedule not found")
    return _serialize(row)


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: str, req: ScheduleUpdateRequest):
    row = db.get_schedule(schedule_id)
    if row is None:
        raise HTTPException(404, "Schedule not found")
    if row["status"] == "completed":
        raise HTTPException(409, "Cannot change status of a completed one-time schedule")

    now = datetime.now(timezone.utc)
    if req.status == "active" and row["status"] == "disabled":
        if row["mode"] == "interval":
            delta = (timedelta(days=row["interval_value"]) if row["interval_unit"] == "days"
                     else timedelta(hours=row["interval_value"]))
            next_run_at = now + delta
        else:
            run_at = datetime.fromisoformat(row["run_at"])
            next_run_at = run_at if run_at > now else now
        updated = db.update_schedule(schedule_id, status="active", next_run_at=next_run_at.isoformat())
    else:
        updated = db.update_schedule(schedule_id, status=req.status)
    return _serialize(updated)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    if not db.delete_schedule(schedule_id):
        raise HTTPException(404, "Schedule not found")
    return {"status": "ok"}
