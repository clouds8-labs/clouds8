"""
Clouds8 Backend API - scan scheduler

Single background daemon thread that polls db-service for due `schedules`
rows and fires them via routers.v1_runs._fire_run - the same fan-out/child-
job logic POST /v1/runs uses, called in-process rather than over HTTP.
Armed once from app.py's lifespan startup hook.

Uses threading (like jobs.py's start_scan/start_sync), not asyncio or
APScheduler - this service has no async code outside the mandatory FastAPI
lifespan, and backend-api runs as a single-process, single-worker container
(no --workers, no compose replicas), so exactly one thread will ever poll.
"""
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict

from db import database as db

logger = logging.getLogger("Clouds8-BackendAPI")

POLL_INTERVAL_SECONDS = 30

_started = False
_lock = threading.Lock()


def start() -> None:
    """Idempotent: safe to call more than once (e.g. under --reload)."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_loop, name="scan-scheduler", daemon=True).start()
    logger.info("Scan scheduler armed (poll interval %ss)", POLL_INTERVAL_SECONDS)


def _loop() -> None:
    while True:
        try:
            _tick()
        except Exception:
            logger.exception("Scheduler tick failed - will retry next poll")
        time.sleep(POLL_INTERVAL_SECONDS)


def _tick() -> None:
    # Timezone-aware UTC, not datetime.now() - this container's clock may
    # not share a timezone with the browser/host (see v1_schedules.py's
    # module docstring), so "due" must compare absolute instants.
    now = datetime.now(timezone.utc)
    due = db.list_due_schedules(before=now.isoformat())
    for sched in due:
        try:
            _fire(sched, now)
        except Exception:
            # one broken schedule must never stop the rest of this tick's
            # due schedules from firing
            logger.exception("Failed to fire schedule %s", sched.get("id"))


def _fire(sched: Dict, now: datetime) -> None:
    from routers.v1_runs import _fire_run

    classes = json.loads(sched["classes"])
    scan_depth = sched.get("scan_depth") or "rules"
    compartment_ids = json.loads(sched["compartment_ids"]) if sched.get("compartment_ids") else None
    regions = json.loads(sched["regions"]) if sched.get("regions") else None
    asset_ids = json.loads(sched["asset_ids"]) if sched.get("asset_ids") else None
    last_run_id = None
    try:
        run = _fire_run(classes, compartment_ids, sched.get("provider") or "oci", scan_depth,
                         profile_id=sched.get("profile_id"), regions=regions, asset_ids=asset_ids)
        last_run_id = run["id"]
    finally:
        # advance/complete even if firing raised, so a persistently broken
        # schedule degrades to "retries and logs every tick" instead of
        # hot-looping or silently going stale forever
        if sched["mode"] == "once":
            db.update_schedule(sched["id"], status="completed",
                                last_run_at=now.isoformat(), last_run_id=last_run_id)
        else:
            next_run_at = now + _interval_delta(sched["interval_value"], sched["interval_unit"])
            db.update_schedule(sched["id"], next_run_at=next_run_at.isoformat(),
                                last_run_at=now.isoformat(), last_run_id=last_run_id)


def _interval_delta(value: int, unit: str) -> timedelta:
    return timedelta(days=value) if unit == "days" else timedelta(hours=value)
