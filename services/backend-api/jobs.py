"""
Clouds8 Backend API - Job orchestration

Runs long-running scans/sync/probes in background threads within this
process, but job STATE (existence, status, progress, result) lives in the
DB service's persisted `jobs` table (via db.database) instead of an
in-memory dict. That's what makes job status visible across processes and
survivable across a restart - this replaces the old api/jobs.py in-memory
registry and the UI's per-scanner module-global threading dicts, all of
which this service is now the single place that does this kind of work.
"""
import logging
import threading
from typing import Any, Callable, Dict, Optional

from db.database import (
    create_job, update_job, get_job, list_jobs, insert_activity_log, save_scan_report, mark_assets_scanned_by_type,
)
from findings import persist_scan_findings, _SCANNER_TO_ASSET_TYPES

logger = logging.getLogger("Clouds8-BackendAPI")


def reconcile_orphaned_jobs() -> int:
    """Mark every job still "running" as "failed" on process startup.

    Every job's actual work happens in a daemon thread of *this* process
    (see start_scan/start_sync below) - there is no persistent external
    worker. So if this process is starting up and a job row says
    "running", that thread cannot possibly still exist: the process that
    owned it already died (crash, restart, redeploy), and the job was
    never going to update itself again. Without this, such a job sits in
    "running" forever and the UI's resume-on-mount logic keeps showing it
    as in-progress indefinitely. Returns how many jobs were reconciled.
    """
    orphaned = list_jobs(status="running", limit=500)
    for job in orphaned:
        update_job(
            job["id"], status="failed",
            error_message="Marked failed on startup: orphaned by a server restart "
                           "(no worker thread can survive a process restart).",
            finished=True,
        )
    if orphaned:
        logger.warning("Reconciled %d orphaned job(s) stuck in 'running' state", len(orphaned))
    return len(orphaned)


def start_scan(
    scanner_type: str,
    runner: Callable[..., Dict[str, Any]],
    *,
    collector,
    provider: str,
    compartment_ids: Optional[list] = None,
    supports_compartments: bool = True,
    regions: Optional[list] = None,
    supports_regions: bool = True,
    asset_ids: Optional[list] = None,
    supports_assets: bool = True,
    scan_depth: str = "rules",
    profile_id: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch ``runner`` in a background thread and return the job record.

    ``runner`` must accept ``progress_callback``, ``run_checks``, and
    (optionally) ``compartment_ids``, returning a report dict — matching
    the ``run_*`` helpers in ``playbooks/``.

    ``scan_depth`` controls how much the scan does: "inventory" collects
    assets only (``run_checks=False``); "rules"/"full" also run every
    security/compliance check (``run_checks=True`` — identical today,
    "full" is reserved for attack-graph analysis in a future release).

    ``profile_id``/``profile_name``, when given, are the explicit Profile
    this scan was fired for — threaded through to asset tagging so the
    findings get stamped with THIS profile even if the global active
    profile changes before this background job finishes.
    """
    run_checks = scan_depth != "inventory"
    job = create_job("scan", cloud_provider=provider, scan_depth=scan_depth,
                      profile_id=profile_id, profile_name=profile_name)
    job_id = job["id"]
    update_job(job_id, status="running", progress_message="Initializing…", started=True)

    def _on_progress(msg: str) -> None:
        update_job(job_id, progress_message=msg)
        try:
            insert_activity_log("INFO", f"{scanner_type}-scanner", msg)
        except Exception:  # logging must never break a scan
            pass

    def _worker() -> None:
        try:
            # scan_status only ever flips not_scanned -> scanned on
            # completion (see findings.py's mark_assets_scanned_by_type
            # call at the end of persist_scan_findings) - nothing resets it
            # back when a *new* scan of the same asset type starts. Without
            # this, every asset of this type already carries "scanned" from
            # last time, so Inventory's "in progress" view (which filters
            # on scan_status="not_scanned") is permanently empty on any
            # re-scan, even while this one is actively running.
            for asset_type in _SCANNER_TO_ASSET_TYPES.get(scanner_type, []):
                try:
                    mark_assets_scanned_by_type(asset_type, "not_scanned")
                except Exception as e:
                    logger.warning("Could not reset scan_status for %s: %s", asset_type, e)

            kwargs: Dict[str, Any] = {
                "collector": collector,
                "progress_callback": _on_progress,
                "run_checks": run_checks,
            }
            if supports_compartments:
                kwargs["compartment_ids"] = compartment_ids
            if supports_regions:
                kwargs["regions"] = regions
            if supports_assets:
                kwargs["asset_ids"] = asset_ids
            report = runner(**kwargs)
            try:
                save_scan_report(scanner_type, report)
            except Exception as e:
                logger.warning("Could not persist %s report: %s", scanner_type, e)
            try:
                persist_scan_findings(scanner_type, report, profile_id=profile_id,
                                       profile_name=profile_name, provider=provider, run_checks=run_checks)
            except Exception as e:
                logger.warning("Could not persist %s findings: %s", scanner_type, e)
            update_job(job_id, status="succeeded", progress_pct=100, progress_message="Done",
                       result_ref=scanner_type, finished=True)
        except Exception as e:
            logger.error("Background %s scan failed: %s", scanner_type, e)
            update_job(job_id, status="failed", error_message=str(e), finished=True)

    threading.Thread(target=_worker, daemon=True).start()
    return get_job(job_id)


def start_sync(sync_fn: Callable[..., Dict[str, Any]], *, cost_driven: bool, provider: str) -> Dict[str, Any]:
    """Launch a provider sync in a background thread and return the job record."""
    job = create_job("sync", cloud_provider=provider)
    job_id = job["id"]
    update_job(job_id, status="running", progress_message=f"Syncing {provider}…", started=True)

    def _worker() -> None:
        try:
            stats = sync_fn(cost_driven=cost_driven, provider=provider)
            status = "failed" if stats.get("error") else "succeeded"
            update_job(job_id, status=status, error_message=stats.get("error"),
                       progress_pct=100, progress_message="Done", result_ref="sync", finished=True)
        except Exception as e:
            logger.error("Background sync failed: %s", e)
            update_job(job_id, status="failed", error_message=str(e), finished=True)

    threading.Thread(target=_worker, daemon=True).start()
    return get_job(job_id)
