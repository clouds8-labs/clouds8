#!/usr/bin/env python3
"""
lynxctl - Clouds8 command-line client

A thin client over the same two services the Dash UI talks to (DB service +
Backend API), built on the shared/client SDK - so the CLI and the web UI
never diverge in how they read assets or trigger work. Run with:

    python services/integration/cli/lynxctl.py <command> ...

Or make it executable and run directly: ./lynxctl.py <command> ...
"""
import argparse
import json
import os
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from shared.client import backend_client, db_client  # noqa: E402


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, default=str))


def _watch_job(job_id: str, poll_interval: float = 2.0) -> dict:
    """Poll a job until it reaches a terminal state, printing progress."""
    while True:
        job = db_client.get_job(job_id)
        if job is None:
            print(f"Job {job_id} not found", file=sys.stderr)
            sys.exit(1)
        if job.progress_message:
            print(f"  [{job.status}] {job.progress_message}")
        if not job.is_active:
            return job.model_dump()
        time.sleep(poll_interval)


# ── assets ───────────────────────────────────────────────────────────────

def cmd_assets_list(args):
    if args.provider:
        assets = db_client.get_assets_by_provider(args.provider, limit=args.limit)
    elif args.type:
        assets = db_client.get_assets_by_type(args.type, limit=args.limit)
    else:
        assets = db_client.get_all_assets(limit=args.limit)
    _print_json(assets)


def cmd_assets_summary(args):
    _print_json(db_client.get_asset_summary())


# ── sync ─────────────────────────────────────────────────────────────────

def cmd_sync_run(args):
    job = backend_client.trigger_sync(provider=args.provider, cost_driven=args.cost_driven)
    print(f"Sync job {job.id} started (provider={args.provider}, cost_driven={args.cost_driven})")
    if args.watch:
        final = _watch_job(job.id)
        print(f"Final status: {final['status']}")
        if final.get("error_message"):
            print(f"Error: {final['error_message']}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Use `lynxctl jobs watch <job-id>` to follow progress.")


# ── scan ─────────────────────────────────────────────────────────────────

def cmd_scan_types(args):
    _print_json(backend_client.list_scanner_types())


def cmd_scan_run(args):
    job = backend_client.trigger_scan(args.type, provider=args.provider, compartment_ids=args.compartment)
    print(f"Scan job {job.id} started (type={args.type}, provider={args.provider})")
    if args.watch:
        final = _watch_job(job.id)
        print(f"Final status: {final['status']}")
        if final.get("error_message"):
            print(f"Error: {final['error_message']}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Use `lynxctl jobs watch <job-id>` to follow progress.")


def cmd_scan_results(args):
    report = backend_client.get_scan_report(args.scanner_type)
    if report is None:
        print(f"No saved report for scanner '{args.scanner_type}'", file=sys.stderr)
        sys.exit(1)
    _print_json(report)


# ── jobs ─────────────────────────────────────────────────────────────────

def cmd_jobs_status(args):
    job = db_client.get_job(args.job_id)
    if job is None:
        print(f"Job '{args.job_id}' not found", file=sys.stderr)
        sys.exit(1)
    _print_json(job.model_dump())


def cmd_jobs_watch(args):
    final = _watch_job(args.job_id)
    _print_json(final)
    if final.get("status") == "failed":
        sys.exit(1)


# ── logs ─────────────────────────────────────────────────────────────────

def cmd_logs_tail(args):
    logs = db_client.get_activity_logs(level=args.level, limit=args.limit)
    seen_ids = set()
    for entry in reversed(logs):
        print(f"{entry.timestamp} [{entry.level}] {entry.source}: {entry.message}")
        seen_ids.add(entry.id)

    if not args.follow:
        return

    print("-- following (Ctrl-C to stop) --", file=sys.stderr)
    try:
        while True:
            time.sleep(2)
            fresh = db_client.get_activity_logs(level=args.level, limit=50)
            new_entries = [e for e in reversed(fresh) if e.id not in seen_ids]
            for entry in new_entries:
                print(f"{entry.timestamp} [{entry.level}] {entry.source}: {entry.message}")
                seen_ids.add(entry.id)
    except KeyboardInterrupt:
        pass


# ── seed ─────────────────────────────────────────────────────────────────

def cmd_seed(args):
    sys.path.insert(0, _REPO_ROOT)
    import seed_data
    seed_data.run_seed()


def main():
    parser = argparse.ArgumentParser(prog="lynxctl", description="Clouds8 command-line client")
    sub = parser.add_subparsers(dest="group", required=True)

    p_assets = sub.add_parser("assets", help="Query the asset inventory")
    assets_sub = p_assets.add_subparsers(dest="action", required=True)
    p_assets_list = assets_sub.add_parser("list", help="List assets")
    p_assets_list.add_argument("--provider", help="Filter by cloud provider (e.g. oci)")
    p_assets_list.add_argument("--type", help="Filter by asset type (e.g. vm, bucket)")
    p_assets_list.add_argument("--limit", type=int, default=100)
    p_assets_list.set_defaults(func=cmd_assets_list)
    p_assets_summary = assets_sub.add_parser("summary", help="Asset counts by type")
    p_assets_summary.set_defaults(func=cmd_assets_summary)

    p_sync = sub.add_parser("sync", help="Trigger a cloud provider sync")
    sync_sub = p_sync.add_subparsers(dest="action", required=True)
    p_sync_run = sync_sub.add_parser("run", help="Start a sync job")
    p_sync_run.add_argument("--provider", default="oci")
    p_sync_run.add_argument("--cost-driven", action="store_true", default=False, dest="cost_driven")
    p_sync_run.add_argument("--watch", action="store_true", default=False, help="Block until the job finishes")
    p_sync_run.set_defaults(func=cmd_sync_run)

    p_scan = sub.add_parser("scan", help="Trigger and inspect security scans")
    scan_sub = p_scan.add_subparsers(dest="action", required=True)
    p_scan_types = scan_sub.add_parser("types", help="List available scanner types")
    p_scan_types.set_defaults(func=cmd_scan_types)
    p_scan_run = scan_sub.add_parser("run", help="Start a scan job")
    p_scan_run.add_argument("--type", required=True, help="Scanner type (see `lynxctl scan types`)")
    p_scan_run.add_argument("--provider", default="oci")
    p_scan_run.add_argument("--compartment", action="append", default=None,
                             help="Compartment ID to scope the scan to (repeatable)")
    p_scan_run.add_argument("--watch", action="store_true", default=False, help="Block until the job finishes")
    p_scan_run.set_defaults(func=cmd_scan_run)
    p_scan_results = scan_sub.add_parser("results", help="Fetch the latest persisted report for a scanner type")
    p_scan_results.add_argument("scanner_type")
    p_scan_results.set_defaults(func=cmd_scan_results)

    p_jobs = sub.add_parser("jobs", help="Inspect background jobs")
    jobs_sub = p_jobs.add_subparsers(dest="action", required=True)
    p_jobs_status = jobs_sub.add_parser("status", help="Show a job's current status")
    p_jobs_status.add_argument("job_id")
    p_jobs_status.set_defaults(func=cmd_jobs_status)
    p_jobs_watch = jobs_sub.add_parser("watch", help="Poll a job until it finishes")
    p_jobs_watch.add_argument("job_id")
    p_jobs_watch.set_defaults(func=cmd_jobs_watch)

    p_logs = sub.add_parser("logs", help="Tail the activity log")
    logs_sub = p_logs.add_subparsers(dest="action", required=True)
    p_logs_tail = logs_sub.add_parser("tail", help="Show recent activity log entries")
    p_logs_tail.add_argument("--limit", type=int, default=20)
    p_logs_tail.add_argument("--level", default=None, help="Filter by level (INFO, WARN, ERROR)")
    p_logs_tail.add_argument("--follow", action="store_true", default=False)
    p_logs_tail.set_defaults(func=cmd_logs_tail)

    p_seed = sub.add_parser("seed", help="Load demo data into the database")
    p_seed.set_defaults(func=cmd_seed)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
