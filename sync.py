"""
Clouds8 - OCI Sync CLI

Thin wrapper around the Backend API's POST /sync endpoint. The actual
collection logic now lives in services/backend-api/sync_runner.py and runs
inside that service - this script (and lynxctl) just trigger a job there
and poll it, so every sync goes through the same tracked, job-table-backed
code path regardless of which client started it.
"""
import argparse
import sys
import time

from shared.client.backend_client import trigger_sync
from shared.client.db_client import get_job


def sync(cost_driven: bool = False, provider: str = "oci", poll_interval: float = 2.0) -> dict:
    """Trigger a sync via the Backend API and block until it completes.

    Returns the final job dict (id, status, error_message, etc.).
    """
    job = trigger_sync(provider=provider, cost_driven=cost_driven)
    print(f"Sync job {job.id} started for provider={provider} (cost_driven={cost_driven})")

    while job.is_active:
        time.sleep(poll_interval)
        polled = get_job(job.id)
        if polled is None:
            print("Warning: job disappeared while polling")
            break
        job = polled
        if job.progress_message:
            print(f"  {job.progress_message}")

    if job.status == "failed":
        print(f"Sync failed: {job.error_message}")
    else:
        print(f"Sync {job.status}.")

    return job.model_dump()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clouds8 OCI Sync CLI")
    parser.add_argument(
        "--cost-driven", action="store_true", default=False,
        help="Query Usage/Cost API first and only scan services generating bills"
    )
    parser.add_argument(
        "--provider", default="oci",
        help="Cloud provider to sync (e.g. oci, aws). Defaults to oci."
    )
    args = parser.parse_args()
    result = sync(cost_driven=args.cost_driven, provider=args.provider)
    sys.exit(1 if result["status"] == "failed" else 0)
