"""
Clouds8 shared client - typed HTTP client for the Backend API service.

Used by the Integration Service (Dash UI + future CLI) to trigger
cloud-provider work (sync, scans, active probes). Job STATUS polling goes
through db_client.get_job() instead - job state lives in the DB service
regardless of which service started the job.
"""
import os
from typing import Any, Dict, List, Optional

import httpx

from .config import BACKEND_API_URL
from .schemas import Job

_client = httpx.Client(
    base_url=BACKEND_API_URL, timeout=30.0,
    headers={"Authorization": f"Bearer {os.getenv('INTERNAL_SERVICE_TOKEN', '')}"},
)


def trigger_sync(provider: str = "oci", cost_driven: bool = False) -> Job:
    r = _client.post("/sync", json={"provider": provider, "cost_driven": cost_driven})
    r.raise_for_status()
    return Job(**r.json())


def get_provider_status(provider: str) -> Dict[str, Any]:
    r = _client.get(f"/providers/{provider}/status")
    r.raise_for_status()
    return r.json()


def list_scanner_types() -> List[str]:
    r = _client.get("/scans/scanners")
    r.raise_for_status()
    return r.json()["scanners"]


def trigger_scan(scanner_type: str, provider: str = "oci",
                  compartment_ids: Optional[List[str]] = None) -> Job:
    r = _client.post(f"/scans/{scanner_type}", json={"provider": provider, "compartment_ids": compartment_ids})
    r.raise_for_status()
    return Job(**r.json())


def get_scan_report(scanner_type: str) -> Optional[Dict[str, Any]]:
    r = _client.get(f"/scans/reports/{scanner_type}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def run_probe(tool: str, target: str, profile: Optional[str] = None) -> Job:
    r = _client.post("/probes/run", json={"tool": tool, "target": target, "profile": profile})
    r.raise_for_status()
    return Job(**r.json())


def get_probe_output(job_id: str) -> dict:
    r = _client.get(f"/probes/jobs/{job_id}/output")
    r.raise_for_status()
    return r.json()
