"""
Clouds8 Backend API - Active probing (Lynker: nmap/nuclei)

Ported from ui/pages/lynker.py, which ran this logic in-process inside the
Dash web server (subprocess execution has no business running inside a web
UI process). Job existence/status is now persisted via the DB service's
`jobs` table like scans/sync; the live stdout buffer stays in-process memory
(module-global dict) since it's ephemeral output tied to a running
subprocess, not state that needs to survive a restart.
"""
import logging
import threading
import uuid
from shutil import which
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db.database import create_job, update_job, get_job

logger = logging.getLogger("Clouds8-BackendAPI")

router = APIRouter(prefix="/probes", tags=["probes"])

TOOL_PROFILES = {
    "nmap": [
        {"label": "Fast Scan (-F)", "value": "-F"},
        {"label": "Standard Scan (-sV -sC)", "value": "-sV -sC"},
        {"label": "All Ports (-p-)", "value": "-p-"},
        {"label": "Ping Sweep (-sn)", "value": "-sn"},
    ],
    "nuclei": [
        {"label": "Critical & High (-s critical,high)", "value": "-s critical,high"},
        {"label": "CVEs Only (-tags cve)", "value": "-tags cve"},
        {"label": "Exposures (-tags exposure)", "value": "-tags exposure"},
        {"label": "Full Scan (All templates)", "value": ""},
    ],
}

_INVALID_TARGET_CHARS = [';', '&', '|', '$', '>', '<', '`', '\\', '!', '\n', '\r']

# job_id -> accumulated stdout/stderr text. In-process only (ephemeral).
_OUTPUT_BUFFERS: Dict[str, str] = {}


@router.get("/profiles/{tool}")
def get_tool_profiles(tool: str):
    return {"profiles": TOOL_PROFILES.get(tool, [])}


class ProbeRequest(BaseModel):
    tool: str
    target: str
    profile: Optional[str] = None


def _build_command(tool: str, target: str, profile: Optional[str]) -> List[str]:
    if tool == "nmap":
        cmd = ["nmap"]
        if profile:
            cmd.extend(profile.split())
        cmd.append(target)
        return cmd
    if tool == "nuclei":
        cmd = ["nuclei", "-u", target, "-no-color"]
        if profile:
            cmd.extend(profile.split())
        return cmd
    raise ValueError(f"Unknown tool '{tool}'")


@router.post("/run", status_code=202)
def run_probe(req: ProbeRequest):
    if req.tool not in TOOL_PROFILES:
        raise HTTPException(400, f"Unknown tool '{req.tool}'. Available: {sorted(TOOL_PROFILES)}")

    target = str(req.target or "").strip()
    if not target:
        raise HTTPException(400, "No target specified")
    if any(ch in target for ch in _INVALID_TARGET_CHARS) or target.startswith('-'):
        raise HTTPException(400, f"Invalid target format '{target}'")

    try:
        cmd_list = _build_command(req.tool, target, req.profile)
    except ValueError as e:
        raise HTTPException(400, str(e))

    job = create_job("probe", scope_id=target)
    job_id = job["id"]
    _OUTPUT_BUFFERS[job_id] = f"$ {' '.join(cmd_list)}\n"
    update_job(job_id, status="running", progress_message=f"Running {req.tool}…", started=True)

    def _worker():
        try:
            if which(req.tool) is None:
                _OUTPUT_BUFFERS[job_id] += f"\nError: Command '{req.tool}' not found. Please install it on the system.\n"
                update_job(job_id, status="failed", error_message=f"'{req.tool}' not installed", finished=True)
                return

            import subprocess
            process = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            for line in process.stdout:
                _OUTPUT_BUFFERS[job_id] += line
            process.wait()
            _OUTPUT_BUFFERS[job_id] += f"\nProcess completed with exit code {process.returncode}\n"
            update_job(job_id, status="succeeded", progress_pct=100, finished=True)
        except Exception as e:
            logger.error("Probe execution error: %s", e)
            _OUTPUT_BUFFERS[job_id] += f"\nExecution Error: {str(e)}\n"
            update_job(job_id, status="failed", error_message=str(e), finished=True)

    threading.Thread(target=_worker, daemon=True).start()
    return get_job(job_id)


@router.get("/jobs/{job_id}/output")
def get_probe_output(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found")
    return {"job": job, "output": _OUTPUT_BUFFERS.get(job_id, "")}
