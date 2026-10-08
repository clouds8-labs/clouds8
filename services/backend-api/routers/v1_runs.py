"""
Clouds8 Backend API — /v1 REST surface (runs, exports, connections)

Additive: existing /scans, /providers, /sync endpoints are unchanged and
still used by Dash/lynxctl. This router serves the new React frontend.

No queue/SSE: a "run" fans out to the existing threaded jobs.start_scan()
once per selected scanner and is polled by aggregating the child jobs'
persisted status (see _aggregate_run) - there is no separate run-state
machine to keep in sync. Exports are generated synchronously (SQLite reads
are fast enough not to need a queue) and held in an in-process dict keyed
by export id, mirroring how job state already lives with this process
during a run - acceptable for a single backend-api instance, and simpler
than standing up object storage for a v1 cut.
"""
import csv
import html
import io
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

import jobs
from collector import build_collector
from collectors.registry import list_providers
from db import database as db
from reports.report_generator import _LynxPDF
from routers.scans import SCANNERS

router = APIRouter(prefix="/v1", tags=["v1"])
logger = logging.getLogger("Clouds8-BackendAPI")


# ── Runs ─────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    classes: List[str]
    compartment_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None
    provider: str = "oci"
    scan_depth: Literal["inventory", "rules", "full"] = "rules"
    profile_id: Optional[str] = None


def _fire_run(classes: List[str], compartment_ids: Optional[List[str]], provider: str,
              scan_depth: str = "rules", profile_id: Optional[str] = None,
              regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None) -> Dict:
    """Validate + fan out a run across the selected scanners. Shared by the
    POST /v1/runs route and scheduler.py's background scheduling loop, so a
    scheduled scan fires through the identical code path as an ad-hoc one."""
    if not classes:
        raise HTTPException(422, "At least one asset class (scanner) must be selected")
    unknown = [c for c in classes if c not in SCANNERS]
    if unknown:
        raise HTTPException(404, f"Unknown scanner class(es): {unknown}. Available: {sorted(SCANNERS)}")

    profile = db.get_profile(profile_id) if profile_id else db.get_active_profile(provider)
    resolved_profile_id = profile.get("id") if profile else None
    resolved_profile_name = profile.get("name") if profile else None

    child_jobs = []
    for scanner_type in classes:
        # A fresh collector per scanner, not one shared across the run: each
        # runs in its own background thread (jobs.start_scan), and a single
        # GCPCollector's http/credentials objects aren't safe for concurrent
        # .execute() calls from multiple threads - that contention is what
        # caused multi-class GCP runs to hang/timeout even after fixing the
        # project-discovery call itself.
        try:
            collector = build_collector(provider, profile_id=profile_id)
        except RuntimeError as e:
            raise HTTPException(422, str(e))
        runner, supports_compartments, supports_regions, supports_assets = SCANNERS[scanner_type]
        job = jobs.start_scan(
            scanner_type, runner, collector=collector, provider=provider,
            compartment_ids=compartment_ids, supports_compartments=supports_compartments,
            regions=regions, supports_regions=supports_regions,
            asset_ids=asset_ids, supports_assets=supports_assets,
            scan_depth=scan_depth, profile_id=resolved_profile_id, profile_name=resolved_profile_name,
        )
        child_jobs.append({"scanner_type": scanner_type, "job_id": job["id"]})

    run = db.create_job("run", cloud_provider=provider, scan_depth=scan_depth,
                         profile_id=resolved_profile_id, profile_name=resolved_profile_name, asset_ids=asset_ids)
    db.update_job(run["id"], status="running", started=True, result_ref=json.dumps(child_jobs))
    return _aggregate_run(db.get_job(run["id"]))


@router.post("/runs", status_code=202)
def start_run(req: RunRequest):
    return _fire_run(req.classes, req.compartment_ids, req.provider, req.scan_depth, req.profile_id,
                      regions=req.regions, asset_ids=req.asset_ids)


def _aggregate_run(run_job: Dict) -> Dict:
    """Compute a run-level state/progress by looking up each child scan job
    fresh - there is no separate run-state to keep in sync, just this
    read-time aggregation."""
    try:
        child_refs = json.loads(run_job.get("result_ref") or "[]")
    except (json.JSONDecodeError, TypeError):
        child_refs = []

    children = []
    for c in child_refs:
        job = db.get_job(c["job_id"])
        if job:
            children.append({**c, "status": job["status"], "progress_message": job.get("progress_message")})

    total = len(children)
    succeeded = sum(1 for c in children if c["status"] == "succeeded")
    failed = sum(1 for c in children if c["status"] == "failed")
    active = sum(1 for c in children if c["status"] in ("pending", "running"))

    if active > 0 or total == 0:
        state = "running"
    elif failed == 0:
        state = "completed"
    elif succeeded == 0:
        state = "failed"
    else:
        state = "partial"

    return {
        "id": run_job["id"],
        "state": state,
        "scan_depth": run_job.get("scan_depth") or "rules",
        "created_at": run_job.get("created_at"),
        "started_at": run_job.get("started_at"),
        "finished_at": run_job.get("finished_at") if active == 0 else None,
        "classes": [c["scanner_type"] for c in children],
        "asset_ids": json.loads(run_job["asset_ids"]) if run_job.get("asset_ids") else None,
        "progress": {
            "percent": round(100 * (succeeded + failed) / total) if total else 0,
            "total": total, "succeeded": succeeded, "failed": failed, "active": active,
        },
        "collectors": children,
    }


@router.get("/runs")
def list_runs(limit: int = 20, profile_id: Optional[str] = None, engagement_id: Optional[str] = None):
    run_jobs = db.list_jobs(job_type="run", limit=limit, profile_id=profile_id, engagement_id=engagement_id)
    return {"items": [_aggregate_run(j) for j in run_jobs], "total": len(run_jobs)}


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    run_job = db.get_job(run_id)
    if run_job is None or run_job.get("job_type") != "run":
        raise HTTPException(404, "Run not found")
    return _aggregate_run(run_job)


# ── Exports (synchronous; in-process store) ──────────────────────────────────

_EXPORTS: Dict[str, Dict[str, Any]] = {}


class ExportRequest(BaseModel):
    format: str  # csv | json | pdf
    sections: List[str] = ["assets", "findings"]
    filter: Dict[str, Any] = {}


def _fetch_export_data(filt: Dict[str, Any]):
    asset_params = {k: v for k, v in filt.items()
                     if k in ("cloud", "asset_class", "exposure", "severity", "region", "account", "q", "profile_id")}
    finding_params = {k: v for k, v in filt.items() if k in ("severity", "state")}
    assets = db.v1_list_assets(limit=5000, **asset_params).get("items", [])
    findings = db.v1_list_findings(limit=5000, **finding_params).get("items", [])
    return assets, findings


def _build_csv(assets: List[Dict], findings: List[Dict], sections: List[str]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    if "assets" in sections:
        writer.writerow(["-- ASSETS --"])
        writer.writerow(["ID", "Class", "Name", "Compartment", "Region", "Exposure", "Risk",
                          "Critical", "High", "Medium", "Low"])
        for a in assets:
            fc = a.get("finding_counts", {})
            writer.writerow([
                a["id"], a["class"], a["name"], a.get("compartment", ""), a.get("region", ""),
                a["exposure"], a["risk"], fc.get("critical", 0), fc.get("high", 0),
                fc.get("medium", 0), fc.get("low", 0),
            ])
        writer.writerow([])
    if "findings" in sections:
        writer.writerow(["-- FINDINGS --"])
        writer.writerow(["ID", "Rule", "Title", "Asset", "Account", "Severity", "State", "Description"])
        for f in findings:
            writer.writerow([
                f["id"], f["rule_id"], f["title"], f.get("asset_name") or f["asset_id"],
                f.get("account", ""), f.get("severity", ""), f["state"], f.get("description", ""),
            ])
    return buf.getvalue()


def _build_html(assets: List[Dict], findings: List[Dict], sections: List[str]) -> str:
    """Plain semantic HTML + inline CSS, one table per section - same
    section shape as _build_csv above, just rendered for viewing in a
    browser instead of a spreadsheet."""
    def esc(v: Any) -> str:
        return html.escape(str(v if v is not None else ""))

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Clouds8 Export</title><style>"
        "body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}"
        "h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem;color:#f0a742}"
        "table{border-collapse:collapse;width:100%;margin-top:0.5rem}"
        "th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:0.85rem}"
        "th{background:#161b22} tr:nth-child(even){background:#161b22}"
        "</style></head><body>",
        "<h1>Clouds8 Export</h1>",
    ]

    if "assets" in sections:
        parts.append(f"<h2>Assets ({len(assets)})</h2>")
        parts.append("<table><tr><th>ID</th><th>Class</th><th>Name</th><th>Compartment</th>"
                      "<th>Region</th><th>Exposure</th><th>Risk</th>"
                      "<th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>")
        for a in assets:
            fc = a.get("finding_counts", {})
            parts.append(
                f"<tr><td>{esc(a['id'])}</td><td>{esc(a['class'])}</td><td>{esc(a['name'])}</td>"
                f"<td>{esc(a.get('compartment'))}</td><td>{esc(a.get('region'))}</td>"
                f"<td>{esc(a['exposure'])}</td><td>{esc(a['risk'])}</td>"
                f"<td>{esc(fc.get('critical', 0))}</td><td>{esc(fc.get('high', 0))}</td>"
                f"<td>{esc(fc.get('medium', 0))}</td><td>{esc(fc.get('low', 0))}</td></tr>"
            )
        parts.append("</table>")

    if "findings" in sections:
        parts.append(f"<h2>Findings ({len(findings)})</h2>")
        parts.append("<table><tr><th>ID</th><th>Rule</th><th>Title</th><th>Asset</th>"
                      "<th>Account</th><th>Severity</th><th>State</th><th>Description</th></tr>")
        for f in findings:
            parts.append(
                f"<tr><td>{esc(f['id'])}</td><td>{esc(f['rule_id'])}</td><td>{esc(f['title'])}</td>"
                f"<td>{esc(f.get('asset_name') or f['asset_id'])}</td><td>{esc(f.get('account'))}</td>"
                f"<td>{esc(f.get('severity'))}</td><td>{esc(f['state'])}</td>"
                f"<td>{esc(f.get('description'))}</td></tr>"
            )
        parts.append("</table>")

    parts.append("</body></html>")
    return "".join(parts)


def _build_pdf(assets: List[Dict], findings: List[Dict], sections: List[str]) -> bytes:
    """Generic summary + table PDF, reusing _LynxPDF's existing branding
    helpers. Not the mockup's fancy multi-section report layout - flagged
    in the migration plan as a follow-up, not a v1 blocker."""
    pdf = _LynxPDF("Cloud Security Export")
    pdf.add_page()
    pdf.section_title("Summary")
    pdf.summary_cell("Assets", str(len(assets)), (0, 212, 255))
    pdf.summary_cell("Findings", str(len(findings)), (230, 70, 70))
    pdf.ln(22)

    if "assets" in sections and assets:
        pdf.section_title(f"Asset Inventory ({len(assets)})")
        pdf.table_header([("Name", 70), ("Class", 25), ("Compartment", 60), ("Exposure", 35), ("Risk", 20)])
        for a in assets[:200]:
            pdf.table_row([
                (a["name"], 70, "L"), (a["class"], 25, "L"), (a.get("compartment", "") or "", 60, "L"),
                (a["exposure"], 35, "L"), (str(a["risk"]), 20, "C"),
            ])
        pdf.ln(4)

    if "findings" in sections and findings:
        pdf.add_page()
        pdf.section_title(f"Findings ({len(findings)})")
        pdf.table_header([("Severity", 25), ("Rule", 30), ("Title", 90), ("Asset", 65)])
        for f in findings[:200]:
            pdf.table_row([
                ((f.get("severity") or "").upper(), 25, "C"), (f["rule_id"], 30, "L"),
                (f["title"], 90, "L"), (f.get("asset_name") or f["asset_id"], 65, "L"),
            ])

    return bytes(pdf.output())


def _export_meta(entry: Dict) -> Dict:
    return {k: v for k, v in entry.items() if k != "data"}


@router.post("/exports", status_code=202)
def create_export(req: ExportRequest):
    if req.format not in ("csv", "json", "pdf", "html"):
        raise HTTPException(422, "format must be one of: csv, json, pdf, html")

    assets, findings = _fetch_export_data(req.filter or {})

    export_id = uuid.uuid4().hex
    if req.format == "csv":
        data = _build_csv(assets, findings, req.sections).encode("utf-8")
        content_type, filename = "text/csv", f"clouds8_export_{export_id[:8]}.csv"
    elif req.format == "json":
        payload: Dict[str, Any] = {}
        if "assets" in req.sections:
            payload["assets"] = assets
        if "findings" in req.sections:
            payload["findings"] = findings
        data = json.dumps(payload, indent=2).encode("utf-8")
        content_type, filename = "application/json", f"clouds8_export_{export_id[:8]}.json"
    elif req.format == "html":
        data = _build_html(assets, findings, req.sections).encode("utf-8")
        content_type, filename = "text/html", f"clouds8_export_{export_id[:8]}.html"
    else:
        data = _build_pdf(assets, findings, req.sections)
        content_type, filename = "application/pdf", f"clouds8_export_{export_id[:8]}.pdf"

    _EXPORTS[export_id] = {
        "id": export_id, "state": "ready", "format": req.format, "filename": filename,
        "content_type": content_type, "data": data, "created_at": time.time(),
        "bytes": len(data), "counts": {"assets": len(assets), "findings": len(findings)},
    }
    return _export_meta(_EXPORTS[export_id])


@router.get("/exports/{export_id}")
def get_export(export_id: str):
    entry = _EXPORTS.get(export_id)
    if entry is None:
        raise HTTPException(404, "Export not found")
    return _export_meta(entry)


@router.get("/exports/{export_id}/file")
def get_export_file(export_id: str):
    entry = _EXPORTS.get(export_id)
    if entry is None:
        raise HTTPException(404, "Export not found")
    return Response(
        content=entry["data"], media_type=entry["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{entry["filename"]}"'},
    )


# ── Connections ──────────────────────────────────────────────────────────────

@router.get("/connections")
def list_connections():
    conns = []
    for provider in list_providers():
        collector = build_collector(provider)
        conns.append({
            "id": provider,
            "cloud": provider,
            "configured": collector is not None,
            "health": "healthy" if collector is not None else "not_configured",
        })
    return {"items": conns, "total": len(conns)}
