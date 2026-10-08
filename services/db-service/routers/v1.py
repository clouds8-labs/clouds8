"""
Clouds8 DB Service — /v1 API

Additive REST surface for the React frontend (see frontend/), reshaping the
existing `assets` + `scan_results` tables into a polymorphic asset/finding
contract loosely modelled on the Clouds8 UI design spec. Every existing
endpoint in app.py keeps working unchanged for the Dash UI and lynxctl -
this router is purely additive.

No new storage engine, no queue, no event stream: reads are synchronous
SQLite queries (see store.py's v1_* functions), and "cursor" pagination is
a plain stringified offset rather than an opaque token - a pragmatic
simplification, not a spec-exact implementation.
"""
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import attack_paths
import store

router = APIRouter(prefix="/v1", tags=["v1"])


# ── Attack paths ─────────────────────────────────────────────────────────────

@router.get("/paths")
def v1_get_attack_paths(entry_point: str):
    return {"items": attack_paths.compute_attack_paths(entry_point)}


# ── Assets ───────────────────────────────────────────────────────────────────

@router.get("/assets")
def v1_list_assets(
    cloud: Optional[str] = None,
    asset_class: Optional[str] = None,
    exposure: Optional[str] = None,
    severity: Optional[str] = None,
    region: Optional[str] = None,
    account: Optional[str] = None,
    scan_status: Optional[str] = None,
    q: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    sort: Optional[str] = None,
    order: Optional[str] = None,
    profile_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
):
    return store.v1_list_assets(
        cloud=cloud, asset_class=asset_class, exposure=exposure, severity=severity,
        region=region, account=account, scan_status=scan_status, q=q, cursor=cursor, limit=limit,
        sort=sort, order=order, profile_id=profile_id, engagement_id=engagement_id,
    )


# NOTE: the /findings sub-route must be registered before the bare
# /assets/{asset_id} route below - same static-before-param-path ordering
# rule as app.py's /scan-reports routes (FastAPI/Starlette matches route
# patterns in registration order, so a param path registered first would
# otherwise swallow "/findings" into asset_id).
@router.get("/assets/{asset_id}/findings")
def v1_get_asset_findings(asset_id: str):
    return store.v1_get_asset_findings(asset_id)


@router.get("/assets/{asset_id}")
def v1_get_asset(asset_id: str):
    asset = store.v1_get_asset(asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    return asset


# ── Findings ─────────────────────────────────────────────────────────────────

@router.get("/findings")
def v1_list_findings(
    rule_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    account: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    group_by: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    profile_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
):
    return store.v1_list_findings(
        rule_id=rule_id, asset_id=asset_id, account=account, severity=severity,
        state=state, group_by=group_by, cursor=cursor, limit=limit,
        profile_id=profile_id, engagement_id=engagement_id,
    )


@router.get("/findings/rule/{rule_id}/assets.txt")
def v1_rule_assets_txt(rule_id: str, severity: Optional[str] = None, state: Optional[str] = None):
    rows = store.v1_list_rule_assets(rule_id, severity, state)
    body = "\n".join(f"{r['asset_name'] or r['asset_id']} ({r['asset_id']})" for r in rows)
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="{rule_id}-affected-assets.txt"'},
    )


class FindingStatePatch(BaseModel):
    state: str


@router.patch("/findings/{finding_id}")
def v1_patch_finding_state(finding_id: int, req: FindingStatePatch):
    try:
        finding = store.v1_patch_finding_state(finding_id, req.state)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding
