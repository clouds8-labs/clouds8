"""
Clouds8 DB Service — Engagements

A minimal named grouping of Profiles (many-to-many - a Profile can belong
to more than one Engagement). No members, roles, audit trail, or retention
settings - deliberately out of scope for this feature (this app has
single-admin auth only, no multi-user model, no audit log infrastructure).
"""
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import store

router = APIRouter(prefix="/v1", tags=["engagements"])


class EngagementCreateRequest(BaseModel):
    name: str
    profile_ids: List[str] = []
    asset_classes: Optional[List[str]] = None
    regions: Optional[List[str]] = None


class EngagementUpdateRequest(BaseModel):
    name: Optional[str] = None
    asset_classes: Optional[List[str]] = None
    regions: Optional[List[str]] = None


class EngagementProfileRequest(BaseModel):
    profile_id: str


@router.post("/engagements", status_code=201)
def create_engagement(req: EngagementCreateRequest):
    return store.create_engagement(req.name, req.profile_ids, req.asset_classes, req.regions)


@router.get("/engagements")
def list_engagements():
    items = store.list_engagements()
    return {"items": items, "total": len(items)}


@router.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: str):
    engagement = store.get_engagement(engagement_id)
    if engagement is None:
        raise HTTPException(404, "Engagement not found")
    return engagement


@router.patch("/engagements/{engagement_id}")
def update_engagement(engagement_id: str, req: EngagementUpdateRequest):
    if store.get_engagement(engagement_id) is None:
        raise HTTPException(404, "Engagement not found")
    return store.update_engagement(
        engagement_id, name=req.name, asset_classes=req.asset_classes, regions=req.regions,
    )


@router.delete("/engagements/{engagement_id}")
def delete_engagement(engagement_id: str):
    if not store.delete_engagement(engagement_id):
        raise HTTPException(404, "Engagement not found")
    return {"status": "ok"}


@router.post("/engagements/{engagement_id}/profiles")
def add_profile_to_engagement(engagement_id: str, req: EngagementProfileRequest):
    engagement = store.add_profile_to_engagement(engagement_id, req.profile_id)
    if engagement is None:
        raise HTTPException(404, "Engagement or profile not found")
    return engagement


@router.delete("/engagements/{engagement_id}/profiles/{profile_id}")
def remove_profile_from_engagement(engagement_id: str, profile_id: str):
    engagement = store.remove_profile_from_engagement(engagement_id, profile_id)
    if engagement is None:
        raise HTTPException(404, "Engagement not found")
    return engagement
