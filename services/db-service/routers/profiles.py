"""
Clouds8 DB Service — Profiles

A Profile is one persisted cloud account/tenancy, scoped to exactly one
cloud_provider, referencing a named section of the local SDK config file
(e.g. ~/.oci/config's [SECTION] for OCI) - no credentials are ever stored
here. Replaces the old live-probe-only /v1/connections stub in
services/backend-api with a real, named, CRUD-able entity.
"""
import sqlite3
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import store

router = APIRouter(prefix="/v1", tags=["profiles"])


class ProfileCreateRequest(BaseModel):
    name: str
    cloud_provider: str
    config_profile_name: str = "DEFAULT"


class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    config_profile_name: Optional[str] = None
    verify_status: Optional[str] = None
    verify_message: Optional[str] = None
    verified_at: Optional[str] = None
    whoami_result: Optional[str] = None
    whoami_checked_at: Optional[str] = None


@router.post("/profiles", status_code=201)
def create_profile(req: ProfileCreateRequest):
    try:
        return store.create_profile(req.name, req.cloud_provider, req.config_profile_name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            f"A profile for {req.cloud_provider}/{req.config_profile_name} already exists. "
            "Each cloud provider + config profile pair can only be registered once.",
        )


@router.get("/profiles")
def list_profiles(cloud_provider: Optional[str] = None):
    items = store.list_profiles(cloud_provider)
    return {"items": items, "total": len(items)}


# NOTE: /profiles/active must be registered before the bare /profiles/{id}
# route below - same static-before-param-path ordering rule already
# documented in v1.py (FastAPI/Starlette matches route patterns in
# registration order).
@router.get("/profiles/active")
def get_active_profile(cloud_provider: str):
    profile = store.get_active_profile(cloud_provider)
    if profile is None:
        raise HTTPException(404, "No active profile for this provider")
    return profile


@router.get("/profiles/{profile_id}")
def get_profile(profile_id: str):
    profile = store.get_profile(profile_id)
    if profile is None:
        raise HTTPException(404, "Profile not found")
    return profile


@router.patch("/profiles/{profile_id}")
def update_profile(profile_id: str, req: ProfileUpdateRequest):
    if store.get_profile(profile_id) is None:
        raise HTTPException(404, "Profile not found")
    try:
        return store.update_profile(
            profile_id, name=req.name, config_profile_name=req.config_profile_name,
            verify_status=req.verify_status, verify_message=req.verify_message, verified_at=req.verified_at,
            whoami_result=req.whoami_result, whoami_checked_at=req.whoami_checked_at,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            "A profile for this cloud provider / config profile pair already exists.",
        )


@router.post("/profiles/{profile_id}/activate")
def activate_profile(profile_id: str):
    profile = store.activate_profile(profile_id)
    if profile is None:
        raise HTTPException(404, "Profile not found")
    return profile


@router.delete("/profiles/{profile_id}")
def delete_profile(profile_id: str):
    if not store.delete_profile(profile_id):
        raise HTTPException(404, "Profile not found")
    return {"status": "ok"}
