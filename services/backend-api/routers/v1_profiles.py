"""
Clouds8 Backend API - Profile verification

The one Profile action needing the cloud provider's own SDK, which only
backend-api has access to (db-service owns persisted CRUD for everything
else about a Profile - see services/db-service/routers/profiles.py).
Fetches the Profile from db-service, attempts to build a real collector
for it, makes one cheap real API call to prove connectivity (not just
that the local config file parsed), and writes the result back.
"""
import json
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from collectors.registry import get_collector
from collectors.whoami import get_whoami
from db import database as db

router = APIRouter(prefix="/v1", tags=["profiles"])

# Suppressed pending UI fixes (truncated permission list, per-item risk
# dots) - whoami_profile's own logic/tests are untouched; flip back to
# True to re-enable the endpoint without any other change.
WHOAMI_ENABLED = False


class VerifyResult(BaseModel):
    profile_id: str
    status: str
    message: str
    verified_at: str


def _attempt_verify(cloud_provider: str, config_profile_name: str):
    if cloud_provider not in ("oci", "gcp"):
        return "failed", f"{cloud_provider.upper()} collector not implemented yet — falls back to mock data."
    try:
        collector = get_collector(cloud_provider, config_profile_name=config_profile_name)
    except Exception as e:
        return "failed", f"Could not construct collector: {e}"
    if not collector.config:
        init_error = getattr(collector, "init_error", None)
        if init_error:
            return "failed", f"Could not load credentials for '{config_profile_name}' — {init_error}"
        hint = (
            f"check the file exists and the section name is correct"
            if cloud_provider == "oci"
            else f"check the service-account key file exists at '{config_profile_name}' and is valid"
        )
        return "failed", f"Could not load credentials for '{config_profile_name}' — {hint}."

    if cloud_provider == "gcp":
        try:
            crm = collector.clients.get("cloudresourcemanager")
            proj = crm.projects().get(projectId=collector.project_id).execute()
            return "ok", f"Connected to GCP project '{proj.get('name', proj.get('projectId'))}' ({collector.project_id})."
        except Exception as e:
            return "failed", f"Key loaded but API call failed: {e}"

    try:
        tenancy_id = collector.config.get("tenancy")
        identity = collector.clients.get("identity")
        comp = identity.get_compartment(tenancy_id).data
        return "ok", f"Connected to tenancy '{comp.name}' ({tenancy_id})."
    except Exception as e:
        return "failed", f"Config loaded but API call failed: {e}"


@router.post("/profiles/{profile_id}/verify", response_model=VerifyResult)
def verify_profile(profile_id: str):
    profile = db.get_profile(profile_id)
    if profile is None:
        raise HTTPException(404, "Profile not found")
    status, message = _attempt_verify(profile["cloud_provider"], profile["config_profile_name"])
    verified_at = datetime.now().isoformat()
    db.update_profile(profile_id, verify_status=status, verify_message=message, verified_at=verified_at)
    return VerifyResult(profile_id=profile_id, status=status, message=message, verified_at=verified_at)


class WhoAmIProfileResult(BaseModel):
    profile_id: str
    whoami: Dict[str, Any]
    whoami_checked_at: str


@router.post("/profiles/{profile_id}/whoami", response_model=WhoAmIProfileResult)
def whoami_profile(profile_id: str):
    """Independent of verify_profile - identifies this Profile's credential
    and its effective permissions, on its own trigger (the UI's "Check
    Permissions" button, not the "Verify" button). Never touches
    verify_status/verify_message."""
    if not WHOAMI_ENABLED:
        raise HTTPException(404, "Not Found")
    profile = db.get_profile(profile_id)
    if profile is None:
        raise HTTPException(404, "Profile not found")

    cloud_provider = profile["cloud_provider"]
    config_profile_name = profile["config_profile_name"]
    if cloud_provider not in ("oci", "gcp"):
        raise HTTPException(422, f"{cloud_provider.upper()} whoami not implemented yet")

    try:
        collector = get_collector(cloud_provider, config_profile_name=config_profile_name)
    except Exception as e:
        raise HTTPException(422, f"Could not construct collector: {e}")
    if not collector.config:
        init_error = getattr(collector, "init_error", None)
        raise HTTPException(422, f"Could not load credentials for '{config_profile_name}'" + (f" — {init_error}" if init_error else "."))

    try:
        whoami_result = get_whoami(cloud_provider, collector).run()
    except Exception as e:
        raise HTTPException(422, f"whoami failed: {e}")

    checked_at = datetime.now().isoformat()
    db.update_profile(profile_id, whoami_result=json.dumps(whoami_result), whoami_checked_at=checked_at)
    return WhoAmIProfileResult(profile_id=profile_id, whoami=whoami_result, whoami_checked_at=checked_at)
