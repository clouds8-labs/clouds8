"""
Clouds8 Backend API - Collector helper

Builds a cloud collector for scans, falling back to mock data when the
provider SDK is not configured (mirrors the behaviour of the Dash UI).
"""
import logging
from typing import Optional

from collectors.base_collector import BaseCollector
from collectors.registry import get_collector
from db import database as db

logger = logging.getLogger("Clouds8-BackendAPI")


def build_collector(provider: str = "oci", profile_id: Optional[str] = None) -> Optional[BaseCollector]:
    """Return a collector instance for ``provider``.

    When ``profile_id`` is given, resolves that specific Profile instead of
    whichever one is currently marked active - used by explicit per-run/
    per-schedule profile selection, which must not be affected by the
    global active-profile flag changing underneath a background job. In
    this case, a collector that fails to connect raises ``RuntimeError``
    instead of silently falling back to mock data: a scan explicitly fired
    against a real Profile must never report fabricated results as if they
    were that profile's live data (see routers/v1_runs.py's _fire_run,
    which turns this into a 422 before any job/mock scan starts).

    Without ``profile_id`` (legacy /scans and /sync entry points, which
    predate the Profiles/Engagements model and have no specific profile to
    blame), resolves whichever Profile is currently marked active for
    ``provider``. Falls back to the collector class's own default/mock
    behaviour if no matching Profile exists, or if the lookup itself fails
    (db-service unreachable) - never raises in this mode.
    """
    config_profile_name = None
    try:
        profile = db.get_profile(profile_id) if profile_id else db.get_active_profile(provider)
        if profile:
            config_profile_name = profile.get("config_profile_name")
    except Exception as e:
        logger.warning("Could not look up profile for '%s': %s — using provider default", provider, e)

    try:
        collector = get_collector(provider, config_profile_name=config_profile_name)
    except Exception as e:  # unknown provider or import failure
        if profile_id:
            raise RuntimeError(f"Could not create {provider.upper()} collector: {e}") from e
        logger.warning("Could not create '%s' collector: %s — using mock data", provider, e)
        return None

    # OCICollector (and future collectors) expose a ``config`` attribute that
    # is falsy when credentials are missing.
    if not getattr(collector, "config", True):
        if profile_id:
            init_error = getattr(collector, "init_error", None)
            detail = f" — {init_error}" if init_error else " — check the profile's credentials."
            raise RuntimeError(f"Could not connect to {provider.upper()} using profile '{config_profile_name}'{detail}")
        logger.info("%s not configured — falling back to mock data", provider.upper())
        return None

    return collector
