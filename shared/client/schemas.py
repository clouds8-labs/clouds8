"""
Clouds8 shared client - typed models for DB service / Backend API responses.

Grows incrementally as pages migrate onto the shared client (see
services/db-service/app.py and services/backend-api/app.py for the full
endpoint surface still to be covered).
"""
from typing import Any, Optional

from pydantic import BaseModel


class Job(BaseModel):
    id: str
    job_type: str
    cloud_provider: Optional[str] = None
    scope_id: Optional[str] = None
    status: str
    progress_pct: Optional[int] = 0
    progress_message: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_message: Optional[str] = None
    result_ref: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.status in ("pending", "running")


class LogEntry(BaseModel):
    id: Optional[int] = None
    timestamp: str
    level: str
    source: str
    message: str
    ip: Optional[str] = None
    metadata: Optional[str] = None


class LogStats(BaseModel):
    total: int
    errors: int
    warnings: int
    sources: int
    ips: int
