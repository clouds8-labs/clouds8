"""
Clouds8 — GCS Bucket Scanner
Scans GCP Cloud Storage buckets across projects for security
misconfigurations. Ported from gcp-pentest-platform's
backend/services/gcs/scanner.py (GCSScanner._analyze_bucket) - the GCS API
calls and risk logic are reused, the async/FastAPI scaffolding is not.

Checks:
  - Public access via IAM (allUsers / allAuthenticatedUsers)
  - Uniform bucket-level access disabled (per-object ACLs allowed)
  - Object versioning disabled
  - Public access prevention not enforced
  - No customer-managed encryption key (CMEK)
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class BucketFinding:
    bucket_name: str
    project_id: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "project_id": self.project_id,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class BucketDetail:
    bucket_name: str
    project_id: str
    location: str
    storage_class: str
    has_public_access: bool
    uniform_bucket_level_access: bool
    public_access_prevention: str
    versioning_enabled: bool
    default_kms_key: Optional[str]
    region: str = "unknown"
    findings: List[BucketFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "project_id": self.project_id,
            "location": self.location,
            "storage_class": self.storage_class,
            "has_public_access": self.has_public_access,
            "uniform_bucket_level_access": self.uniform_bucket_level_access,
            "public_access_prevention": self.public_access_prevention,
            "versioning_enabled": self.versioning_enabled,
            "default_kms_key": self.default_kms_key,
            "region": self.region,
            "findings": [f.to_dict() for f in self.findings],
            "risk_level": self._risk_level(),
        }

    def _risk_level(self) -> str:
        if any(f.severity == "CRITICAL" for f in self.findings):
            return "CRITICAL"
        if any(f.severity == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f.severity == "MEDIUM" for f in self.findings):
            return "MEDIUM"
        if self.findings:
            return "LOW"
        return "PASS"


@dataclass
class BucketScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_buckets: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    buckets: List[BucketDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_buckets": self.total_buckets,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "buckets": [b.to_dict() for b in self.buckets],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_public_access(b: BucketDetail) -> Optional[BucketFinding]:
    if b.has_public_access:
        return BucketFinding(
            bucket_name=b.bucket_name, project_id=b.project_id,
            check_id="gcp-bucket-public",
            severity="CRITICAL",
            title="Public Bucket Exposure",
            detail=f"Bucket '{b.bucket_name}' is publicly accessible via IAM "
                   "(allUsers or allAuthenticatedUsers).",
            remediation="Remove allUsers/allAuthenticatedUsers from the bucket's IAM bindings.",
        )
    return None


def _check_uniform_access(b: BucketDetail) -> Optional[BucketFinding]:
    if not b.uniform_bucket_level_access:
        return BucketFinding(
            bucket_name=b.bucket_name, project_id=b.project_id,
            check_id="gcp-bucket-no-uniform-access",
            severity="HIGH",
            title="Uniform Bucket-Level Access Disabled",
            detail=f"Bucket '{b.bucket_name}' allows per-object ACLs, which can grant "
                   "access that bypasses bucket-level IAM policy.",
            remediation="Enable uniform bucket-level access so all access is governed by IAM.",
        )
    return None


def _check_versioning(b: BucketDetail) -> Optional[BucketFinding]:
    if not b.versioning_enabled:
        return BucketFinding(
            bucket_name=b.bucket_name, project_id=b.project_id,
            check_id="gcp-bucket-no-versioning",
            severity="MEDIUM",
            title="Object Versioning Disabled",
            detail=f"Bucket '{b.bucket_name}' has versioning disabled - deleted or "
                   "overwritten objects are unrecoverable.",
            remediation="Enable object versioning for recovery from accidental deletion/overwrite.",
        )
    return None


def _check_public_access_prevention(b: BucketDetail) -> Optional[BucketFinding]:
    if b.public_access_prevention == "unspecified":
        return BucketFinding(
            bucket_name=b.bucket_name, project_id=b.project_id,
            check_id="gcp-bucket-no-pap",
            severity="MEDIUM",
            title="Public Access Prevention Not Enforced",
            detail=f"Bucket '{b.bucket_name}' does not enforce public access prevention at the bucket level.",
            remediation="Set publicAccessPrevention to 'enforced' on the bucket.",
        )
    return None


def _check_cmek(b: BucketDetail) -> Optional[BucketFinding]:
    if not b.default_kms_key:
        return BucketFinding(
            bucket_name=b.bucket_name, project_id=b.project_id,
            check_id="gcp-bucket-no-cmek",
            severity="LOW",
            title="No Customer-Managed Encryption Key",
            detail=f"Bucket '{b.bucket_name}' uses Google-managed encryption only (no CMEK).",
            remediation="Configure a default Cloud KMS key for server-side encryption if required by policy.",
        )
    return None


ALL_CHECKS = [_check_public_access, _check_uniform_access, _check_versioning,
              _check_public_access_prevention, _check_cmek]


# ---------------------------------------------------------------------------
# Bucket Scanner
# ---------------------------------------------------------------------------
class GcpBucketScanner:
    """Scans GCS buckets across projects for security misconfigurations."""

    def __init__(self, collector=None, progress_callback=None, run_checks: bool = True):
        self.collector = collector
        self.progress_callback = progress_callback
        self.run_checks = run_checks

    def _progress(self, msg: str):
        logger.info(msg)
        if self.progress_callback:
            try:
                self.progress_callback(msg)
            except Exception:
                pass

    def run(self, compartment_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None,
            asset_ids: Optional[List[str]] = None) -> BucketScanReport:
        report = BucketScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_buckets = len(report.buckets)

        all_findings = [f for b in report.buckets for f in b.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: BucketScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP Bucket Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            storage_client = self.collector.get_client("storage")
            if not storage_client:
                self._progress("GCP Bucket Scanner: Storage client not available")
                report.buckets = []
                return

            self._progress(f"GCP Bucket Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            def _scan_project(proj):
                project_id = proj["id"]
                buckets = []
                try:
                    result = storage_client.buckets().list(project=project_id, projection="full").execute()
                    for bucket in result.get("items", []):
                        detail = self._analyze_bucket(bucket, project_id, storage_client)
                        # GCP's list API is already project-wide - this filters
                        # client-side after the fetch, it cannot skip the
                        # underlying API call the way OCI's per-region client
                        # setup can.
                        if regions and detail.region not in regions:
                            continue
                        if asset_ids and detail.bucket_name not in asset_ids:
                            continue
                        if self.run_checks:
                            for check in ALL_CHECKS:
                                finding = check(detail)
                                if finding:
                                    detail.findings.append(finding)
                        buckets.append(detail)
                except Exception as e:
                    logger.debug(f"GCP Bucket Scanner: Error in project {project_id}: {e}")
                return buckets

            all_buckets = []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        all_buckets.extend(f.result())
                    except Exception as e:
                        logger.error(f"GCP Bucket Scanner thread error: {e}")

            report.buckets = all_buckets
            self._progress(f"GCP Bucket Scanner: Found {len(all_buckets)} buckets. Complete!")

        except GCPAuthError:
            raise
        except Exception as e:
            logger.error("GCP Bucket Scanner live scan error: %s", e)
            self._progress(f"GCP Bucket Scanner: Error — {e}")

    def _analyze_bucket(self, bucket: dict, project_id: str, storage_client) -> BucketDetail:
        name = bucket.get("name", "")

        has_public_access = False
        try:
            iam_policy = storage_client.buckets().getIamPolicy(bucket=name).execute()
            has_public_access = any(
                m in PUBLIC_MEMBERS
                for binding in iam_policy.get("bindings", [])
                for m in binding.get("members", [])
            )
        except Exception:
            pass

        iam_config = bucket.get("iamConfiguration", {})
        return BucketDetail(
            bucket_name=name,
            project_id=project_id,
            location=bucket.get("location", ""),
            storage_class=bucket.get("storageClass", ""),
            has_public_access=has_public_access,
            uniform_bucket_level_access=iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False),
            public_access_prevention=iam_config.get("publicAccessPrevention", "unspecified"),
            versioning_enabled=bucket.get("versioning", {}).get("enabled", False),
            default_kms_key=bucket.get("encryption", {}).get("defaultKmsKeyName"),
            region=(bucket.get("location") or "unknown").lower(),
        )

    def _run_mock(self, report: BucketScanReport):
        self._progress("GCP Bucket Scanner: Running in mock mode...")

        mock_bucket = BucketDetail(
            bucket_name="mock-public-bucket", project_id="mock-project",
            location="US", storage_class="STANDARD",
            has_public_access=True, uniform_bucket_level_access=False,
            public_access_prevention="unspecified", versioning_enabled=False,
            default_kms_key=None, region="us",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_bucket)
                if finding:
                    mock_bucket.findings.append(finding)

        mock_bucket2 = BucketDetail(
            bucket_name="mock-logs-bucket", project_id="mock-project",
            location="US-CENTRAL1", storage_class="STANDARD",
            has_public_access=False, uniform_bucket_level_access=True,
            public_access_prevention="enforced", versioning_enabled=True,
            default_kms_key="projects/mock-project/locations/us/keyRings/r/cryptoKeys/k",
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_bucket2)
                if finding:
                    mock_bucket2.findings.append(finding)

        report.buckets = [mock_bucket, mock_bucket2]
        report.projects_scanned = 1
        self._progress("GCP Bucket Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_bucket_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                         progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP bucket scan and return results as a dict."""
    scanner = GcpBucketScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
