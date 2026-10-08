"""
Clouds8 — GCP Secret Manager Scanner
Scans GCP Secret Manager secrets for security misconfigurations and static
privilege-escalation indicators. Ported from gcp-pentest-platform's
backend/services/secrets/scanner.py - per-secret checks plus its
testIamPermissions-based risky-permission catalog (detection only, no
exploit-command strings - matches gcp_iam_scanner.py's existing precedent
for porting that module's privesc checks as plain findings+remediation).

Checks:
  - Secret has a public IAM binding (allUsers/allAuthenticatedUsers)
  - Secret has no automatic rotation configured
  - Secret has no expiration/TTL set
  - Secret uses Google-managed (not customer-managed) encryption
  - Caller holds a known Secret Manager privilege-escalation permission
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}

# Ported from gcp-pentest-platform's RISKY_PERMISSIONS/PERMISSION_SEVERITY/
# PERMISSION_DESCRIPTION maps - what the scanning credential itself can do
# to secrets, not a per-secret misconfiguration.
PRIVESC_METHODS = [
    {
        "id": "secretmanager_secrets_setiampolicy",
        "permission": "secretmanager.secrets.setIamPolicy",
        "title": "Secret IAM Policy Modification",
        "detail": "The caller can grant itself or anyone else access to any secret in the project.",
        "severity": "CRITICAL",
        "remediation": "Remove secretmanager.secrets.setIamPolicy from non-admin identities.",
    },
    {
        "id": "secretmanager_versions_access",
        "permission": "secretmanager.versions.access",
        "title": "Secret Version Access",
        "detail": "The caller can read the plaintext value of any secret version in the project.",
        "severity": "CRITICAL",
        "remediation": "Scope secretmanager.versions.access to only the specific secrets each identity needs.",
    },
    {
        "id": "secretmanager_secrets_delete",
        "permission": "secretmanager.secrets.delete",
        "title": "Secret Deletion",
        "detail": "The caller can permanently delete secrets, a potential denial-of-service vector.",
        "severity": "HIGH",
        "remediation": "Remove secretmanager.secrets.delete from non-admin identities.",
    },
    {
        "id": "secretmanager_versions_destroy",
        "permission": "secretmanager.versions.destroy",
        "title": "Secret Version Destruction",
        "detail": "The caller can permanently destroy secret versions, losing the secret material irrecoverably.",
        "severity": "HIGH",
        "remediation": "Remove secretmanager.versions.destroy from non-admin identities.",
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class SecretFinding:
    resource_id: str
    resource_name: str
    project_id: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "project_id": self.project_id,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class SecretDetail:
    secret_id: str
    full_name: str
    project_id: str
    replication_type: str
    encryption_type: str
    rotation_enabled: bool
    has_expiration: bool
    has_public_access: bool
    version_count: int
    region: str = "global"
    findings: List[SecretFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "full_name": self.full_name,
            "project_id": self.project_id,
            "replication_type": self.replication_type,
            "encryption_type": self.encryption_type,
            "rotation_enabled": self.rotation_enabled,
            "has_expiration": self.has_expiration,
            "has_public_access": self.has_public_access,
            "version_count": self.version_count,
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
class GcpSecretsScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_secrets: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    secrets: List[SecretDetail] = field(default_factory=list)
    # Project-level privesc findings aren't tied to one secret, kept alongside.
    project_findings: List[SecretFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_secrets": self.total_secrets,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "secrets": [s.to_dict() for s in self.secrets],
            "findings": [f.to_dict() for f in self.project_findings],
        }


# ---------------------------------------------------------------------------
# Per-secret checks
# ---------------------------------------------------------------------------
def _check_public_access(s: SecretDetail) -> Optional[SecretFinding]:
    if s.has_public_access:
        return SecretFinding(
            resource_id=s.secret_id, resource_name=s.secret_id, project_id=s.project_id,
            check_id="gcp-secrets-public-access",
            severity="CRITICAL",
            title="Secret Publicly Accessible",
            detail=f"Secret '{s.secret_id}' grants a role to allUsers/allAuthenticatedUsers.",
            remediation="Remove allUsers/allAuthenticatedUsers from the secret's IAM policy.",
        )
    return None


def _check_no_rotation(s: SecretDetail) -> Optional[SecretFinding]:
    if not s.rotation_enabled:
        return SecretFinding(
            resource_id=s.secret_id, resource_name=s.secret_id, project_id=s.project_id,
            check_id="gcp-secrets-no-rotation",
            severity="HIGH",
            title="No Automatic Rotation Configured",
            detail=f"Secret '{s.secret_id}' has no rotation schedule - versions never expire on their own.",
            remediation="Configure a rotation period and Pub/Sub topic so this secret rotates automatically.",
        )
    return None


def _check_no_expiration(s: SecretDetail) -> Optional[SecretFinding]:
    if not s.has_expiration:
        return SecretFinding(
            resource_id=s.secret_id, resource_name=s.secret_id, project_id=s.project_id,
            check_id="gcp-secrets-no-expiration",
            severity="MEDIUM",
            title="No Expiration Set",
            detail=f"Secret '{s.secret_id}' has no expire time or TTL - it lives indefinitely.",
            remediation="Set an expiration time or TTL appropriate for this secret's lifecycle.",
        )
    return None


def _check_non_cmek(s: SecretDetail) -> Optional[SecretFinding]:
    if s.encryption_type == "Google-managed":
        return SecretFinding(
            resource_id=s.secret_id, resource_name=s.secret_id, project_id=s.project_id,
            check_id="gcp-secrets-no-cmek",
            severity="LOW",
            title="Google-Managed Encryption (Not CMEK)",
            detail=f"Secret '{s.secret_id}' uses Google-managed encryption instead of a customer-managed key.",
            remediation="Configure customer-managed encryption (CMEK) for secrets holding sensitive material.",
        )
    return None


ALL_SECRET_CHECKS = [_check_public_access, _check_no_rotation, _check_no_expiration, _check_non_cmek]


def _privesc_findings_for_project(project_id: str, granted_permissions: List[str]) -> List[SecretFinding]:
    findings = []
    granted = set(granted_permissions)
    for method in PRIVESC_METHODS:
        if method["permission"] in granted:
            findings.append(SecretFinding(
                resource_id=project_id, resource_name=project_id, project_id=project_id,
                check_id=f"gcp-secrets-privesc-{method['id']}",
                severity=method["severity"],
                title=method["title"],
                detail=method["detail"],
                remediation=method["remediation"],
            ))
    return findings


# ---------------------------------------------------------------------------
# Secret Manager Scanner
# ---------------------------------------------------------------------------
class GcpSecretsScanner:
    """Scans GCP Secret Manager secrets across projects."""

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

    def run(self, compartment_ids: Optional[List[str]] = None,
            asset_ids: Optional[List[str]] = None) -> GcpSecretsScanReport:
        report = GcpSecretsScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_secrets = len(report.secrets)

        all_findings = [f for s in report.secrets for f in s.findings] + report.project_findings
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: GcpSecretsScanReport, compartment_ids: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP Secrets Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            sm_client = self.collector.get_client("secretmanager")
            crm_client = self.collector.get_client("cloudresourcemanager")
            if not sm_client:
                self._progress("GCP Secrets Scanner: Secret Manager client not available")
                return

            self._progress(f"GCP Secrets Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            risky_permissions = [m["permission"] for m in PRIVESC_METHODS]

            def _scan_project(proj):
                project_id = proj["id"]
                secrets, project_findings = [], []
                try:
                    if crm_client:
                        resp = crm_client.projects().testIamPermissions(
                            resource=project_id, body={"permissions": risky_permissions},
                        ).execute()
                        project_findings = _privesc_findings_for_project(project_id, resp.get("permissions", []))

                    page_token = None
                    while True:
                        resp = sm_client.projects().secrets().list(
                            parent=f"projects/{project_id}", pageToken=page_token,
                        ).execute()
                        for secret in resp.get("secrets", []):
                            detail = self._analyze_secret(secret, project_id, sm_client)
                            if asset_ids and detail.secret_id not in asset_ids:
                                continue
                            if self.run_checks:
                                for check in ALL_SECRET_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            secrets.append(detail)
                        page_token = resp.get("nextPageToken")
                        if not page_token:
                            break
                except Exception as e:
                    if getattr(getattr(e, "resp", None), "status", None) == 403:
                        raise PermissionError(
                            f"Profile lacks permission to list Secret Manager secrets in project "
                            f"'{project_id}' (secretmanager.secrets.list) — grant the service "
                            f"account the Secret Manager Viewer role."
                        ) from e
                    logger.debug(f"GCP Secrets Scanner: Error in project {project_id}: {e}")
                return secrets, project_findings

            all_secrets, all_project_findings = [], []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        secrets, project_findings = f.result()
                        all_secrets.extend(secrets)
                        all_project_findings.extend(project_findings)
                    except PermissionError:
                        raise
                    except Exception as e:
                        logger.error(f"GCP Secrets Scanner thread error: {e}")

            report.secrets = all_secrets
            report.project_findings = all_project_findings if self.run_checks else []
            self._progress(f"GCP Secrets Scanner: Found {len(all_secrets)} secrets. Complete!")

        except (PermissionError, GCPAuthError):
            raise
        except Exception as e:
            logger.error("GCP Secrets Scanner live scan error: %s", e)
            self._progress(f"GCP Secrets Scanner: Error — {e}")

    def _analyze_secret(self, secret: dict, project_id: str, sm_client) -> SecretDetail:
        full_name = secret.get("name", "")
        secret_id = full_name.split("/")[-1] if full_name else ""

        replication = secret.get("replication", {})
        replication_type = "automatic" if "automatic" in replication else "user-managed"

        cmek = (
            replication.get("automatic", {}).get("customerManagedEncryption")
            or (replication.get("userManaged", {}).get("replicas") or [{}])[0].get("customerManagedEncryption")
        )
        encryption_type = "CMEK" if cmek else "Google-managed"

        rotation = secret.get("rotation", {})
        rotation_enabled = bool(rotation.get("nextRotationTime"))

        has_expiration = bool(secret.get("expireTime") or secret.get("ttl"))

        has_public_access = False
        try:
            policy = sm_client.projects().secrets().getIamPolicy(resource=full_name).execute()
            for binding in policy.get("bindings", []):
                members = binding.get("members", [])
                if any(m in PUBLIC_PRINCIPALS for m in members):
                    has_public_access = True
        except Exception:
            pass

        version_count = 0
        try:
            versions = sm_client.projects().secrets().versions().list(parent=full_name).execute()
            version_count = len(versions.get("versions", []))
        except Exception:
            pass

        return SecretDetail(
            secret_id=secret_id,
            full_name=full_name,
            project_id=project_id,
            replication_type=replication_type,
            encryption_type=encryption_type,
            rotation_enabled=rotation_enabled,
            has_expiration=has_expiration,
            has_public_access=has_public_access,
            version_count=version_count,
        )

    def _run_mock(self, report: GcpSecretsScanReport):
        self._progress("GCP Secrets Scanner: Running in mock mode...")

        mock_secret = SecretDetail(
            secret_id="db-password", full_name="projects/mock-project/secrets/db-password",
            project_id="mock-project", replication_type="automatic", encryption_type="Google-managed",
            rotation_enabled=False, has_expiration=False, has_public_access=False, version_count=3,
        )
        if self.run_checks:
            for check in ALL_SECRET_CHECKS:
                finding = check(mock_secret)
                if finding:
                    mock_secret.findings.append(finding)

        report.secrets = [mock_secret]
        report.project_findings = (
            _privesc_findings_for_project("mock-project", ["secretmanager.versions.access"])
            if self.run_checks else []
        )
        report.projects_scanned = 1
        self._progress("GCP Secrets Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_secrets_scan(collector=None, compartment_ids=None, asset_ids=None,
                          progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP Secret Manager scan and return results as a dict."""
    scanner = GcpSecretsScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, asset_ids=asset_ids)
    return report.to_dict()
