"""
Clouds8 — GCP IAM & Service Account Scanner
Scans GCP service accounts and project IAM for security misconfigurations
and static privilege-escalation indicators. Ported from
gcp-pentest-platform's backend/services/iam_scan/scanner.py (per-SA checks)
and backend/services/privesc/engine.py's PRIVESC_METHODS catalog (static
detection only - the full attack-path graph in that module is out of scope
here, deferred to a future provider-agnostic Attack Paths effort).

Checks:
  - Service account has user-managed (downloadable) keys
  - Service account has a public IAM binding (allUsers/allAuthenticatedUsers)
  - Service account has been granted roles/iam.serviceAccountTokenCreator
  - Caller holds a known IAM privilege-escalation permission at project level
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10

# A representative subset of gcp-pentest-platform's 17-method privesc
# catalog (services/privesc/engine.py) - detection only, no graph/chaining.
PRIVESC_METHODS = [
    {
        "id": "iam_serviceaccounts_getaccesstoken",
        "permission": "iam.serviceAccounts.getAccessToken",
        "title": "Service Account Token Generation",
        "detail": "The caller can generate access tokens for any service account via "
                  "generateAccessToken, allowing impersonation of a higher-privileged SA.",
        "severity": "CRITICAL",
        "remediation": "Remove iam.serviceAccounts.getAccessToken from non-admin identities; "
                       "use Workload Identity Federation instead of long-lived tokens.",
    },
    {
        "id": "iam_serviceaccountkeys_create",
        "permission": "iam.serviceAccountKeys.create",
        "title": "Service Account Key Creation",
        "detail": "The caller can create persistent JSON key files for any service account "
                  "in the project, enabling long-term impersonation.",
        "severity": "HIGH",
        "remediation": "Remove iam.serviceAccountKeys.create from non-admin identities; "
                       "disable user-managed SA keys via an org policy where possible.",
    },
    {
        "id": "resourcemanager_projects_setiampolicy",
        "permission": "resourcemanager.projects.setIamPolicy",
        "title": "Project IAM Policy Modification",
        "detail": "The caller can directly modify the project's IAM policy, including "
                  "granting themselves roles/owner.",
        "severity": "CRITICAL",
        "remediation": "Remove resourcemanager.projects.setIamPolicy from non-admin identities; "
                       "require policy changes to go through a reviewed process.",
    },
    {
        "id": "iam_roles_update",
        "permission": "iam.roles.update",
        "title": "IAM Role Update Privilege Escalation",
        "detail": "The caller can update existing IAM roles, adding new permissions to a "
                  "role they already hold and granting themselves any GCP permission.",
        "severity": "CRITICAL",
        "remediation": "Remove iam.roles.update from non-admin identities; use predefined roles where possible.",
    },
    {
        "id": "cloudbuild_builds_create",
        "permission": "cloudbuild.builds.create",
        "title": "Cloud Build Privilege Escalation",
        "detail": "The caller can submit Cloud Build jobs, which run as the Cloud Build "
                  "service account (Editor role by default) - full project control.",
        "severity": "CRITICAL",
        "remediation": "Restrict the Cloud Build service account's permissions; "
                       "audit and remove unnecessary cloudbuild.builds.create grants.",
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class IamFinding:
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
class ServiceAccountDetail:
    unique_id: str
    email: str
    project_id: str
    disabled: bool
    has_user_keys: bool
    has_public_binding: bool
    has_token_creator: bool
    region: str = "global"
    findings: List[IamFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unique_id": self.unique_id,
            "email": self.email,
            "project_id": self.project_id,
            "disabled": self.disabled,
            "has_user_keys": self.has_user_keys,
            "has_public_binding": self.has_public_binding,
            "has_token_creator": self.has_token_creator,
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
class GcpIamScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_service_accounts: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    service_accounts: List[ServiceAccountDetail] = field(default_factory=list)
    # Project-level privesc findings aren't tied to one SA, kept alongside.
    project_findings: List[IamFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_service_accounts": self.total_service_accounts,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "service_accounts": [sa.to_dict() for sa in self.service_accounts],
            "findings": [f.to_dict() for f in self.project_findings],
        }


# ---------------------------------------------------------------------------
# Per-service-account checks
# ---------------------------------------------------------------------------
def _check_user_keys(sa: ServiceAccountDetail) -> Optional[IamFinding]:
    if sa.has_user_keys:
        return IamFinding(
            resource_id=sa.unique_id, resource_name=sa.email, project_id=sa.project_id,
            check_id="gcp-iam-sa-user-keys",
            severity="HIGH",
            title="Service Account Has User-Managed Keys",
            detail=f"Service account '{sa.email}' has downloadable, long-lived JSON key(s).",
            remediation="Delete user-managed keys and use Workload Identity Federation or short-lived tokens.",
        )
    return None


def _check_public_binding(sa: ServiceAccountDetail) -> Optional[IamFinding]:
    if sa.has_public_binding:
        return IamFinding(
            resource_id=sa.unique_id, resource_name=sa.email, project_id=sa.project_id,
            check_id="gcp-iam-sa-public-binding",
            severity="CRITICAL",
            title="Service Account Publicly Accessible",
            detail=f"Service account '{sa.email}' grants a role to allUsers/allAuthenticatedUsers.",
            remediation="Remove allUsers/allAuthenticatedUsers from the service account's IAM policy.",
        )
    return None


def _check_token_creator(sa: ServiceAccountDetail) -> Optional[IamFinding]:
    if sa.has_token_creator:
        return IamFinding(
            resource_id=sa.unique_id, resource_name=sa.email, project_id=sa.project_id,
            check_id="gcp-iam-sa-token-creator",
            severity="HIGH",
            title="Service Account Token Creator Role Granted",
            detail=f"Another principal holds roles/iam.serviceAccountTokenCreator on '{sa.email}', "
                   "allowing impersonation of this service account.",
            remediation="Review and remove unnecessary serviceAccountTokenCreator bindings.",
        )
    return None


ALL_SA_CHECKS = [_check_user_keys, _check_public_binding, _check_token_creator]


def _privesc_findings_for_project(project_id: str, granted_permissions: List[str]) -> List[IamFinding]:
    findings = []
    granted = set(granted_permissions)
    for method in PRIVESC_METHODS:
        if method["permission"] in granted:
            findings.append(IamFinding(
                resource_id=project_id, resource_name=project_id, project_id=project_id,
                check_id=f"gcp-privesc-{method['id']}",
                severity=method["severity"],
                title=method["title"],
                detail=method["detail"],
                remediation=method["remediation"],
            ))
    return findings


# ---------------------------------------------------------------------------
# IAM Scanner
# ---------------------------------------------------------------------------
class GcpIamScanner:
    """Scans GCP service accounts and project IAM across projects."""

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
            asset_ids: Optional[List[str]] = None) -> GcpIamScanReport:
        report = GcpIamScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_service_accounts = len(report.service_accounts)

        all_findings = [f for sa in report.service_accounts for f in sa.findings] + report.project_findings
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: GcpIamScanReport, compartment_ids: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP IAM Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            iam_client = self.collector.get_client("iam")
            crm_client = self.collector.get_client("cloudresourcemanager")
            if not iam_client:
                self._progress("GCP IAM Scanner: IAM client not available")
                return

            self._progress(f"GCP IAM Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            risky_permissions = [m["permission"] for m in PRIVESC_METHODS]

            def _scan_project(proj):
                project_id = proj["id"]
                sas, project_findings = [], []
                try:
                    if crm_client:
                        resp = crm_client.projects().testIamPermissions(
                            resource=project_id, body={"permissions": risky_permissions},
                        ).execute()
                        project_findings = _privesc_findings_for_project(project_id, resp.get("permissions", []))

                    page_token = None
                    while True:
                        resp = iam_client.projects().serviceAccounts().list(
                            name=f"projects/{project_id}", pageToken=page_token,
                        ).execute()
                        for sa in resp.get("accounts", []):
                            detail = self._analyze_sa(sa, project_id, iam_client)
                            if asset_ids and detail.unique_id not in asset_ids:
                                continue
                            if self.run_checks:
                                for check in ALL_SA_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            sas.append(detail)
                        page_token = resp.get("nextPageToken")
                        if not page_token:
                            break
                except Exception as e:
                    logger.debug(f"GCP IAM Scanner: Error in project {project_id}: {e}")
                return sas, project_findings

            all_sas, all_project_findings = [], []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        sas, project_findings = f.result()
                        all_sas.extend(sas)
                        all_project_findings.extend(project_findings)
                    except Exception as e:
                        logger.error(f"GCP IAM Scanner thread error: {e}")

            report.service_accounts = all_sas
            report.project_findings = all_project_findings if self.run_checks else []
            self._progress(f"GCP IAM Scanner: Found {len(all_sas)} service accounts. Complete!")

        except GCPAuthError:
            raise
        except Exception as e:
            logger.error("GCP IAM Scanner live scan error: %s", e)
            self._progress(f"GCP IAM Scanner: Error — {e}")

    def _analyze_sa(self, sa: dict, project_id: str, iam_client) -> ServiceAccountDetail:
        email = sa.get("email", "")
        sa_name = sa.get("name", f"projects/{project_id}/serviceAccounts/{email}")

        has_user_keys = False
        try:
            resp = iam_client.projects().serviceAccounts().keys().list(
                name=sa_name, keyTypes=["USER_MANAGED"],
            ).execute()
            has_user_keys = len(resp.get("keys", [])) > 0
        except Exception:
            pass

        has_public_binding = False
        has_token_creator = False
        try:
            resp = iam_client.projects().serviceAccounts().getIamPolicy(resource=sa_name).execute()
            for binding in resp.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    has_public_binding = True
                if binding.get("role") == "roles/iam.serviceAccountTokenCreator":
                    has_token_creator = True
        except Exception:
            pass

        return ServiceAccountDetail(
            unique_id=sa.get("uniqueId", email),
            email=email,
            project_id=project_id,
            disabled=sa.get("disabled", False),
            has_user_keys=has_user_keys,
            has_public_binding=has_public_binding,
            has_token_creator=has_token_creator,
        )

    def _run_mock(self, report: GcpIamScanReport):
        self._progress("GCP IAM Scanner: Running in mock mode...")

        mock_sa = ServiceAccountDetail(
            unique_id="111111111111111111111", email="ci-deploy@mock-project.iam.gserviceaccount.com",
            project_id="mock-project", disabled=False,
            has_user_keys=True, has_public_binding=False, has_token_creator=True,
        )
        if self.run_checks:
            for check in ALL_SA_CHECKS:
                finding = check(mock_sa)
                if finding:
                    mock_sa.findings.append(finding)

        report.service_accounts = [mock_sa]
        report.project_findings = (
            _privesc_findings_for_project("mock-project", ["iam.serviceAccountKeys.create"])
            if self.run_checks else []
        )
        report.projects_scanned = 1
        self._progress("GCP IAM Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_iam_scan(collector=None, compartment_ids=None, asset_ids=None,
                      progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP IAM scan and return results as a dict."""
    scanner = GcpIamScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, asset_ids=asset_ids)
    return report.to_dict()
