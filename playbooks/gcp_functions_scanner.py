"""
Clouds8 — GCP Cloud Functions Scanner
Scans Cloud Functions (v2) for insecure configurations plus static
privilege-escalation indicators. Ported from gcp-pentest-platform's
backend/services/cloud_functions/scanner.py - per-function checks plus its
testIamPermissions-based risky-permission catalog (detection only, no
exploit-command strings - matches gcp_iam_scanner.py's existing precedent
for porting that module's privesc checks as plain findings+remediation).

Checks:
  - Function allows unauthenticated invocation (allUsers/allAuthenticatedUsers)
  - Function has environment variables that look like secrets (TOKEN/KEY/
    SECRET/PASSWORD/CRED in the key name)
  - Function runs as the default Compute service account
  - Caller holds a known Cloud Functions privilege-escalation permission
    (create+actAs is flagged as a single combined CRITICAL finding, same
    as the reference repo's escalation-chain special-case)
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
SENSITIVE_KEY_PATTERNS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CRED")

# Ported from gcp-pentest-platform's RISKY_PERMISSIONS/PERMISSION_SEVERITY/
# PERMISSION_DESCRIPTION maps.
PRIVESC_METHODS = [
    {
        "id": "cloudfunctions_functions_update",
        "permission": "cloudfunctions.functions.update",
        "title": "Cloud Function Code Modification",
        "detail": "The caller can modify existing function code/config, enabling a backdoor injection.",
        "severity": "CRITICAL",
        "remediation": "Remove cloudfunctions.functions.update from non-admin identities.",
    },
    {
        "id": "cloudfunctions_functions_call",
        "permission": "cloudfunctions.functions.call",
        "title": "Cloud Function Invocation Access",
        "detail": "The caller can invoke any function in the project, including internal/private ones.",
        "severity": "HIGH",
        "remediation": "Scope cloudfunctions.functions.call to only the functions each identity needs.",
    },
    {
        "id": "cloudfunctions_functions_setiampolicy",
        "permission": "cloudfunctions.functions.setIamPolicy",
        "title": "Cloud Function IAM Policy Modification",
        "detail": "The caller can grant external principals access to invoke or modify functions.",
        "severity": "HIGH",
        "remediation": "Remove cloudfunctions.functions.setIamPolicy from non-admin identities.",
    },
    {
        "id": "cloudfunctions_functions_sourcecodeget",
        "permission": "cloudfunctions.functions.sourceCodeGet",
        "title": "Cloud Function Source Code Access",
        "detail": "The caller can download function source code, potentially exposing hardcoded secrets.",
        "severity": "MEDIUM",
        "remediation": "Restrict cloudfunctions.functions.sourceCodeGet; audit source for hardcoded secrets.",
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FunctionFinding:
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
class FunctionDetail:
    function_name: str
    full_name: str
    project_id: str
    runtime: str
    state: str
    trigger_type: str
    allow_unauthenticated: bool
    sensitive_env_vars: List[str]
    uses_default_sa: bool
    region: str = "unknown"
    findings: List[FunctionFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "full_name": self.full_name,
            "project_id": self.project_id,
            "runtime": self.runtime,
            "state": self.state,
            "trigger_type": self.trigger_type,
            "allow_unauthenticated": self.allow_unauthenticated,
            "sensitive_env_vars": self.sensitive_env_vars,
            "uses_default_sa": self.uses_default_sa,
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
class GcpFunctionsScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_functions: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    functions: List[FunctionDetail] = field(default_factory=list)
    # Project-level privesc findings aren't tied to one function, kept alongside.
    project_findings: List[FunctionFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_functions": self.total_functions,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "functions": [f.to_dict() for f in self.functions],
            "findings": [f.to_dict() for f in self.project_findings],
        }


# ---------------------------------------------------------------------------
# Per-function checks
# ---------------------------------------------------------------------------
def _check_unauthenticated(fn: FunctionDetail) -> Optional[FunctionFinding]:
    if fn.allow_unauthenticated:
        severity = "CRITICAL" if fn.uses_default_sa else "HIGH"
        return FunctionFinding(
            resource_id=fn.function_name, resource_name=fn.function_name, project_id=fn.project_id,
            check_id="gcp-functions-unauthenticated",
            severity=severity,
            title="Function Allows Unauthenticated Invocation",
            detail=f"Function '{fn.function_name}' grants invoke access to allUsers/allAuthenticatedUsers"
                   + (" and runs as the default Compute service account." if fn.uses_default_sa else "."),
            remediation="Remove allUsers/allAuthenticatedUsers from the function's IAM policy; "
                        "require authenticated invocation and front with IAP/API Gateway if public access is needed.",
        )
    return None


def _check_sensitive_env_vars(fn: FunctionDetail) -> Optional[FunctionFinding]:
    if fn.sensitive_env_vars:
        return FunctionFinding(
            resource_id=fn.function_name, resource_name=fn.function_name, project_id=fn.project_id,
            check_id="gcp-functions-sensitive-env",
            severity="HIGH",
            title="Sensitive Environment Variables",
            detail=f"Function '{fn.function_name}' has env var(s) that look like secrets: "
                   f"{', '.join(fn.sensitive_env_vars)}.",
            remediation="Move secret values into Secret Manager and reference them at deploy time "
                        "instead of plaintext environment variables.",
        )
    return None


def _check_default_sa(fn: FunctionDetail) -> Optional[FunctionFinding]:
    if fn.uses_default_sa:
        return FunctionFinding(
            resource_id=fn.function_name, resource_name=fn.function_name, project_id=fn.project_id,
            check_id="gcp-functions-default-sa",
            severity="MEDIUM",
            title="Function Uses Default Compute Service Account",
            detail=f"Function '{fn.function_name}' runs as the default Compute SA, "
                   "which typically has broad project-level Editor access.",
            remediation="Create a dedicated, least-privilege service account for this function.",
        )
    return None


ALL_FUNCTION_CHECKS = [_check_unauthenticated, _check_sensitive_env_vars, _check_default_sa]


def _privesc_findings_for_project(project_id: str, granted_permissions: List[str]) -> List[FunctionFinding]:
    findings = []
    granted = set(granted_permissions)

    # Escalation-chain special case: create + actAs = deploy a function as a
    # high-privilege SA to steal its token - flag as one combined CRITICAL
    # finding instead of two separate lower-signal ones.
    has_create = "cloudfunctions.functions.create" in granted
    has_act_as = "iam.serviceAccounts.actAs" in granted
    if has_create and has_act_as:
        findings.append(FunctionFinding(
            resource_id=project_id, resource_name=project_id, project_id=project_id,
            check_id="gcp-functions-privesc-create-actas",
            severity="CRITICAL",
            title="Function Deploy + Service Account Impersonation",
            detail="The caller can deploy a new function running as any service account it can impersonate, "
                   "escalating to that service account's privileges.",
            remediation="Remove cloudfunctions.functions.create or iam.serviceAccounts.actAs "
                        "from non-admin identities - the combination enables full privilege escalation.",
        ))
        granted = granted - {"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"}

    for method in PRIVESC_METHODS:
        if method["permission"] in granted:
            findings.append(FunctionFinding(
                resource_id=project_id, resource_name=project_id, project_id=project_id,
                check_id=f"gcp-functions-privesc-{method['id']}",
                severity=method["severity"],
                title=method["title"],
                detail=method["detail"],
                remediation=method["remediation"],
            ))
    return findings


# ---------------------------------------------------------------------------
# Cloud Functions Scanner
# ---------------------------------------------------------------------------
class GcpFunctionsScanner:
    """Scans Cloud Functions (v2) across projects."""

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
            asset_ids: Optional[List[str]] = None) -> GcpFunctionsScanReport:
        report = GcpFunctionsScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_functions = len(report.functions)

        all_findings = [f for fn in report.functions for f in fn.findings] + report.project_findings
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: GcpFunctionsScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP Functions Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            cf_client = self.collector.get_client("cloudfunctions")
            crm_client = self.collector.get_client("cloudresourcemanager")
            if not cf_client:
                self._progress("GCP Functions Scanner: Cloud Functions client not available")
                return

            self._progress(f"GCP Functions Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            risky_permissions = [m["permission"] for m in PRIVESC_METHODS] + [
                "cloudfunctions.functions.create", "iam.serviceAccounts.actAs",
            ]

            def _scan_project(proj):
                project_id = proj["id"]
                functions, project_findings = [], []
                try:
                    if crm_client:
                        resp = crm_client.projects().testIamPermissions(
                            resource=project_id, body={"permissions": risky_permissions},
                        ).execute()
                        project_findings = _privesc_findings_for_project(project_id, resp.get("permissions", []))

                    parent = f"projects/{project_id}/locations/-"
                    request = cf_client.projects().locations().functions().list(parent=parent)
                    while request is not None:
                        response = request.execute()
                        for fn in response.get("functions", []):
                            detail = self._analyze_function(fn, project_id, cf_client)
                            # GCP's list API is already project-wide - this filters
                            # client-side after the fetch, it cannot skip the
                            # underlying API call the way OCI's per-region client
                            # setup can.
                            if regions and detail.region not in regions:
                                continue
                            if asset_ids and detail.function_name not in asset_ids:
                                continue
                            if self.run_checks:
                                for check in ALL_FUNCTION_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            functions.append(detail)
                        request = cf_client.projects().locations().functions().list_next(
                            previous_request=request, previous_response=response
                        )
                except Exception as e:
                    if getattr(getattr(e, "resp", None), "status", None) == 403:
                        raise PermissionError(
                            f"Profile lacks permission to list Cloud Functions in project "
                            f"'{project_id}' (cloudfunctions.functions.list) — grant the service "
                            f"account the Cloud Functions Viewer role."
                        ) from e
                    logger.debug(f"GCP Functions Scanner: Error in project {project_id}: {e}")
                return functions, project_findings

            all_functions, all_project_findings = [], []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        functions, project_findings = f.result()
                        all_functions.extend(functions)
                        all_project_findings.extend(project_findings)
                    except PermissionError:
                        raise
                    except Exception as e:
                        logger.error(f"GCP Functions Scanner thread error: {e}")

            report.functions = all_functions
            report.project_findings = all_project_findings if self.run_checks else []
            self._progress(f"GCP Functions Scanner: Found {len(all_functions)} functions. Complete!")

        except (PermissionError, GCPAuthError):
            raise
        except Exception as e:
            logger.error("GCP Functions Scanner live scan error: %s", e)
            self._progress(f"GCP Functions Scanner: Error — {e}")

    def _analyze_function(self, fn: dict, project_id: str, cf_client) -> FunctionDetail:
        full_name = fn.get("name", "")
        function_name = full_name.split("/")[-1] if full_name else ""
        location = full_name.split("/")[3] if full_name.count("/") >= 3 else "unknown"

        build_config = fn.get("buildConfig", {})
        runtime = build_config.get("runtime", "")

        service_config = fn.get("serviceConfig", {})
        service_account_email = service_config.get("serviceAccountEmail", "") or fn.get("serviceAccountEmail", "")
        uses_default_sa = service_account_email.endswith("-compute@developer.gserviceaccount.com")

        env_vars = service_config.get("environmentVariables", {})
        sensitive_env_vars = [k for k in env_vars if any(pat in k.upper() for pat in SENSITIVE_KEY_PATTERNS)]

        if fn.get("eventTrigger"):
            trigger_type = "event"
        elif fn.get("httpsTrigger") or service_config.get("uri"):
            trigger_type = "https"
        else:
            trigger_type = "unknown"

        allow_unauthenticated = False
        try:
            iam_resp = cf_client.projects().locations().functions().getIamPolicy(resource=full_name).execute()
            for binding in iam_resp.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    allow_unauthenticated = True
        except Exception:
            pass

        return FunctionDetail(
            function_name=function_name,
            full_name=full_name,
            project_id=project_id,
            runtime=runtime,
            state=fn.get("state", ""),
            trigger_type=trigger_type,
            allow_unauthenticated=allow_unauthenticated,
            sensitive_env_vars=sensitive_env_vars,
            uses_default_sa=uses_default_sa,
            region=location,
        )

    def _run_mock(self, report: GcpFunctionsScanReport):
        self._progress("GCP Functions Scanner: Running in mock mode...")

        mock_fn = FunctionDetail(
            function_name="process-upload", full_name="projects/mock-project/locations/us-central1/functions/process-upload",
            project_id="mock-project", runtime="python311", state="ACTIVE", trigger_type="https",
            allow_unauthenticated=True, sensitive_env_vars=["API_KEY"], uses_default_sa=True,
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_FUNCTION_CHECKS:
                finding = check(mock_fn)
                if finding:
                    mock_fn.findings.append(finding)

        report.functions = [mock_fn]
        report.project_findings = (
            _privesc_findings_for_project(
                "mock-project", ["cloudfunctions.functions.create", "iam.serviceAccounts.actAs"]
            ) if self.run_checks else []
        )
        report.projects_scanned = 1
        self._progress("GCP Functions Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_functions_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                            progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP Cloud Functions scan and return results as a dict."""
    scanner = GcpFunctionsScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
