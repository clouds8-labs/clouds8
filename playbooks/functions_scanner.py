"""
Clouds8 — Functions (Serverless) Scanner
Scans OCI Functions applications and their functions across compartments
for security and hygiene issues.

Checks:
  - Application with no configured subnets (unreachable/misconfigured)
  - Image signature verification (image policy) disabled
  - Per-function tracing disabled (observability gap)
  - Hardcoded secrets in a function's environment variable config

Uses ThreadPoolExecutor for parallel compartment scanning.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from playbooks.secret_scanner import CONTENT_PATTERNS

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10

# Env var key names that look secret-ish regardless of their value.
_SECRET_KEY_PATTERN = re.compile(r"secret|password|token|key|credential", re.IGNORECASE)


def _env_var_secret_matches(config: Dict[str, str]) -> List[str]:
    """Return the list of env var key names in `config` that look like they
    hold a secret — either the key name itself is secret-ish, or the value
    matches one of secret_scanner's content-detection regexes. Values are
    never returned/retained, only key names, so secrets never get persisted
    into the findings DB."""
    matched_keys = []
    for key, value in (config or {}).items():
        if _SECRET_KEY_PATTERN.search(key):
            matched_keys.append(key)
            continue
        value_str = str(value) if value is not None else ""
        if any(pattern.search(value_str) for pattern, _label, _severity in CONTENT_PATTERNS):
            matched_keys.append(key)
    return matched_keys


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FunctionsFinding:
    """A single security finding for a Functions application or function.
    `resource_id` holds either the application's or a function's OCID,
    depending on which check fired."""
    resource_id: str
    resource_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class ApplicationDetail:
    """Enriched details for a Functions application."""
    application_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    subnet_count: int
    network_security_group_count: int
    image_policy_enabled: Optional[bool]
    function_count: int
    time_created: str
    region: str = "unknown"
    findings: List[FunctionsFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "application_id": self.application_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "subnet_count": self.subnet_count,
            "network_security_group_count": self.network_security_group_count,
            "image_policy_enabled": self.image_policy_enabled,
            "function_count": self.function_count,
            "time_created": self.time_created,
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
class FunctionsScanReport:
    """Full Functions scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_applications: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    compartments_scanned: int = 0
    region: str = ""
    applications: List[ApplicationDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_applications": self.total_applications,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "applications": [a.to_dict() for a in self.applications],
        }


# ---------------------------------------------------------------------------
# Application-level checks
# ---------------------------------------------------------------------------
def _check_no_subnets(a: ApplicationDetail) -> Optional[FunctionsFinding]:
    """Flag active applications with no configured subnets."""
    if a.lifecycle_state == "ACTIVE" and a.subnet_count == 0:
        return FunctionsFinding(
            resource_id=a.application_id, resource_name=a.display_name,
            compartment_name=a.compartment_name,
            check_id="functions-no-subnets",
            severity="MEDIUM",
            title="Application Has No Subnets",
            detail=f"Application '{a.display_name}' has no subnets configured.",
            remediation="Assign at least one subnet so the application's functions can be invoked.",
        )
    return None


def _check_image_policy_disabled(a: ApplicationDetail) -> Optional[FunctionsFinding]:
    """Flag applications with no image signature verification policy enforced."""
    if not a.image_policy_enabled:
        return FunctionsFinding(
            resource_id=a.application_id, resource_name=a.display_name,
            compartment_name=a.compartment_name,
            check_id="functions-image-policy-disabled",
            severity="MEDIUM",
            title="Image Signature Verification Disabled",
            detail=f"Application '{a.display_name}' does not enforce an image signing policy — "
                   "unsigned or untrusted function images can be deployed.",
            remediation="Enable an image policy requiring signature verification against a trusted key.",
        )
    return None


APPLICATION_CHECKS = [_check_no_subnets, _check_image_policy_disabled]


# ---------------------------------------------------------------------------
# Functions Scanner
# ---------------------------------------------------------------------------
class FunctionsScanner:
    """Scans OCI Functions applications across compartments for security and hygiene issues."""

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
            asset_ids: Optional[List[str]] = None) -> FunctionsScanReport:
        report = FunctionsScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_applications = len(report.applications)

        all_findings = [f for a in report.applications for f in a.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: FunctionsScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan Functions applications across all subscribed regions."""
        try:
            import oci

            self._progress("Functions Scanner: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-phoenix-1")]
            if regions:
                subscribed_regions = [r for r in subscribed_regions if r in regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_comps = [c for c in self.collector.compartments if c.get("lifecycle_state") == "ACTIVE"]
            if compartment_ids:
                active_comps = [c for c in active_comps if c["id"] in compartment_ids]

            report.compartments_scanned = len(active_comps)

            all_apps = []

            for region in subscribed_regions:
                self._progress(f"Functions Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                fn_client = self.collector.get_client("functions_management")
                if not fn_client:
                    self._progress(f"Functions Scanner: Functions client not available in {region}")
                    continue

                self._progress(f"Functions Scanner [{region}]: Scanning {len(active_comps)} compartments ({_MAX_WORKERS} threads)...")

                def _scan_compartment(comp):
                    cid, cname = comp["id"], comp["name"]
                    apps = []
                    try:
                        app_list = oci.pagination.list_call_get_all_results(
                            fn_client.list_applications, cid
                        ).data
                        for app in app_list:
                            if app.lifecycle_state in ("DELETED", "DELETING"):
                                continue

                            image_policy_config = getattr(app, "image_policy_config", None)

                            functions = []
                            try:
                                functions = [
                                    fn for fn in oci.pagination.list_call_get_all_results(
                                        fn_client.list_functions, app.id
                                    ).data
                                    if fn.lifecycle_state not in ("DELETED", "DELETING")
                                ]
                            except Exception as e:
                                logger.debug(f"Functions Scanner: could not list functions for app {app.display_name}: {e}")

                            detail = ApplicationDetail(
                                application_id=app.id,
                                display_name=app.display_name,
                                compartment_name=cname,
                                compartment_id=cid,
                                lifecycle_state=app.lifecycle_state,
                                subnet_count=len(getattr(app, "subnet_ids", None) or []),
                                network_security_group_count=len(getattr(app, "network_security_group_ids", None) or []),
                                image_policy_enabled=getattr(image_policy_config, "is_policy_enabled", None) if image_policy_config else None,
                                function_count=len(functions),
                                time_created=str(getattr(app, "time_created", "")),
                                region=region,
                            )
                            if self.run_checks:
                                for check in APPLICATION_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)

                                # Per-function checks: trace_config + env-var secrets.
                                for fn in functions:
                                    fn_trace = getattr(fn, "trace_config", None)
                                    if getattr(fn_trace, "is_enabled", None) is False:
                                        detail.findings.append(FunctionsFinding(
                                            resource_id=fn.id, resource_name=fn.display_name,
                                            compartment_name=cname,
                                            check_id="functions-trace-disabled",
                                            severity="LOW",
                                            title="Function Tracing Disabled",
                                            detail=f"Function '{fn.display_name}' has tracing disabled, "
                                                   "reducing observability into invocations.",
                                            remediation="Enable tracing on the function for better observability.",
                                        ))

                                    try:
                                        full_fn = fn_client.get_function(fn.id).data
                                        matched_keys = _env_var_secret_matches(getattr(full_fn, "config", None))
                                        if matched_keys:
                                            detail.findings.append(FunctionsFinding(
                                                resource_id=fn.id, resource_name=fn.display_name,
                                                compartment_name=cname,
                                                check_id="functions-secret-in-env",
                                                severity="CRITICAL",
                                                title="Possible Secret in Environment Variables",
                                                detail=f"Function '{fn.display_name}' has environment "
                                                       f"variable(s) that look like secrets: {', '.join(matched_keys)}.",
                                                remediation="Move secrets out of function config into OCI Vault "
                                                            "and reference them at runtime instead.",
                                            ))
                                    except Exception as e:
                                        logger.debug(f"Functions Scanner: could not get function config for {fn.display_name}: {e}")

                            apps.append(detail)
                    except Exception as e:
                        logger.debug(f"Functions Scanner: Error in compartment {cname} ({region}): {e}")
                    return apps

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_compartment, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_apps.extend(f.result())
                        except Exception as e:
                            logger.error(f"Functions Scanner thread error ({region}): {e}")

            if asset_ids:
                all_apps = [a for a in all_apps if a.application_id in asset_ids]
            report.applications = all_apps

            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"Functions Scanner: Found {len(all_apps)} applications. Complete!")

        except Exception as e:
            logger.error("Functions Scanner live scan error: %s", e)
            self._progress(f"Functions Scanner: Error — {e}")

    def _run_mock(self, report: FunctionsScanReport):
        self._progress("Functions Scanner: Running in mock mode...")

        clean_app = ApplicationDetail(
            application_id="ocid1.fnapp.oc1..mock1",
            display_name="prod-image-resizer",
            compartment_name="Production",
            compartment_id="ocid1.compartment.oc1..prod",
            lifecycle_state="ACTIVE",
            subnet_count=1,
            network_security_group_count=1,
            image_policy_enabled=True,
            function_count=1,
            time_created="2025-03-01T00:00:00Z",
        )
        if self.run_checks:
            for check in APPLICATION_CHECKS:
                finding = check(clean_app)
                if finding:
                    clean_app.findings.append(finding)

        risky_app = ApplicationDetail(
            application_id="ocid1.fnapp.oc1..mock2",
            display_name="dev-webhook-handler",
            compartment_name="Development",
            compartment_id="ocid1.compartment.oc1..dev",
            lifecycle_state="ACTIVE",
            subnet_count=0,
            network_security_group_count=0,
            image_policy_enabled=False,
            function_count=1,
            time_created="2024-07-10T00:00:00Z",
        )
        if self.run_checks:
            for check in APPLICATION_CHECKS:
                finding = check(risky_app)
                if finding:
                    risky_app.findings.append(finding)
            risky_app.findings.append(FunctionsFinding(
                resource_id="ocid1.fnfunc.oc1..mock1", resource_name="webhook-handler-fn",
                compartment_name="Development",
                check_id="functions-trace-disabled",
                severity="LOW",
                title="Function Tracing Disabled",
                detail="Function 'webhook-handler-fn' has tracing disabled, reducing observability into invocations.",
                remediation="Enable tracing on the function for better observability.",
            ))
            matched_keys = _env_var_secret_matches({
                "DB_PASSWORD": "Sup3rSecret!23",
                "STRIPE_API_KEY": "sk_live_abc123def456",
            })
            risky_app.findings.append(FunctionsFinding(
                resource_id="ocid1.fnfunc.oc1..mock1", resource_name="webhook-handler-fn",
                compartment_name="Development",
                check_id="functions-secret-in-env",
                severity="CRITICAL",
                title="Possible Secret in Environment Variables",
                detail=f"Function 'webhook-handler-fn' has environment variable(s) that look like "
                       f"secrets: {', '.join(matched_keys)}.",
                remediation="Move secrets out of function config into OCI Vault and reference them at runtime instead.",
            ))

        report.applications = [clean_app, risky_app]
        report.compartments_scanned = 2
        self._progress("Functions Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_functions_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                        progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run Functions scan and return results as a dict."""
    scanner = FunctionsScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
