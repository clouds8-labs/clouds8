"""
Clouds8 — CIS GCP Foundations Benchmark Runner (subset)
Implements a representative set of CIS GCP Foundation Benchmark v2.0 checks
across all 6 sections, matching the section breadth of clouds8's existing
OCI CIS runner (playbooks/cis_benchmark.py). Ported from
gcp-pentest-platform's backend/services/cspm/cis_checks.py - the GCP CIS
control catalog (title/description/rationale/severity/remediation) is
reused for the checks below; the full ~25-check engine and its BigQuery/GKE
sections are deferred to a future phase.

Sections:
  1. Identity & Access Management (IAM)
  3. Networking
  4. Compute (VM)
  5. Storage (GCS)
  6. Database (Cloud SQL)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class GcpCisCheckResult:
    check_id: str                # e.g. "GCP-CIS-1.4"
    title: str
    category: str                # e.g. "Identity & Access Management"
    severity: str                # critical, high, medium, low
    status: str                  # "PASS", "FAIL", "ERROR"
    affected_resources: List[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    cis_section: str = ""        # e.g. "1.4"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "affected_resources": self.affected_resources,
            "description": self.description,
            "remediation": self.remediation,
            "cis_section": self.cis_section,
        }


@dataclass
class GcpCisBenchmarkReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    results: List[GcpCisCheckResult] = field(default_factory=list)
    region: str = ""
    projects_scanned: int = 0

    @property
    def compliance_pct(self) -> float:
        evaluated = self.passed + self.failed
        if evaluated == 0:
            return 0.0
        return round(100.0 * self.passed / evaluated, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "compliance_pct": self.compliance_pct,
            "region": self.region,
            "projects_scanned": self.projects_scanned,
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# CIS Benchmark Runner
# ---------------------------------------------------------------------------
class GcpCisBenchmarkRunner:
    """Runs a representative subset of the CIS GCP Foundations Benchmark
    against a live GCP project set, via GCPCollector."""

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

    def run(self, compartment_ids: Optional[List[str]] = None) -> GcpCisBenchmarkReport:
        report = GcpCisBenchmarkReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_checks = len(report.results)
        report.passed = sum(1 for r in report.results if r.status == "PASS")
        report.failed = sum(1 for r in report.results if r.status == "FAIL")
        report.errors = sum(1 for r in report.results if r.status == "ERROR")
        return report

    def _run_live(self, report: GcpCisBenchmarkReport, compartment_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP CIS Benchmark: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]
            report.projects_scanned = len(active_projects)

            crm = self.collector.get_client("cloudresourcemanager")
            compute = self.collector.get_client("compute")
            storage = self.collector.get_client("storage")
            sqladmin = self.collector.get_client("sqladmin")

            results: List[GcpCisCheckResult] = []
            for proj in active_projects:
                project_id = proj["id"]
                self._progress(f"GCP CIS Benchmark: Checking project {project_id}...")
                results.extend(self._check_iam(crm, project_id))
                results.extend(self._check_networking(compute, project_id))
                results.extend(self._check_compute(compute, project_id))
                results.extend(self._check_storage(storage, project_id))
                results.extend(self._check_sql(sqladmin, project_id))

            report.results = results
            self._progress(f"GCP CIS Benchmark: {len(results)} checks evaluated. Complete!")

        except GCPAuthError:
            raise
        except Exception as e:
            logger.error("GCP CIS Benchmark live scan error: %s", e)
            self._progress(f"GCP CIS Benchmark: Error — {e}")

    # ── Section 1: IAM ────────────────────────────────────────────────────
    def _check_iam(self, crm, project_id: str) -> List[GcpCisCheckResult]:
        result = GcpCisCheckResult(
            check_id="GCP-CIS-1.4", cis_section="1.4", category="Identity & Access Management",
            title="Ensure that service accounts do not have admin-level roles",
            severity="HIGH", status="PASS",
            description="Service accounts should not be granted Owner/Editor/IAM-admin roles directly.",
            remediation="Remove roles/owner, roles/editor, or roles/iam.*Admin from service account principals; "
                        "grant least-privilege custom roles instead.",
        )
        try:
            policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
            admin_roles = {"roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/iam.admin"}
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                if role in admin_roles or "admin" in role.lower():
                    for member in binding.get("members", []):
                        if member.startswith("serviceAccount:"):
                            result.status = "FAIL"
                            result.affected_resources.append(f"{member} -> {role}")
        except Exception as e:
            result.status = "ERROR"
            result.description = f"Could not evaluate: {e}"
        return [result]

    # ── Section 3: Networking ─────────────────────────────────────────────
    def _check_networking(self, compute, project_id: str) -> List[GcpCisCheckResult]:
        result = GcpCisCheckResult(
            check_id="GCP-CIS-3.2", cis_section="3.2", category="Networking",
            title="Ensure that SSH access is restricted from the internet",
            severity="HIGH", status="PASS",
            description="No firewall rule should allow ingress on port 22 from 0.0.0.0/0.",
            remediation="Restrict SSH ingress firewall rules to known source ranges, or require IAP tunneling.",
        )
        try:
            resp = compute.firewalls().list(project=project_id).execute()
            for rule in resp.get("items", []):
                if rule.get("direction", "INGRESS") != "INGRESS" or rule.get("disabled"):
                    continue
                if "0.0.0.0/0" not in rule.get("sourceRanges", []):
                    continue
                for allowed in rule.get("allowed", []):
                    ports = allowed.get("ports", [])
                    if allowed.get("IPProtocol") in ("tcp", "all") and ("22" in ports or not ports):
                        result.status = "FAIL"
                        result.affected_resources.append(rule.get("name", ""))
        except Exception as e:
            result.status = "ERROR"
            result.description = f"Could not evaluate: {e}"
        return [result]

    # ── Section 4: Compute (VM) ───────────────────────────────────────────
    def _check_compute(self, compute, project_id: str) -> List[GcpCisCheckResult]:
        result = GcpCisCheckResult(
            check_id="GCP-CIS-4.2", cis_section="4.2", category="Compute",
            title="Ensure that Compute instances do not have public IP addresses",
            severity="MEDIUM", status="PASS",
            description="Instances with external IPs are directly reachable from the internet.",
            remediation="Remove external IPs; access instances via IAP, Cloud NAT, or a bastion host.",
        )
        try:
            resp = compute.instances().aggregatedList(project=project_id).execute()
            for zone_scope, scoped_list in resp.get("items", {}).items():
                for inst in scoped_list.get("instances", []):
                    has_external_ip = any(
                        ac.get("natIP")
                        for nic in inst.get("networkInterfaces", [])
                        for ac in nic.get("accessConfigs", [])
                    )
                    if has_external_ip:
                        result.status = "FAIL"
                        result.affected_resources.append(inst.get("name", ""))
        except Exception as e:
            result.status = "ERROR"
            result.description = f"Could not evaluate: {e}"
        return [result]

    # ── Section 5: Storage (GCS) ──────────────────────────────────────────
    def _check_storage(self, storage, project_id: str) -> List[GcpCisCheckResult]:
        result = GcpCisCheckResult(
            check_id="GCP-CIS-5.1", cis_section="5.1", category="Storage",
            title="Ensure Cloud Storage buckets are not anonymously or publicly accessible",
            severity="CRITICAL", status="PASS",
            description="No bucket should grant access to allUsers or allAuthenticatedUsers.",
            remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM policies.",
        )
        try:
            resp = storage.buckets().list(project=project_id).execute()
            for bucket in resp.get("items", []):
                name = bucket.get("name", "")
                try:
                    policy = storage.buckets().getIamPolicy(bucket=name).execute()
                    for binding in policy.get("bindings", []):
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            result.status = "FAIL"
                            result.affected_resources.append(name)
                except Exception:
                    pass
        except Exception as e:
            result.status = "ERROR"
            result.description = f"Could not evaluate: {e}"
        return [result]

    # ── Section 6: Database (Cloud SQL) ───────────────────────────────────
    def _check_sql(self, sqladmin, project_id: str) -> List[GcpCisCheckResult]:
        result = GcpCisCheckResult(
            check_id="GCP-CIS-6.1", cis_section="6.1", category="Database",
            title="Ensure Cloud SQL database instances do not have public IPs",
            severity="HIGH", status="PASS",
            description="Cloud SQL instances with public IPs are directly reachable from the internet.",
            remediation="Disable public IP; use Cloud SQL Auth Proxy or Private IP.",
        )
        try:
            resp = sqladmin.instances().list(project=project_id).execute()
            for inst in resp.get("items", []):
                if any(ip.get("type") == "PRIMARY" for ip in inst.get("ipAddresses", [])):
                    result.status = "FAIL"
                    result.affected_resources.append(inst.get("name", ""))
        except Exception as e:
            result.status = "ERROR"
            result.description = f"Could not evaluate: {e}"
        return [result]

    def _run_mock(self, report: GcpCisBenchmarkReport):
        self._progress("GCP CIS Benchmark: Running in mock mode...")
        report.results = [
            GcpCisCheckResult(
                check_id="GCP-CIS-1.4", cis_section="1.4", category="Identity & Access Management",
                title="Ensure that service accounts do not have admin-level roles",
                severity="HIGH", status="FAIL", affected_resources=["serviceAccount:ci@mock-project.iam.gserviceaccount.com -> roles/editor"],
                description="Service accounts should not be granted Owner/Editor/IAM-admin roles directly.",
                remediation="Remove roles/owner, roles/editor, or roles/iam.*Admin from service account principals.",
            ),
            GcpCisCheckResult(
                check_id="GCP-CIS-3.2", cis_section="3.2", category="Networking",
                title="Ensure that SSH access is restricted from the internet",
                severity="HIGH", status="FAIL", affected_resources=["allow-ssh-all"],
                description="No firewall rule should allow ingress on port 22 from 0.0.0.0/0.",
                remediation="Restrict SSH ingress firewall rules to known source ranges, or require IAP tunneling.",
            ),
            GcpCisCheckResult(
                check_id="GCP-CIS-4.2", cis_section="4.2", category="Compute",
                title="Ensure that Compute instances do not have public IP addresses",
                severity="MEDIUM", status="PASS",
                description="Instances with external IPs are directly reachable from the internet.",
                remediation="Remove external IPs; access instances via IAP, Cloud NAT, or a bastion host.",
            ),
            GcpCisCheckResult(
                check_id="GCP-CIS-5.1", cis_section="5.1", category="Storage",
                title="Ensure Cloud Storage buckets are not anonymously or publicly accessible",
                severity="CRITICAL", status="FAIL", affected_resources=["mock-public-bucket"],
                description="No bucket should grant access to allUsers or allAuthenticatedUsers.",
                remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM policies.",
            ),
            GcpCisCheckResult(
                check_id="GCP-CIS-6.1", cis_section="6.1", category="Database",
                title="Ensure Cloud SQL database instances do not have public IPs",
                severity="HIGH", status="PASS",
                description="Cloud SQL instances with public IPs are directly reachable from the internet.",
                remediation="Disable public IP; use Cloud SQL Auth Proxy or Private IP.",
            ),
        ]
        report.projects_scanned = 1
        self._progress("GCP CIS Benchmark: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_cis_scan(collector=None, compartment_ids=None, progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP CIS benchmark scan and return results as a dict."""
    runner = GcpCisBenchmarkRunner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = runner.run(compartment_ids=compartment_ids)
    return report.to_dict()
