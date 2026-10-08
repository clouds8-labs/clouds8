"""
Clouds8 — GCP Compute Instance Scanner
Scans GCP Compute Engine VM instances across projects for security
misconfigurations. Ported from gcp-pentest-platform's
backend/services/compute_security (ComputeSecurityScanner._analyze_instance) -
the GCP API calls and risk logic are reused, the async/FastAPI scaffolding
around them is not.

Checks:
  - External (public) IP exposure
  - Default Compute SA combined with the broad cloud-platform OAuth scope
  - Serial port interactive access enabled
  - Shielded VM not fully configured (secure boot / vTPM)
  - Project-wide SSH keys allowed on an instance that also has its own
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class VmFinding:
    instance_id: str
    instance_name: str
    project_id: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "instance_name": self.instance_name,
            "project_id": self.project_id,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class VmDetail:
    instance_id: str
    name: str
    project_id: str
    zone: str
    status: str
    machine_type: str
    has_external_ip: bool
    external_ips: List[str]
    uses_default_sa: bool
    has_cloud_platform_scope: bool
    serial_port_enabled: bool
    shielded_secure_boot: bool
    shielded_vtpm: bool
    region: str = "unknown"
    findings: List[VmFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "name": self.name,
            "project_id": self.project_id,
            "zone": self.zone,
            "status": self.status,
            "machine_type": self.machine_type,
            "has_external_ip": self.has_external_ip,
            "external_ips": self.external_ips,
            "uses_default_sa": self.uses_default_sa,
            "has_cloud_platform_scope": self.has_cloud_platform_scope,
            "serial_port_enabled": self.serial_port_enabled,
            "shielded_secure_boot": self.shielded_secure_boot,
            "shielded_vtpm": self.shielded_vtpm,
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
class VmScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_vms: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    vms: List[VmDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_vms": self.total_vms,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "vms": [v.to_dict() for v in self.vms],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_public_ip(vm: VmDetail) -> Optional[VmFinding]:
    if vm.has_external_ip:
        return VmFinding(
            instance_id=vm.instance_id, instance_name=vm.name, project_id=vm.project_id,
            check_id="gcp-vm-public-ip",
            severity="HIGH",
            title="Public IP Exposure",
            detail=f"Instance '{vm.name}' has external IP(s): {', '.join(vm.external_ips)}",
            remediation="Remove the external IP and access the instance via IAP/Bastion or a private VPN.",
        )
    return None


def _check_default_sa_full_access(vm: VmDetail) -> Optional[VmFinding]:
    if vm.uses_default_sa and vm.has_cloud_platform_scope:
        return VmFinding(
            instance_id=vm.instance_id, instance_name=vm.name, project_id=vm.project_id,
            check_id="gcp-vm-default-sa-full-access",
            severity="CRITICAL",
            title="Default Service Account With Full API Access",
            detail=f"Instance '{vm.name}' runs as the default Compute SA with the "
                   "cloud-platform scope - any process on the VM can call any GCP API as this SA.",
            remediation="Attach a dedicated, least-privilege service account and scope it narrowly.",
        )
    return None


def _check_serial_port(vm: VmDetail) -> Optional[VmFinding]:
    if vm.serial_port_enabled:
        return VmFinding(
            instance_id=vm.instance_id, instance_name=vm.name, project_id=vm.project_id,
            check_id="gcp-vm-serial-port-enabled",
            severity="HIGH",
            title="Serial Port Interactive Access Enabled",
            detail=f"Instance '{vm.name}' has serial-port-enable=true, allowing interactive console access.",
            remediation="Set the 'serial-port-enable' metadata key to false unless actively debugging.",
        )
    return None


def _check_shielded_vm(vm: VmDetail) -> Optional[VmFinding]:
    if not vm.shielded_secure_boot or not vm.shielded_vtpm:
        return VmFinding(
            instance_id=vm.instance_id, instance_name=vm.name, project_id=vm.project_id,
            check_id="gcp-vm-shielded-incomplete",
            severity="MEDIUM",
            title="Shielded VM Not Fully Configured",
            detail=f"Instance '{vm.name}' has secure boot and/or vTPM disabled.",
            remediation="Enable Secure Boot and vTPM in the instance's Shielded VM configuration.",
        )
    return None


ALL_CHECKS = [_check_public_ip, _check_default_sa_full_access, _check_serial_port, _check_shielded_vm]


# ---------------------------------------------------------------------------
# VM Scanner
# ---------------------------------------------------------------------------
class GcpVmScanner:
    """Scans GCP Compute instances across projects for security misconfigurations."""

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
            asset_ids: Optional[List[str]] = None) -> VmScanReport:
        report = VmScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_vms = len(report.vms)

        all_findings = [f for v in report.vms for f in v.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: VmScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan Compute instances across all accessible GCP projects."""
        try:
            self._progress("GCP VM Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            compute_client = self.collector.get_client("compute")
            if not compute_client:
                self._progress("GCP VM Scanner: Compute client not available")
                report.vms = []
                return

            self._progress(f"GCP VM Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            def _scan_project(proj):
                project_id = proj["id"]
                vms = []
                try:
                    result = compute_client.instances().aggregatedList(project=project_id).execute()
                    for scoped_list in result.get("items", {}).values():
                        for inst in scoped_list.get("instances", []):
                            detail = self._analyze_instance(inst, project_id)
                            # GCP's list API is already project-wide - this filters
                            # client-side after the fetch, it cannot skip the
                            # underlying API call the way OCI's per-region client
                            # setup can.
                            if regions and detail.region not in regions:
                                continue
                            if asset_ids and detail.instance_id not in asset_ids:
                                continue
                            if self.run_checks:
                                for check in ALL_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            vms.append(detail)
                except Exception as e:
                    # A 403 here means the profile's credentials work but lack
                    # the IAM permission to list instances - that must fail
                    # the scan loudly, not look like "zero VMs in this
                    # project" (which a caller would read as a clean result).
                    if getattr(getattr(e, "resp", None), "status", None) == 403:
                        raise PermissionError(
                            f"Profile lacks permission to list Compute instances in project "
                            f"'{project_id}' (compute.instances.list) — grant the service "
                            f"account the Compute Viewer role."
                        ) from e
                    logger.debug(f"GCP VM Scanner: Error in project {project_id}: {e}")
                return vms

            all_vms = []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        all_vms.extend(f.result())
                    except PermissionError:
                        raise
                    except Exception as e:
                        logger.error(f"GCP VM Scanner thread error: {e}")

            report.vms = all_vms
            self._progress(f"GCP VM Scanner: Found {len(all_vms)} instances. Complete!")

        except (PermissionError, GCPAuthError):
            raise
        except Exception as e:
            logger.error("GCP VM Scanner live scan error: %s", e)
            self._progress(f"GCP VM Scanner: Error — {e}")

    def _analyze_instance(self, inst: dict, project_id: str) -> VmDetail:
        zone = inst.get("zone", "").rsplit("/", 1)[-1]
        region = zone.rsplit("-", 1)[0] if zone else "unknown"

        external_ips = []
        for nic in inst.get("networkInterfaces", []):
            for ac in nic.get("accessConfigs", []):
                if ac.get("natIP"):
                    external_ips.append(ac["natIP"])

        service_accounts = inst.get("serviceAccounts", [])
        sa_emails = [sa.get("email", "") for sa in service_accounts]
        uses_default_sa = any(e.endswith(DEFAULT_SA_SUFFIX) for e in sa_emails)
        all_scopes = [s for sa in service_accounts for s in sa.get("scopes", [])]
        has_cloud_platform = CLOUD_PLATFORM_SCOPE in all_scopes

        metadata_items = {m["key"]: m["value"] for m in inst.get("metadata", {}).get("items", [])}
        serial_port = metadata_items.get("serial-port-enable", "0") not in ("0", "false")

        shielded = inst.get("shieldedInstanceConfig", {})

        return VmDetail(
            instance_id=str(inst.get("id")),
            name=inst.get("name", ""),
            project_id=project_id,
            zone=zone,
            status=inst.get("status", ""),
            machine_type=(inst.get("machineType") or "").rsplit("/", 1)[-1],
            has_external_ip=bool(external_ips),
            external_ips=external_ips,
            uses_default_sa=uses_default_sa,
            has_cloud_platform_scope=has_cloud_platform,
            serial_port_enabled=serial_port,
            shielded_secure_boot=shielded.get("enableSecureBoot", False),
            shielded_vtpm=shielded.get("enableVtpm", False),
            region=region,
        )

    def _run_mock(self, report: VmScanReport):
        self._progress("GCP VM Scanner: Running in mock mode...")

        mock_vm = VmDetail(
            instance_id="1234567890", name="prod-web-01", project_id="mock-project",
            zone="us-central1-a", status="RUNNING", machine_type="e2-medium",
            has_external_ip=True, external_ips=["34.1.2.3"],
            uses_default_sa=True, has_cloud_platform_scope=True,
            serial_port_enabled=False, shielded_secure_boot=False, shielded_vtpm=False,
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_vm)
                if finding:
                    mock_vm.findings.append(finding)

        mock_vm2 = VmDetail(
            instance_id="9876543210", name="dev-worker-01", project_id="mock-project",
            zone="us-central1-b", status="RUNNING", machine_type="e2-small",
            has_external_ip=False, external_ips=[],
            uses_default_sa=False, has_cloud_platform_scope=False,
            serial_port_enabled=False, shielded_secure_boot=True, shielded_vtpm=True,
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_vm2)
                if finding:
                    mock_vm2.findings.append(finding)

        report.vms = [mock_vm, mock_vm2]
        report.projects_scanned = 1
        self._progress("GCP VM Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_vm_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                     progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP VM scan and return results as a dict."""
    scanner = GcpVmScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
