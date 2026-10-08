"""
Clouds8 — GCP VPC Firewall Scanner
Scans VPC firewall rules for overly permissive internet-facing ingress.
Ported from gcp-pentest-platform's backend/services/firewall/__init__.py -
no OCI analogue in this codebase (OCI's security-list/NSG equivalent lives
inside playbooks/cis_benchmark.py as CIS checks, not a standalone scanner).
Unlike the other 3 ported GCP modules this session, the reference module has
no testIamPermissions/self-privilege component - firewall rules are a pure
resource-configuration surface, not a capability of the scanning credential.

Checks:
  - Rule allows ALL traffic (any protocol/port) from 0.0.0.0/0 or ::/0
  - Rule exposes a dangerous administrative port (SSH/RDP/Kubernetes API/
    Docker API) to the internet
  - Rule exposes another well-known dangerous port (DB ports, WinRM, Telnet,
    FTP) to the internet
  - Rule allows generic public ingress with no specific dangerous port match
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10

# Ported from gcp-pentest-platform's DANGEROUS_PORTS map.
CRITICAL_PORTS = {
    "22": "SSH", "3389": "RDP", "6443": "Kubernetes API",
    "2375": "Docker API (unencrypted)", "2376": "Docker API (TLS)",
}
OTHER_DANGEROUS_PORTS = {
    "5432": "PostgreSQL", "3306": "MySQL", "1433": "MSSQL",
    "5985": "WinRM HTTP", "5986": "WinRM HTTPS", "23": "Telnet", "21": "FTP",
}
DANGEROUS_PORTS = {**CRITICAL_PORTS, **OTHER_DANGEROUS_PORTS}
PUBLIC_SOURCE_RANGES = ("0.0.0.0/0", "::/0")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FirewallFinding:
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
class FirewallRuleDetail:
    rule_name: str
    project_id: str
    network: str
    direction: str
    disabled: bool
    is_public_ingress: bool
    has_all_traffic: bool
    dangerous_ports: List[str]  # ["22 (SSH)", ...]
    exposed_services: List[str]
    region: str = "global"
    findings: List[FirewallFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "project_id": self.project_id,
            "network": self.network,
            "direction": self.direction,
            "disabled": self.disabled,
            "is_public_ingress": self.is_public_ingress,
            "has_all_traffic": self.has_all_traffic,
            "dangerous_ports": self.dangerous_ports,
            "exposed_services": self.exposed_services,
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
class GcpFirewallScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_rules: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    rules: List[FirewallRuleDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_rules": self.total_rules,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "rules": [r.to_dict() for r in self.rules],
        }


# ---------------------------------------------------------------------------
# Per-rule checks
# ---------------------------------------------------------------------------
def _check_allow_all_traffic(r: FirewallRuleDetail) -> Optional[FirewallFinding]:
    if r.is_public_ingress and r.has_all_traffic:
        return FirewallFinding(
            resource_id=r.rule_name, resource_name=r.rule_name, project_id=r.project_id,
            check_id="gcp-firewall-allow-all-public",
            severity="CRITICAL",
            title="Firewall Rule Allows All Traffic From the Internet",
            detail=f"Rule '{r.rule_name}' allows all protocols/ports from {'/'.join(PUBLIC_SOURCE_RANGES)}.",
            remediation="Restrict this rule's source ranges to known CIDRs and scope allowed "
                        "protocols/ports to only what's required.",
        )
    return None


def _check_critical_port_exposed(r: FirewallRuleDetail) -> Optional[FirewallFinding]:
    if r.is_public_ingress and not r.has_all_traffic:
        critical = [p for p in r.dangerous_ports if any(name in p for name in CRITICAL_PORTS.values())]
        if critical:
            return FirewallFinding(
                resource_id=r.rule_name, resource_name=r.rule_name, project_id=r.project_id,
                check_id="gcp-firewall-critical-port-public",
                severity="CRITICAL",
                title="Administrative Port Exposed to the Internet",
                detail=f"Rule '{r.rule_name}' exposes {', '.join(critical)} to the internet.",
                remediation="Remove public access to administrative ports; use IAP TCP forwarding, "
                            "a bastion host, or a VPN instead.",
            )
    return None


def _check_other_dangerous_port_exposed(r: FirewallRuleDetail) -> Optional[FirewallFinding]:
    if r.is_public_ingress and not r.has_all_traffic:
        other = [p for p in r.dangerous_ports if not any(name in p for name in CRITICAL_PORTS.values())]
        if other:
            return FirewallFinding(
                resource_id=r.rule_name, resource_name=r.rule_name, project_id=r.project_id,
                check_id="gcp-firewall-dangerous-port-public",
                severity="HIGH",
                title="Dangerous Port Exposed to the Internet",
                detail=f"Rule '{r.rule_name}' exposes {', '.join(other)} to the internet.",
                remediation="Restrict this rule's source ranges; database/management ports should "
                            "never be reachable from 0.0.0.0/0.",
            )
    return None


def _check_generic_public_ingress(r: FirewallRuleDetail) -> Optional[FirewallFinding]:
    if r.is_public_ingress and not r.has_all_traffic and not r.dangerous_ports:
        return FirewallFinding(
            resource_id=r.rule_name, resource_name=r.rule_name, project_id=r.project_id,
            check_id="gcp-firewall-public-ingress",
            severity="MEDIUM",
            title="Public Ingress Rule",
            detail=f"Rule '{r.rule_name}' allows public ingress: {', '.join(r.exposed_services[:5])}.",
            remediation="Confirm this exposure is intentional; scope source ranges as narrowly as possible.",
        )
    return None


ALL_FIREWALL_CHECKS = [
    _check_allow_all_traffic, _check_critical_port_exposed,
    _check_other_dangerous_port_exposed, _check_generic_public_ingress,
]


# ---------------------------------------------------------------------------
# Firewall Scanner
# ---------------------------------------------------------------------------
class GcpFirewallScanner:
    """Scans VPC firewall rules across projects."""

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
            asset_ids: Optional[List[str]] = None) -> GcpFirewallScanReport:
        report = GcpFirewallScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_rules = len(report.rules)

        all_findings = [f for r in report.rules for f in r.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: GcpFirewallScanReport, compartment_ids: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP Firewall Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            compute_client = self.collector.get_client("compute")
            if not compute_client:
                self._progress("GCP Firewall Scanner: Compute client not available")
                return

            self._progress(f"GCP Firewall Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            def _scan_project(proj):
                project_id = proj["id"]
                rules = []
                try:
                    result = compute_client.firewalls().list(project=project_id).execute()
                    for fw in result.get("items", []):
                        detail = self._analyze_rule(fw, project_id)
                        if asset_ids and detail.rule_name not in asset_ids:
                            continue
                        if self.run_checks:
                            for check in ALL_FIREWALL_CHECKS:
                                finding = check(detail)
                                if finding:
                                    detail.findings.append(finding)
                        rules.append(detail)
                except Exception as e:
                    if getattr(getattr(e, "resp", None), "status", None) == 403:
                        raise PermissionError(
                            f"Profile lacks permission to list firewall rules in project "
                            f"'{project_id}' (compute.firewalls.list) — grant the service "
                            f"account the Compute Network Viewer role."
                        ) from e
                    logger.debug(f"GCP Firewall Scanner: Error in project {project_id}: {e}")
                return rules

            all_rules = []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        all_rules.extend(f.result())
                    except PermissionError:
                        raise
                    except Exception as e:
                        logger.error(f"GCP Firewall Scanner thread error: {e}")

            report.rules = all_rules
            self._progress(f"GCP Firewall Scanner: Found {len(all_rules)} rules. Complete!")

        except (PermissionError, GCPAuthError):
            raise
        except Exception as e:
            logger.error("GCP Firewall Scanner live scan error: %s", e)
            self._progress(f"GCP Firewall Scanner: Error — {e}")

    def _analyze_rule(self, fw: dict, project_id: str) -> FirewallRuleDetail:
        name = fw.get("name", "")
        network = fw.get("network", "").split("/")[-1]
        direction = fw.get("direction", "INGRESS")
        disabled = fw.get("disabled", False)

        source_ranges = fw.get("sourceRanges", [])
        allowed = fw.get("allowed", [])
        is_allow = bool(allowed)
        is_public_source = any(r in PUBLIC_SOURCE_RANGES for r in source_ranges)
        is_public_ingress = direction == "INGRESS" and is_public_source and is_allow and not disabled

        exposed_services = []
        has_all_traffic = False
        dangerous_ports = []

        for rule in allowed:
            proto = rule.get("IPProtocol", "")
            ports = rule.get("ports", [])

            if proto == "all" or (proto in ("tcp", "udp") and not ports):
                has_all_traffic = True
                exposed_services.append(f"{proto}:ALL")
                continue

            for port in ports:
                port_str = str(port)
                if "-" in port_str:
                    exposed_services.append(f"{proto}:{port_str}")
                    lo, hi = port_str.split("-", 1)
                    try:
                        lo_i, hi_i = int(lo), int(hi)
                        for dp, dp_name in DANGEROUS_PORTS.items():
                            if lo_i <= int(dp) <= hi_i:
                                dangerous_ports.append(f"{proto}/{dp} ({dp_name})")
                    except ValueError:
                        pass
                else:
                    svc_name = DANGEROUS_PORTS.get(port_str, "")
                    label = f"{proto}/{port_str}" + (f" ({svc_name})" if svc_name else "")
                    exposed_services.append(label)
                    if svc_name:
                        dangerous_ports.append(label)

        return FirewallRuleDetail(
            rule_name=name,
            project_id=project_id,
            network=network,
            direction=direction,
            disabled=disabled,
            is_public_ingress=is_public_ingress,
            has_all_traffic=has_all_traffic,
            dangerous_ports=list(set(dangerous_ports)),
            exposed_services=exposed_services,
        )

    def _run_mock(self, report: GcpFirewallScanReport):
        self._progress("GCP Firewall Scanner: Running in mock mode...")

        mock_rule = FirewallRuleDetail(
            rule_name="allow-ssh-all", project_id="mock-project", network="default",
            direction="INGRESS", disabled=False, is_public_ingress=True, has_all_traffic=False,
            dangerous_ports=["tcp/22 (SSH)"], exposed_services=["tcp/22 (SSH)"],
        )
        if self.run_checks:
            for check in ALL_FIREWALL_CHECKS:
                finding = check(mock_rule)
                if finding:
                    mock_rule.findings.append(finding)

        report.rules = [mock_rule]
        report.projects_scanned = 1
        self._progress("GCP Firewall Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_firewall_scan(collector=None, compartment_ids=None, asset_ids=None,
                           progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP VPC firewall scan and return results as a dict."""
    scanner = GcpFirewallScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, asset_ids=asset_ids)
    return report.to_dict()
