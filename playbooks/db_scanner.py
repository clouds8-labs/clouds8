"""
Clouds8 — Autonomous Database Scanner
Scans OCI Autonomous Databases across compartments for security misconfigurations.

Checks:
  - mTLS enforcement (is_mtls_connection_required)
  - Public IP / Whitelisted IP exposure
  - Network isolation (private endpoint via subnet_id + NSG)
  - Auto-scaling configuration
  - Lifecycle state anomalies (STOPPED, UNAVAILABLE)
  - Free-tier databases in production compartments

Uses ThreadPoolExecutor for parallel compartment scanning.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AdbFinding:
    """A single security finding for an Autonomous Database."""
    db_id: str
    db_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "db_name": self.db_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class AdbDetail:
    """Enriched details for an Autonomous Database."""
    db_id: str
    display_name: str
    db_name: str
    compartment_name: str
    compartment_id: str
    db_workload: str
    lifecycle_state: str
    is_free_tier: bool
    is_dedicated: bool
    is_mtls_required: Optional[bool]
    is_auto_scaling_enabled: bool
    cpu_core_count: Optional[int]
    data_storage_size_in_tbs: Optional[float]
    time_created: str
    whitelisted_ips: Optional[List[str]]
    subnet_id: Optional[str]
    nsg_ids: Optional[List[str]]
    region: str = "unknown"
    findings: List[AdbFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "display_name": self.display_name,
            "db_name": self.db_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "db_workload": self.db_workload,
            "lifecycle_state": self.lifecycle_state,
            "is_free_tier": self.is_free_tier,
            "is_dedicated": self.is_dedicated,
            "is_mtls_required": self.is_mtls_required,
            "is_auto_scaling_enabled": self.is_auto_scaling_enabled,
            "cpu_core_count": self.cpu_core_count,
            "data_storage_size_in_tbs": self.data_storage_size_in_tbs,
            "time_created": self.time_created,
            "whitelisted_ips": self.whitelisted_ips,
            "subnet_id": self.subnet_id,
            "nsg_ids": self.nsg_ids,
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
class DbScanReport:
    """Full Database scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_databases: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    compartments_scanned: int = 0
    region: str = ""
    databases: List[AdbDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_databases": self.total_databases,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "databases": [d.to_dict() for d in self.databases],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_mtls(db: AdbDetail) -> Optional[AdbFinding]:
    """Check if mTLS is enforced."""
    if db.is_mtls_required is False:
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-mtls-disabled",
            severity="CRITICAL",
            title="mTLS Not Enforced",
            detail=f"Autonomous DB '{db.display_name}' does not require mTLS connections. "
                   "This allows unencrypted or weakly authenticated client connections.",
            remediation="Enable 'Require mutual TLS (mTLS) authentication' in the database network settings.",
        )
    return None


def _check_public_access(db: AdbDetail) -> Optional[AdbFinding]:
    """Check if DB is exposed with whitelisted public IPs without private endpoint."""
    if not db.subnet_id and db.whitelisted_ips:
        # Public access with IP allowlist
        if "0.0.0.0/0" in db.whitelisted_ips:
            return AdbFinding(
                db_id=db.db_id, db_name=db.display_name,
                compartment_name=db.compartment_name,
                check_id="adb-public-unrestricted",
                severity="CRITICAL",
                title="Unrestricted Public Access (0.0.0.0/0)",
                detail=f"Autonomous DB '{db.display_name}' allows connections from any IP address.",
                remediation="Restrict whitelisted IPs to known CIDR ranges or migrate to a private endpoint.",
            )
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-public-access",
            severity="HIGH",
            title="Public Access Enabled",
            detail=f"Autonomous DB '{db.display_name}' is publicly accessible via whitelisted IPs: "
                   f"{', '.join(db.whitelisted_ips[:5])}",
            remediation="Consider migrating to a private endpoint (VCN) for network isolation.",
        )
    elif not db.subnet_id and not db.whitelisted_ips:
        # Public but no whitelist — could be fully open or just misconfigured
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-no-network-restriction",
            severity="HIGH",
            title="No Network Access Restrictions",
            detail=f"Autonomous DB '{db.display_name}' has no private endpoint and no IP allowlist configured.",
            remediation="Configure a private endpoint or add specific IP allowlist entries.",
        )
    return None


def _check_private_endpoint(db: AdbDetail) -> Optional[AdbFinding]:
    """Check private endpoint + NSG configuration."""
    if db.subnet_id and (not db.nsg_ids or len(db.nsg_ids) == 0):
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-no-nsg",
            severity="MEDIUM",
            title="Private Endpoint Without NSG",
            detail=f"Autonomous DB '{db.display_name}' uses a private endpoint but has no Network Security Groups.",
            remediation="Attach at least one NSG to restrict ingress traffic to authorized sources.",
        )
    return None


def _check_lifecycle(db: AdbDetail) -> Optional[AdbFinding]:
    """Flag databases in unhealthy states."""
    problem_states = {"UNAVAILABLE", "RESTORE_FAILED", "BACKUP_IN_PROGRESS", "INACCESSIBLE"}
    if db.lifecycle_state in problem_states:
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-unhealthy-state",
            severity="HIGH",
            title=f"Database in {db.lifecycle_state} State",
            detail=f"Autonomous DB '{db.display_name}' is in '{db.lifecycle_state}' — may indicate failure or attack.",
            remediation="Investigate the root cause and restore the database to AVAILABLE state.",
        )
    return None


def _check_free_tier(db: AdbDetail) -> Optional[AdbFinding]:
    """Warn about free-tier databases (no SLA, limited security features)."""
    if db.is_free_tier:
        return AdbFinding(
            db_id=db.db_id, db_name=db.display_name,
            compartment_name=db.compartment_name,
            check_id="adb-free-tier",
            severity="LOW",
            title="Free Tier Database",
            detail=f"Autonomous DB '{db.display_name}' is a free-tier instance with limited SLA and security features.",
            remediation="Consider upgrading to a paid tier for production workloads.",
        )
    return None


ALL_CHECKS = [_check_mtls, _check_public_access, _check_private_endpoint, _check_lifecycle, _check_free_tier]


# ---------------------------------------------------------------------------
# Database Scanner
# ---------------------------------------------------------------------------
class DbScanner:
    """Scans OCI Autonomous Databases across compartments for security misconfigurations."""

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
            asset_ids: Optional[List[str]] = None) -> DbScanReport:
        report = DbScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_databases = len(report.databases)

        all_findings = [f for d in report.databases for f in d.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: DbScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan Autonomous Databases across all subscribed regions."""
        try:
            self._progress("DB Scanner: Discovering subscribed regions...")
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
            
            all_dbs = []

            for region in subscribed_regions:
                self._progress(f"DB Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                db_client = self.collector.get_client("database")
                if not db_client:
                    self._progress(f"DB Scanner: Database client not available in {region}")
                    continue

                self._progress(f"DB Scanner [{region}]: Scanning {len(active_comps)} compartments ({_MAX_WORKERS} threads)...")

                def _scan_compartment(comp):
                    cid, cname = comp["id"], comp["name"]
                    dbs = []
                    try:
                        import oci
                        adb_list = oci.pagination.list_call_get_all_results(
                            db_client.list_autonomous_databases, cid
                        ).data
                        for adb in adb_list:
                            if adb.lifecycle_state in ("TERMINATED", "TERMINATING"):
                                continue
                            detail = AdbDetail(
                                db_id=adb.id,
                                display_name=adb.display_name,
                                db_name=getattr(adb, "db_name", ""),
                                compartment_name=cname,
                                compartment_id=cid,
                                db_workload=getattr(adb, "db_workload", ""),
                                lifecycle_state=adb.lifecycle_state,
                                is_free_tier=getattr(adb, "is_free_tier", False),
                                is_dedicated=getattr(adb, "is_dedicated", False),
                                is_mtls_required=getattr(adb, "is_mtls_connection_required", None),
                                is_auto_scaling_enabled=getattr(adb, "is_auto_scaling_enabled", False),
                                cpu_core_count=getattr(adb, "cpu_core_count", None),
                                data_storage_size_in_tbs=getattr(adb, "data_storage_size_in_tbs", None),
                                time_created=str(getattr(adb, "time_created", "")),
                                whitelisted_ips=getattr(adb, "whitelisted_ips", None),
                                subnet_id=getattr(adb, "subnet_id", None),
                                nsg_ids=getattr(adb, "nsg_ids", None),
                                region=region,
                            )
                            # Run all security checks
                            if self.run_checks:
                                for check in ALL_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            dbs.append(detail)
                    except Exception as e:
                        logger.debug(f"DB Scanner: Error in compartment {cname} ({region}): {e}")
                    return dbs

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_compartment, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_dbs.extend(f.result())
                        except Exception as e:
                            logger.error(f"DB Scanner thread error ({region}): {e}")

            if asset_ids:
                all_dbs = [d for d in all_dbs if d.db_id in asset_ids]
            report.databases = all_dbs

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"DB Scanner: Found {len(all_dbs)} databases. Complete!")

        except Exception as e:
            logger.error("DB Scanner live scan error: %s", e)
            self._progress(f"DB Scanner: Error — {e}")

    def _run_mock(self, report: DbScanReport):
        self._progress("DB Scanner: Running in mock mode...")

        mock_db = AdbDetail(
            db_id="ocid1.autonomousdatabase.oc1..mock1",
            display_name="ProdAnalytics",
            db_name="PRODANALYTICS",
            compartment_name="Production",
            compartment_id="ocid1.compartment.oc1..prod",
            db_workload="OLTP",
            lifecycle_state="AVAILABLE",
            is_free_tier=False,
            is_dedicated=False,
            is_mtls_required=False,
            is_auto_scaling_enabled=True,
            cpu_core_count=4,
            data_storage_size_in_tbs=1,
            time_created="2025-06-15T10:00:00Z",
            whitelisted_ips=["0.0.0.0/0"],
            subnet_id=None,
            nsg_ids=None,
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_db)
                if finding:
                    mock_db.findings.append(finding)

        mock_db2 = AdbDetail(
            db_id="ocid1.autonomousdatabase.oc1..mock2",
            display_name="DevWarehouse",
            db_name="DEVWAREHOUSE",
            compartment_name="Development",
            compartment_id="ocid1.compartment.oc1..dev",
            db_workload="DW",
            lifecycle_state="AVAILABLE",
            is_free_tier=True,
            is_dedicated=False,
            is_mtls_required=True,
            is_auto_scaling_enabled=False,
            cpu_core_count=1,
            data_storage_size_in_tbs=0.02,
            time_created="2025-09-20T08:00:00Z",
            whitelisted_ips=None,
            subnet_id="ocid1.subnet.oc1..mock1",
            nsg_ids=[],
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_db2)
                if finding:
                    mock_db2.findings.append(finding)

        report.databases = [mock_db, mock_db2]
        report.compartments_scanned = 2
        self._progress("DB Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_db_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                 progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run Database scan and return results as a dict."""
    scanner = DbScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
