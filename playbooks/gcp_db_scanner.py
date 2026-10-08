"""
Clouds8 — GCP Cloud SQL Scanner
Scans GCP Cloud SQL instances across projects for security
misconfigurations. Ported from gcp-pentest-platform's
backend/services/cloudsql/scanner.py (CloudSQLScanner._analyze_instance) -
the Cloud SQL API calls and risk logic are reused, the async/FastAPI
scaffolding is not.

Checks:
  - Public IP enabled
  - 0.0.0.0/0 in authorized networks
  - SSL/TLS not required
  - Automated backups disabled
  - Point-in-time recovery disabled
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class DbFinding:
    db_id: str
    db_name: str
    project_id: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "db_name": self.db_name,
            "project_id": self.project_id,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class CloudSqlDetail:
    db_id: str
    name: str
    project_id: str
    database_version: str
    state: str
    has_public_ip: bool
    has_public_auth_network: bool
    ssl_required: bool
    backup_enabled: bool
    pitr_enabled: bool
    region: str = "unknown"
    findings: List[DbFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "name": self.name,
            "project_id": self.project_id,
            "database_version": self.database_version,
            "state": self.state,
            "has_public_ip": self.has_public_ip,
            "has_public_auth_network": self.has_public_auth_network,
            "ssl_required": self.ssl_required,
            "backup_enabled": self.backup_enabled,
            "pitr_enabled": self.pitr_enabled,
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
class GcpDbScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_databases: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    databases: List[CloudSqlDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_databases": self.total_databases,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "databases": [d.to_dict() for d in self.databases],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_public_ip(db: CloudSqlDetail) -> Optional[DbFinding]:
    if db.has_public_ip:
        return DbFinding(
            db_id=db.db_id, db_name=db.name, project_id=db.project_id,
            check_id="gcp-db-public-ip",
            severity="CRITICAL",
            title="Public IP Enabled",
            detail=f"Cloud SQL instance '{db.name}' has a public IP - internet-accessible.",
            remediation="Disable the public IP and use Cloud SQL Auth Proxy or Private IP instead.",
        )
    return None


def _check_public_auth_network(db: CloudSqlDetail) -> Optional[DbFinding]:
    if db.has_public_auth_network:
        return DbFinding(
            db_id=db.db_id, db_name=db.name, project_id=db.project_id,
            check_id="gcp-db-open-authorized-network",
            severity="CRITICAL",
            title="Unrestricted Authorized Network (0.0.0.0/0)",
            detail=f"Cloud SQL instance '{db.name}' allows connections from any IP address.",
            remediation="Remove 0.0.0.0/0 from authorized networks; restrict to known CIDR ranges.",
        )
    return None


def _check_ssl_required(db: CloudSqlDetail) -> Optional[DbFinding]:
    if not db.ssl_required:
        return DbFinding(
            db_id=db.db_id, db_name=db.name, project_id=db.project_id,
            check_id="gcp-db-ssl-not-required",
            severity="HIGH",
            title="SSL/TLS Not Required",
            detail=f"Cloud SQL instance '{db.name}' allows unencrypted client connections.",
            remediation="Enable 'Require SSL/TLS' in the instance's connection settings.",
        )
    return None


def _check_backups(db: CloudSqlDetail) -> Optional[DbFinding]:
    if not db.backup_enabled:
        return DbFinding(
            db_id=db.db_id, db_name=db.name, project_id=db.project_id,
            check_id="gcp-db-no-backups",
            severity="HIGH",
            title="Automated Backups Disabled",
            detail=f"Cloud SQL instance '{db.name}' has automated backups disabled.",
            remediation="Enable automated backups in the instance's backup configuration.",
        )
    return None


def _check_pitr(db: CloudSqlDetail) -> Optional[DbFinding]:
    if not db.pitr_enabled:
        return DbFinding(
            db_id=db.db_id, db_name=db.name, project_id=db.project_id,
            check_id="gcp-db-no-pitr",
            severity="MEDIUM",
            title="Point-in-Time Recovery Disabled",
            detail=f"Cloud SQL instance '{db.name}' does not have point-in-time recovery enabled.",
            remediation="Enable point-in-time recovery for faster, more granular restores.",
        )
    return None


ALL_CHECKS = [_check_public_ip, _check_public_auth_network, _check_ssl_required,
              _check_backups, _check_pitr]


# ---------------------------------------------------------------------------
# Cloud SQL Scanner
# ---------------------------------------------------------------------------
class GcpDbScanner:
    """Scans GCP Cloud SQL instances across projects for security misconfigurations."""

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
            asset_ids: Optional[List[str]] = None) -> GcpDbScanReport:
        report = GcpDbScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
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

    def _run_live(self, report: GcpDbScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP DB Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            sql_client = self.collector.get_client("sqladmin")
            if not sql_client:
                self._progress("GCP DB Scanner: Cloud SQL client not available")
                report.databases = []
                return

            self._progress(f"GCP DB Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            def _scan_project(proj):
                project_id = proj["id"]
                dbs = []
                try:
                    resp = sql_client.instances().list(project=project_id).execute()
                    for inst in resp.get("items", []):
                        detail = self._analyze_instance(inst, project_id)
                        # GCP's list API is already project-wide - this filters
                        # client-side after the fetch, it cannot skip the
                        # underlying API call the way OCI's per-region client
                        # setup can.
                        if regions and detail.region not in regions:
                            continue
                        if asset_ids and detail.db_id not in asset_ids:
                            continue
                        if self.run_checks:
                            for check in ALL_CHECKS:
                                finding = check(detail)
                                if finding:
                                    detail.findings.append(finding)
                        dbs.append(detail)
                except Exception as e:
                    logger.debug(f"GCP DB Scanner: Error in project {project_id}: {e}")
                return dbs

            all_dbs = []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        all_dbs.extend(f.result())
                    except Exception as e:
                        logger.error(f"GCP DB Scanner thread error: {e}")

            report.databases = all_dbs
            self._progress(f"GCP DB Scanner: Found {len(all_dbs)} Cloud SQL instances. Complete!")

        except GCPAuthError:
            raise
        except Exception as e:
            logger.error("GCP DB Scanner live scan error: %s", e)
            self._progress(f"GCP DB Scanner: Error — {e}")

    def _analyze_instance(self, inst: dict, project_id: str) -> CloudSqlDetail:
        name = inst.get("name", "")
        settings = inst.get("settings", {})

        ip_addresses = inst.get("ipAddresses", [])
        has_public_ip = any(ip.get("type") == "PRIMARY" for ip in ip_addresses)

        ip_config = settings.get("ipConfiguration", {})
        ssl_required = ip_config.get("requireSsl", False)
        auth_networks = ip_config.get("authorizedNetworks", [])
        has_public_auth_network = any(
            n.get("value", "") in ("0.0.0.0/0", "::0/0", "::/0") for n in auth_networks
        )

        backup_config = settings.get("backupConfiguration", {})

        return CloudSqlDetail(
            db_id=name,
            name=name,
            project_id=project_id,
            database_version=inst.get("databaseVersion", ""),
            state=inst.get("state", ""),
            has_public_ip=has_public_ip,
            has_public_auth_network=has_public_auth_network,
            ssl_required=ssl_required,
            backup_enabled=backup_config.get("enabled", False),
            pitr_enabled=backup_config.get("pointInTimeRecoveryEnabled", False),
            region=inst.get("region", "unknown"),
        )

    def _run_mock(self, report: GcpDbScanReport):
        self._progress("GCP DB Scanner: Running in mock mode...")

        mock_db = CloudSqlDetail(
            db_id="prod-postgres", name="prod-postgres", project_id="mock-project",
            database_version="POSTGRES_15", state="RUNNABLE",
            has_public_ip=True, has_public_auth_network=True,
            ssl_required=False, backup_enabled=True, pitr_enabled=False,
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_db)
                if finding:
                    mock_db.findings.append(finding)

        mock_db2 = CloudSqlDetail(
            db_id="dev-mysql", name="dev-mysql", project_id="mock-project",
            database_version="MYSQL_8_0", state="RUNNABLE",
            has_public_ip=False, has_public_auth_network=False,
            ssl_required=True, backup_enabled=True, pitr_enabled=True,
            region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_db2)
                if finding:
                    mock_db2.findings.append(finding)

        report.databases = [mock_db, mock_db2]
        report.projects_scanned = 1
        self._progress("GCP DB Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_db_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                     progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP Cloud SQL scan and return results as a dict."""
    scanner = GcpDbScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
