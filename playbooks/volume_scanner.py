"""
Clouds8 — Block Volume Scanner
Scans OCI Block Volumes across compartments for security and hygiene issues.

Checks:
  - Encryption with a customer-managed (Vault) key vs. Oracle-managed default
  - Unattached volumes (stale, unmonitored, may retain sensitive data)
  - Missing backup policy assignment (data-loss risk)
  - Faulty lifecycle state

Uses ThreadPoolExecutor for parallel compartment scanning. Scoped to block
volumes only (not boot volumes) — boot volume posture is covered indirectly
via the VM scanner's instance-level checks.
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
class VolumeFinding:
    """A single security finding for a Block Volume."""
    volume_id: str
    volume_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "volume_id": self.volume_id,
            "volume_name": self.volume_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class VolumeDetail:
    """Enriched details for a Block Volume."""
    volume_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    availability_domain: str
    lifecycle_state: str
    size_in_gbs: Optional[int]
    vpus_per_gb: Optional[int]
    kms_key_id: Optional[str]
    is_hydrated: Optional[bool]
    is_attached: bool
    has_backup_policy: bool
    time_created: str
    region: str = "unknown"
    findings: List[VolumeFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "volume_id": self.volume_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "lifecycle_state": self.lifecycle_state,
            "size_in_gbs": self.size_in_gbs,
            "vpus_per_gb": self.vpus_per_gb,
            "kms_key_id": self.kms_key_id,
            "is_hydrated": self.is_hydrated,
            "is_attached": self.is_attached,
            "has_backup_policy": self.has_backup_policy,
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
class VolumeScanReport:
    """Full Block Volume scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_volumes: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    unattached_volumes: int = 0
    unencrypted_volumes: int = 0
    compartments_scanned: int = 0
    region: str = ""
    volumes: List[VolumeDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_volumes": self.total_volumes,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "unattached_volumes": self.unattached_volumes,
            "unencrypted_volumes": self.unencrypted_volumes,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "volumes": [v.to_dict() for v in self.volumes],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_kms_encryption(v: VolumeDetail) -> Optional[VolumeFinding]:
    """Flag volumes relying on Oracle-managed (not customer-managed) encryption keys."""
    if not v.kms_key_id:
        return VolumeFinding(
            volume_id=v.volume_id, volume_name=v.display_name,
            compartment_name=v.compartment_name,
            check_id="volume-no-kms",
            severity="LOW",
            title="No Customer-Managed Encryption Key",
            detail=f"Volume '{v.display_name}' uses Oracle-managed encryption instead of a Vault-managed key.",
            remediation="Assign a customer-managed Vault key for centralized key rotation and audit control.",
        )
    return None


def _check_unattached(v: VolumeDetail) -> Optional[VolumeFinding]:
    """Flag volumes not attached to any compute instance."""
    if not v.is_attached and v.lifecycle_state == "AVAILABLE":
        return VolumeFinding(
            volume_id=v.volume_id, volume_name=v.display_name,
            compartment_name=v.compartment_name,
            check_id="volume-unattached",
            severity="MEDIUM",
            title="Unattached Volume",
            detail=f"Volume '{v.display_name}' is not attached to any instance — may hold stale, "
                   "unmonitored data and represents unnecessary attack surface.",
            remediation="Attach to an instance, back up and delete, or archive if no longer needed.",
        )
    return None


def _check_backup_policy(v: VolumeDetail) -> Optional[VolumeFinding]:
    """Flag volumes with no backup policy assigned."""
    if not v.has_backup_policy:
        return VolumeFinding(
            volume_id=v.volume_id, volume_name=v.display_name,
            compartment_name=v.compartment_name,
            check_id="volume-no-backup-policy",
            severity="MEDIUM",
            title="No Backup Policy Assigned",
            detail=f"Volume '{v.display_name}' has no volume backup policy — data cannot be recovered "
                   "in the event of accidental deletion or corruption.",
            remediation="Assign a Gold/Silver/Bronze (or custom) volume backup policy.",
        )
    return None


def _check_faulty_state(v: VolumeDetail) -> Optional[VolumeFinding]:
    """Flag volumes in a faulty lifecycle state."""
    if v.lifecycle_state == "FAULTY":
        return VolumeFinding(
            volume_id=v.volume_id, volume_name=v.display_name,
            compartment_name=v.compartment_name,
            check_id="volume-faulty",
            severity="HIGH",
            title="Volume in FAULTY State",
            detail=f"Volume '{v.display_name}' is in a FAULTY state — may indicate underlying storage "
                   "failure or a failed restore operation.",
            remediation="Investigate the volume's health via the OCI console and restore from backup if needed.",
        )
    return None


ALL_CHECKS = [_check_kms_encryption, _check_unattached, _check_backup_policy, _check_faulty_state]


# ---------------------------------------------------------------------------
# Volume Scanner
# ---------------------------------------------------------------------------
class VolumeScanner:
    """Scans OCI Block Volumes across compartments for security and hygiene issues."""

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
            asset_ids: Optional[List[str]] = None) -> VolumeScanReport:
        report = VolumeScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_volumes = len(report.volumes)

        all_findings = [f for v in report.volumes for f in v.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")
        report.unattached_volumes = sum(1 for v in report.volumes if not v.is_attached)
        report.unencrypted_volumes = sum(1 for v in report.volumes if not v.kms_key_id)

        return report

    def _run_live(self, report: VolumeScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan Block Volumes across all subscribed regions."""
        try:
            import oci

            self._progress("Volume Scanner: Discovering subscribed regions...")
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

            all_volumes = []

            for region in subscribed_regions:
                self._progress(f"Volume Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                bs_client = self.collector.get_client("block_storage")
                compute_client = self.collector.get_client("compute")
                if not bs_client:
                    self._progress(f"Volume Scanner: Block Storage client not available in {region}")
                    continue

                self._progress(f"Volume Scanner [{region}]: Scanning {len(active_comps)} compartments ({_MAX_WORKERS} threads)...")

                def _scan_compartment(comp):
                    cid, cname = comp["id"], comp["name"]
                    vols = []
                    try:
                        vol_list = oci.pagination.list_call_get_all_results(
                            bs_client.list_volumes, cid
                        ).data

                        # Determine which volumes are currently attached
                        attached_ids = set()
                        try:
                            attachments = oci.pagination.list_call_get_all_results(
                                compute_client.list_volume_attachments, cid
                            ).data
                            attached_ids = {
                                a.volume_id for a in attachments
                                if a.lifecycle_state == "ATTACHED"
                            }
                        except Exception as e:
                            logger.debug(f"Volume Scanner: could not list attachments in {cname}: {e}")

                        for vol in vol_list:
                            if vol.lifecycle_state in ("TERMINATED", "TERMINATING"):
                                continue

                            has_backup_policy = False
                            try:
                                assignment = bs_client.get_volume_backup_policy_asset_assignment(vol.id).data
                                has_backup_policy = bool(assignment)
                            except Exception as e:
                                logger.debug(f"Volume Scanner: could not check backup policy for {vol.id}: {e}")

                            detail = VolumeDetail(
                                volume_id=vol.id,
                                display_name=vol.display_name,
                                compartment_name=cname,
                                compartment_id=cid,
                                availability_domain=getattr(vol, "availability_domain", ""),
                                lifecycle_state=vol.lifecycle_state,
                                size_in_gbs=getattr(vol, "size_in_gbs", None),
                                vpus_per_gb=getattr(vol, "vpus_per_gb", None),
                                kms_key_id=getattr(vol, "kms_key_id", None),
                                is_hydrated=getattr(vol, "is_hydrated", None),
                                is_attached=vol.id in attached_ids,
                                has_backup_policy=has_backup_policy,
                                time_created=str(getattr(vol, "time_created", "")),
                                region=region,
                            )
                            if self.run_checks:
                                for check in ALL_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            vols.append(detail)
                    except Exception as e:
                        logger.debug(f"Volume Scanner: Error in compartment {cname} ({region}): {e}")
                    return vols

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_compartment, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_volumes.extend(f.result())
                        except Exception as e:
                            logger.error(f"Volume Scanner thread error ({region}): {e}")

            if asset_ids:
                all_volumes = [v for v in all_volumes if v.volume_id in asset_ids]
            report.volumes = all_volumes

            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"Volume Scanner: Found {len(all_volumes)} volumes. Complete!")

        except Exception as e:
            logger.error("Volume Scanner live scan error: %s", e)
            self._progress(f"Volume Scanner: Error — {e}")

    def _run_mock(self, report: VolumeScanReport):
        self._progress("Volume Scanner: Running in mock mode...")

        mock_vol = VolumeDetail(
            volume_id="ocid1.volume.oc1..mock1",
            display_name="prod-db-data-vol",
            compartment_name="Production",
            compartment_id="ocid1.compartment.oc1..prod",
            availability_domain="AD-1",
            lifecycle_state="AVAILABLE",
            size_in_gbs=500,
            vpus_per_gb=10,
            kms_key_id=None,
            is_hydrated=True,
            is_attached=True,
            has_backup_policy=False,
            time_created="2025-06-15T10:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_vol)
                if finding:
                    mock_vol.findings.append(finding)

        mock_vol2 = VolumeDetail(
            volume_id="ocid1.volume.oc1..mock2",
            display_name="dev-scratch-vol",
            compartment_name="Development",
            compartment_id="ocid1.compartment.oc1..dev",
            availability_domain="AD-1",
            lifecycle_state="AVAILABLE",
            size_in_gbs=50,
            vpus_per_gb=10,
            kms_key_id="ocid1.key.oc1..mockkey",
            is_hydrated=True,
            is_attached=False,
            has_backup_policy=True,
            time_created="2025-09-20T08:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_vol2)
                if finding:
                    mock_vol2.findings.append(finding)

        report.volumes = [mock_vol, mock_vol2]
        report.compartments_scanned = 2
        self._progress("Volume Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_volume_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                     progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run Block Volume scan and return results as a dict."""
    scanner = VolumeScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
