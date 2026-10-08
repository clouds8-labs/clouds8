"""
Clouds8 — Custom Image Scanner
Scans OCI custom Compute Images across compartments for security and hygiene issues.

Checks:
  - Legacy BIOS firmware (no Secure Boot support) vs. UEFI_64
  - Paravirtualized encryption-in-transit disabled between instance and block storage
  - OCI management/monitoring agent support disabled at the image level
  - Stale custom images (old, unused housekeeping risk)

Scoped to custom images only — identified via ``base_image_id`` being set,
which OCI populates only for images derived from another image (i.e. not
Oracle-provided platform images). Uses ThreadPoolExecutor for parallel
compartment scanning.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
_STALE_DAYS = 180


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ImageFinding:
    """A single security finding for a custom Compute Image."""
    image_id: str
    image_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "image_name": self.image_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class ImageDetail:
    """Enriched details for a custom Compute Image."""
    image_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    operating_system: str
    operating_system_version: str
    base_image_id: Optional[str]
    firmware: Optional[str]
    is_pv_encryption_in_transit_enabled: Optional[bool]
    is_management_supported: Optional[bool]
    is_monitoring_supported: Optional[bool]
    size_in_mbs: Optional[int]
    time_created: str
    region: str = "unknown"
    findings: List[ImageFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "operating_system": self.operating_system,
            "operating_system_version": self.operating_system_version,
            "base_image_id": self.base_image_id,
            "firmware": self.firmware,
            "is_pv_encryption_in_transit_enabled": self.is_pv_encryption_in_transit_enabled,
            "is_management_supported": self.is_management_supported,
            "is_monitoring_supported": self.is_monitoring_supported,
            "size_in_mbs": self.size_in_mbs,
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
class ImageScanReport:
    """Full custom Image scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_images: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    stale_images: int = 0
    compartments_scanned: int = 0
    region: str = ""
    images: List[ImageDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_images": self.total_images,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "stale_images": self.stale_images,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "images": [i.to_dict() for i in self.images],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_legacy_firmware(img: ImageDetail) -> Optional[ImageFinding]:
    """Flag images using legacy BIOS firmware instead of UEFI (no Secure Boot support)."""
    if img.firmware and img.firmware != "UEFI_64":
        return ImageFinding(
            image_id=img.image_id, image_name=img.display_name,
            compartment_name=img.compartment_name,
            check_id="image-legacy-firmware",
            severity="MEDIUM",
            title="Legacy BIOS Firmware",
            detail=f"Image '{img.display_name}' uses '{img.firmware}' firmware, which does not "
                   "support Secure Boot or Shielded Instances.",
            remediation="Rebuild the image with UEFI_64 firmware to enable Secure Boot.",
        )
    return None


def _check_pv_encryption(img: ImageDetail) -> Optional[ImageFinding]:
    """Flag images with paravirtualized in-transit encryption disabled."""
    if img.is_pv_encryption_in_transit_enabled is False:
        return ImageFinding(
            image_id=img.image_id, image_name=img.display_name,
            compartment_name=img.compartment_name,
            check_id="image-pv-encryption-disabled",
            severity="HIGH",
            title="In-Transit Encryption Disabled",
            detail=f"Image '{img.display_name}' does not enable paravirtualized encryption in transit "
                   "between instances launched from it and attached block storage.",
            remediation="Rebuild or reconfigure the image with in-transit encryption enabled.",
        )
    return None


def _check_management_agent(img: ImageDetail) -> Optional[ImageFinding]:
    """Flag images that don't support the OCI management agent."""
    if img.is_management_supported is False:
        return ImageFinding(
            image_id=img.image_id, image_name=img.display_name,
            compartment_name=img.compartment_name,
            check_id="image-management-disabled",
            severity="LOW",
            title="Management Agent Not Supported",
            detail=f"Image '{img.display_name}' does not support the OCI management agent, "
                   "reducing patch/config visibility for instances launched from it.",
            remediation="Rebuild the image with the Oracle Cloud Agent management plugin enabled.",
        )
    return None


def _check_monitoring_agent(img: ImageDetail) -> Optional[ImageFinding]:
    """Flag images that don't support the OCI monitoring agent."""
    if img.is_monitoring_supported is False:
        return ImageFinding(
            image_id=img.image_id, image_name=img.display_name,
            compartment_name=img.compartment_name,
            check_id="image-monitoring-disabled",
            severity="LOW",
            title="Monitoring Agent Not Supported",
            detail=f"Image '{img.display_name}' does not support the OCI monitoring agent, "
                   "reducing observability for instances launched from it.",
            remediation="Rebuild the image with the Oracle Cloud Agent monitoring plugin enabled.",
        )
    return None


def _check_stale(img: ImageDetail) -> Optional[ImageFinding]:
    """Flag old custom images that may be forgotten housekeeping debt."""
    if not img.time_created:
        return None
    try:
        created = datetime.fromisoformat(img.time_created.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created).days
    except Exception:
        return None
    if age_days > _STALE_DAYS and img.lifecycle_state == "AVAILABLE":
        return ImageFinding(
            image_id=img.image_id, image_name=img.display_name,
            compartment_name=img.compartment_name,
            check_id="image-stale",
            severity="LOW",
            title="Stale Custom Image",
            detail=f"Image '{img.display_name}' is {age_days} days old — verify it is still in use.",
            remediation="Archive or delete unused custom images to reduce attack surface and cost.",
        )
    return None


ALL_CHECKS = [_check_legacy_firmware, _check_pv_encryption, _check_management_agent,
              _check_monitoring_agent, _check_stale]


# ---------------------------------------------------------------------------
# Image Scanner
# ---------------------------------------------------------------------------
class ImageScanner:
    """Scans OCI custom Compute Images across compartments for security and hygiene issues."""

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
            asset_ids: Optional[List[str]] = None) -> ImageScanReport:
        report = ImageScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_images = len(report.images)

        all_findings = [f for i in report.images for f in i.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")
        report.stale_images = sum(1 for i in report.images if any(f.check_id == "image-stale" for f in i.findings))

        return report

    def _run_live(self, report: ImageScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan custom Compute Images across all subscribed regions."""
        try:
            import oci

            self._progress("Image Scanner: Discovering subscribed regions...")
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

            all_images = []

            for region in subscribed_regions:
                self._progress(f"Image Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                compute_client = self.collector.get_client("compute")
                if not compute_client:
                    self._progress(f"Image Scanner: Compute client not available in {region}")
                    continue

                self._progress(f"Image Scanner [{region}]: Scanning {len(active_comps)} compartments ({_MAX_WORKERS} threads)...")

                def _scan_compartment(comp):
                    cid, cname = comp["id"], comp["name"]
                    imgs = []
                    try:
                        image_list = oci.pagination.list_call_get_all_results(
                            compute_client.list_images, cid
                        ).data
                        for img in image_list:
                            # Custom images only — platform (Oracle-provided) images
                            # never have a base_image_id.
                            if not getattr(img, "base_image_id", None):
                                continue
                            if img.lifecycle_state in ("DELETED",):
                                continue

                            launch_options = getattr(img, "launch_options", None)
                            agent_features = getattr(img, "agent_features", None)

                            detail = ImageDetail(
                                image_id=img.id,
                                display_name=img.display_name,
                                compartment_name=cname,
                                compartment_id=cid,
                                lifecycle_state=img.lifecycle_state,
                                operating_system=getattr(img, "operating_system", ""),
                                operating_system_version=getattr(img, "operating_system_version", ""),
                                base_image_id=img.base_image_id,
                                firmware=getattr(launch_options, "firmware", None) if launch_options else None,
                                is_pv_encryption_in_transit_enabled=(
                                    getattr(launch_options, "is_pv_encryption_in_transit_enabled", None)
                                    if launch_options else None
                                ),
                                is_management_supported=(
                                    getattr(agent_features, "is_management_supported", None)
                                    if agent_features else None
                                ),
                                is_monitoring_supported=(
                                    getattr(agent_features, "is_monitoring_supported", None)
                                    if agent_features else None
                                ),
                                size_in_mbs=getattr(img, "size_in_mbs", None),
                                time_created=str(getattr(img, "time_created", "")),
                                region=region,
                            )
                            if self.run_checks:
                                for check in ALL_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            imgs.append(detail)
                    except Exception as e:
                        logger.debug(f"Image Scanner: Error in compartment {cname} ({region}): {e}")
                    return imgs

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = {pool.submit(_scan_compartment, c): c for c in active_comps}
                    done = 0
                    total_c = len(active_comps)
                    for f in as_completed(futures):
                        comp = futures[f]
                        done += 1
                        try:
                            all_images.extend(f.result())
                        except Exception as e:
                            logger.error(f"Image Scanner thread error ({region}): {e}")
                        if done % 10 == 0 or done == total_c:
                            self._progress(
                                f"Image Scanner [{region}]: [{done}/{total_c}] compartments scanned "
                                f"— {comp['name']}"
                            )

            if asset_ids:
                all_images = [i for i in all_images if i.image_id in asset_ids]
            report.images = all_images

            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"Image Scanner: Found {len(all_images)} custom images. Complete!")

        except Exception as e:
            logger.error("Image Scanner live scan error: %s", e)
            self._progress(f"Image Scanner: Error — {e}")

    def _run_mock(self, report: ImageScanReport):
        self._progress("Image Scanner: Running in mock mode...")

        mock_img = ImageDetail(
            image_id="ocid1.image.oc1..mock1",
            display_name="golden-web-image-v3",
            compartment_name="Production",
            compartment_id="ocid1.compartment.oc1..prod",
            lifecycle_state="AVAILABLE",
            operating_system="Oracle Linux",
            operating_system_version="8",
            base_image_id="ocid1.image.oc1..base1",
            firmware="BIOS",
            is_pv_encryption_in_transit_enabled=False,
            is_management_supported=True,
            is_monitoring_supported=True,
            size_in_mbs=47000,
            time_created="2024-01-15T10:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_img)
                if finding:
                    mock_img.findings.append(finding)

        mock_img2 = ImageDetail(
            image_id="ocid1.image.oc1..mock2",
            display_name="dev-sandbox-image",
            compartment_name="Development",
            compartment_id="ocid1.compartment.oc1..dev",
            lifecycle_state="AVAILABLE",
            operating_system="Ubuntu",
            operating_system_version="22.04",
            base_image_id="ocid1.image.oc1..base2",
            firmware="UEFI_64",
            is_pv_encryption_in_transit_enabled=True,
            is_management_supported=True,
            is_monitoring_supported=True,
            size_in_mbs=32000,
            time_created="2025-11-01T08:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(mock_img2)
                if finding:
                    mock_img2.findings.append(finding)

        report.images = [mock_img, mock_img2]
        report.compartments_scanned = 2
        self._progress("Image Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_image_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                    progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run custom Image scan and return results as a dict."""
    scanner = ImageScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
