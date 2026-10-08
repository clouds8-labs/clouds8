"""
Clouds8 — Vault & Secret Scanner
Scans OCI Tenancy for Vaults, Keys, and Secrets across compartments.
Collects details about lifecycle states, descriptions, and metadata.

Uses ThreadPoolExecutor for parallel compartment scanning.
"""

import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10  # Parallel OCI API threads


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class VaultDetail:
    """Details of an OCI KMS Vault."""
    vault_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    time_created: str
    vault_type: str
    management_endpoint: str
    freeform_tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vault_id": self.vault_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "time_created": self.time_created,
            "vault_type": self.vault_type,
            "management_endpoint": self.management_endpoint,
            "freeform_tags": self.freeform_tags,
        }


@dataclass
class SecretDetail:
    """Details of an OCI Secret."""
    secret_id: str
    secret_name: str
    compartment_name: str
    compartment_id: str
    vault_id: str
    key_id: str
    lifecycle_state: str
    time_created: str
    time_of_current_version_expiry: Optional[str] = None
    description: Optional[str] = None
    secret_value: Optional[str] = None
    freeform_tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "secret_name": self.secret_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "vault_id": self.vault_id,
            "key_id": self.key_id,
            "lifecycle_state": self.lifecycle_state,
            "time_created": self.time_created,
            "time_of_current_version_expiry": self.time_of_current_version_expiry,
            "description": self.description,
            "secret_value": self.secret_value,
            "freeform_tags": self.freeform_tags,
        }


@dataclass
class VaultScanReport:
    """Full Vault & Secret scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_vaults: int = 0
    active_vaults: int = 0
    total_secrets: int = 0
    active_secrets: int = 0
    compartments_scanned: int = 0
    region: str = ""
    vaults: List[VaultDetail] = field(default_factory=list)
    secrets: List[SecretDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_vaults": self.total_vaults,
            "active_vaults": self.active_vaults,
            "total_secrets": self.total_secrets,
            "active_secrets": self.active_secrets,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "vaults": [v.to_dict() for v in self.vaults],
            "secrets": [s.to_dict() for s in self.secrets],
        }


# ---------------------------------------------------------------------------
# Vault Scanner
# ---------------------------------------------------------------------------
class VaultScanner:
    """
    Scans OCI Key Management Vaults and Secrets across compartments.
    """

    def __init__(self, collector=None, progress_callback=None, run_checks: bool = True):
        self.collector = collector
        self.progress_callback = progress_callback
        # No-op: this scanner has no security checks today (pure vault/secret
        # inventory), so run_checks is accepted only for call-signature
        # uniformity with the other playbook scanners.
        self.run_checks = run_checks

    def _progress(self, msg: str):
        logger.info(msg)
        if self.progress_callback:
            try:
                self.progress_callback(msg)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, compartment_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None,
            asset_ids: Optional[List[str]] = None) -> VaultScanReport:
        """
        Scan Vaults & Secrets across compartments.
        """
        report = VaultScanReport()

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()

        # Tally
        report.total_vaults = len(report.vaults)
        report.active_vaults = sum(1 for v in report.vaults if v.lifecycle_state == "ACTIVE")
        report.total_secrets = len(report.secrets)
        report.active_secrets = sum(1 for s in report.secrets if s.lifecycle_state == "ACTIVE")

        return report

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------
    def _run_live(self, report: VaultScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan live OCI environment across all subscribed regions."""
        try:
            self._progress("Vault Scanner: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-phoenix-1")]
            if regions:
                subscribed_regions = [r for r in subscribed_regions if r in regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_comps = [
                c for c in self.collector.compartments
                if c.get("lifecycle_state") == "ACTIVE"
            ]

            if compartment_ids:
                active_comps = [
                    c for c in active_comps
                    if c["id"] in compartment_ids
                ]

            report.compartments_scanned = len(active_comps)
            
            all_vaults = []
            all_secrets = []

            for region in subscribed_regions:
                self._progress(f"Vault Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)

                vault_client = self.collector.get_client("kms_vault")
                secrets_client = self.collector.get_client("secrets")
                secrets_read_client = self.collector.get_client("secrets_read")

                if not vault_client or not secrets_client:
                    self._progress(f"Vault Scanner: KMS or Secrets client not available in {region}")
                    continue

                self._progress(
                    f"Vault Scanner [{region}]: Scanning {len(active_comps)} compartments "
                    f"in parallel ({_MAX_WORKERS} threads)..."
                )

                def _scan_compartment(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    c_vaults = []
                    c_secrets = []

                    # List Vaults
                    try:
                        vaults_resp = vault_client.list_vaults(cid).data
                        for v in vaults_resp:
                            if v.lifecycle_state not in ("DELETED", "DELETING"):
                                c_vaults.append(VaultDetail(
                                    vault_id=v.id,
                                    display_name=v.display_name,
                                    compartment_name=cname,
                                    compartment_id=cid,
                                    lifecycle_state=v.lifecycle_state,
                                    time_created=str(getattr(v, "time_created", "")),
                                    vault_type=getattr(v, "vault_type", "UNKNOWN"),
                                    management_endpoint=getattr(v, "management_endpoint", ""),
                                    freeform_tags=getattr(v, "freeform_tags", {}) or {}
                                ))
                    except Exception as e:
                        logger.debug(f"Vault Scanner: Error listing vaults in {cname} ({region}): {e}")

                    # List Secrets
                    try:
                        secrets_resp = secrets_client.list_secrets(cid).data
                        for s in secrets_resp:
                            if s.lifecycle_state not in ("DELETED", "DELETING"):
                                # Fetch exact secret bundle
                                secret_value = None
                                if secrets_read_client and s.lifecycle_state == "ACTIVE":
                                    try:
                                        bundle = secrets_read_client.get_secret_bundle(s.id).data
                                        if getattr(bundle, "secret_bundle_content", None):
                                            content = bundle.secret_bundle_content.content
                                            if content:
                                                secret_value = base64.b64decode(content).decode("utf-8")
                                    except Exception as e:
                                        logger.debug(f"Vault Scanner: Insufficient permissions or error reading secret {s.id} ({region}): {e}")

                                c_secrets.append(SecretDetail(
                                    secret_id=s.id,
                                    secret_name=s.secret_name,
                                    compartment_name=cname,
                                    compartment_id=cid,
                                    vault_id=s.vault_id,
                                    key_id=getattr(s, "key_id", ""),
                                    lifecycle_state=s.lifecycle_state,
                                    time_created=str(getattr(s, "time_created", "")),
                                    time_of_current_version_expiry=str(getattr(s, "time_of_current_version_expiry", "")) if getattr(s, "time_of_current_version_expiry", None) else None,
                                    description=getattr(s, "description", None),
                                    secret_value=secret_value,
                                    freeform_tags=getattr(s, "freeform_tags", {}) or {}
                                ))
                    except Exception as e:
                        logger.debug(f"Vault Scanner: Error listing secrets in {cname} ({region}): {e}")

                    return c_vaults, c_secrets

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_compartment, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            v, s = f.result()
                            all_vaults.extend(v)
                            all_secrets.extend(s)
                        except Exception as e:
                            logger.error(f"Error in compartment scan thread ({region}): {e}")

            if asset_ids:
                all_vaults = [v for v in all_vaults if v.vault_id in asset_ids]
                all_secrets = [s for s in all_secrets if s.secret_id in asset_ids]
            report.vaults = all_vaults
            report.secrets = all_secrets

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"Vault Scanner: Found {len(all_vaults)} Vaults and {len(all_secrets)} Secrets. Complete!")

        except Exception as e:
            logger.error("Vault Scanner live scan error: %s", e)
            self._progress(f"Vault Scanner: Error — {e}")

    # ------------------------------------------------------------------
    # Mock scanning
    # ------------------------------------------------------------------
    def _run_mock(self, report: VaultScanReport):
        """Generate mock Vault data."""
        self._progress("Vault Scanner: Running in mock mode...")

        report.vaults = [
            VaultDetail(
                vault_id="ocid1.vault.oc1..mock1",
                display_name="Production Vault",
                compartment_name="Production",
                compartment_id="ocid1.compartment.oc1..prod",
                lifecycle_state="ACTIVE",
                time_created="2025-01-01T10:00:00Z",
                vault_type="DEFAULT",
                management_endpoint="https://mock-mgmt.vault.oci.oraclecloud.com",
                freeform_tags={"Environment": "Prod"}
            ),
        ]

        report.secrets = [
            SecretDetail(
                secret_id="ocid1.vaultsecret.oc1..mock1",
                secret_name="db-prod-password",
                compartment_name="Production",
                compartment_id="ocid1.compartment.oc1..prod",
                vault_id="ocid1.vault.oc1..mock1",
                key_id="ocid1.key.oc1..mock1",
                lifecycle_state="ACTIVE",
                time_created="2025-01-02T10:00:00Z",
                description="Production database master password",
                secret_value="hunter2",
                freeform_tags={"Service": "Database"}
            )
        ]

        report.compartments_scanned = 1
        self._progress("Vault Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_vault_scan(
    collector=None,
    compartment_ids=None,
    regions=None,
    asset_ids=None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run Vault scan and return results as a dict."""
    scanner = VaultScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
