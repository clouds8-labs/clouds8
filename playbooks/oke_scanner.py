"""
Clouds8 — OKE (Container Engine for Kubernetes) Scanner
Scans OCI OKE clusters and their node pools across compartments for
security and hygiene issues.

Checks:
  - Public Kubernetes API endpoint
  - Deprecated/vulnerable Kubernetes Dashboard add-on enabled
  - Legacy Helm v2/Tiller add-on enabled (known privilege-escalation history)
  - Image signature verification (image policy) disabled
  - Deprecated/EOL Kubernetes control-plane version
  - Node pool Kubernetes version skew against the control plane

Uses ThreadPoolExecutor for parallel compartment scanning.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10

# Minimum Kubernetes minor version OCI/OKE still actively supports.
# Verify against https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengaboutk8sversions.htm
# at implementation/maintenance time — OKE's supported version matrix changes over time.
_MIN_SUPPORTED_K8S_MINOR = (1, 28)


def _parse_k8s_minor(version: Optional[str]) -> Optional[tuple]:
    """Parse a 'v1.28.2' style string into a (major, minor) tuple."""
    if not version:
        return None
    try:
        v = version.lstrip("v")
        parts = v.split(".")
        return (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ClusterFinding:
    """A single security finding for an OKE cluster."""
    cluster_id: str
    cluster_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class ClusterDetail:
    """Enriched details for an OKE cluster."""
    cluster_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    kubernetes_version: str
    vcn_id: Optional[str]
    is_public_ip_enabled: Optional[bool]
    is_kubernetes_dashboard_enabled: Optional[bool]
    is_tiller_enabled: Optional[bool]
    is_image_policy_enabled: Optional[bool]
    node_pool_count: int
    node_pool_version_mismatches: List[str] = field(default_factory=list)
    time_created: str = ""
    region: str = "unknown"
    findings: List[ClusterFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "kubernetes_version": self.kubernetes_version,
            "vcn_id": self.vcn_id,
            "is_public_ip_enabled": self.is_public_ip_enabled,
            "is_kubernetes_dashboard_enabled": self.is_kubernetes_dashboard_enabled,
            "is_tiller_enabled": self.is_tiller_enabled,
            "is_image_policy_enabled": self.is_image_policy_enabled,
            "node_pool_count": self.node_pool_count,
            "node_pool_version_mismatches": self.node_pool_version_mismatches,
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
class ClusterScanReport:
    """Full OKE cluster scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_clusters: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    public_endpoint_clusters: int = 0
    deprecated_version_clusters: int = 0
    compartments_scanned: int = 0
    region: str = ""
    clusters: List[ClusterDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_clusters": self.total_clusters,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "public_endpoint_clusters": self.public_endpoint_clusters,
            "deprecated_version_clusters": self.deprecated_version_clusters,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "clusters": [c.to_dict() for c in self.clusters],
        }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------
def _check_public_api_endpoint(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters whose Kubernetes API endpoint is reachable from the internet."""
    if c.is_public_ip_enabled is True:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-public-api-endpoint",
            severity="HIGH",
            title="Public Kubernetes API Endpoint",
            detail=f"Cluster '{c.display_name}' exposes its Kubernetes API endpoint with a public IP.",
            remediation="Disable the public IP on the cluster endpoint and access the API via a "
                        "private endpoint (bastion, VPN, or FastConnect).",
        )
    return None


def _check_dashboard_enabled(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters with the deprecated/vulnerable Kubernetes Dashboard add-on enabled."""
    if c.is_kubernetes_dashboard_enabled is True:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-dashboard-enabled",
            severity="MEDIUM",
            title="Kubernetes Dashboard Add-on Enabled",
            detail=f"Cluster '{c.display_name}' has the Kubernetes Dashboard add-on enabled — "
                   "a deprecated component with a history of exposure/misconfiguration risk.",
            remediation="Disable the Kubernetes Dashboard add-on; use OCI Console or kubectl instead.",
        )
    return None


def _check_tiller_enabled(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters with the legacy Helm v2/Tiller add-on enabled."""
    if c.is_tiller_enabled is True:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-tiller-enabled",
            severity="HIGH",
            title="Legacy Helm Tiller Add-on Enabled",
            detail=f"Cluster '{c.display_name}' has the Helm v2/Tiller add-on enabled — Tiller has a "
                   "known history of cluster-wide privilege-escalation CVEs.",
            remediation="Disable Tiller and migrate to Helm v3, which has no in-cluster Tiller component.",
        )
    return None


def _check_image_policy_disabled(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters with no image signature verification policy enforced."""
    if not c.is_image_policy_enabled:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-image-policy-disabled",
            severity="MEDIUM",
            title="Image Signature Verification Disabled",
            detail=f"Cluster '{c.display_name}' does not enforce an image signing policy — unsigned "
                   "or untrusted container images can be deployed.",
            remediation="Enable an image policy requiring signature verification against a trusted key.",
        )
    return None


def _check_deprecated_version(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters running a Kubernetes control-plane version below the supported floor."""
    minor = _parse_k8s_minor(c.kubernetes_version)
    if minor is not None and minor < _MIN_SUPPORTED_K8S_MINOR:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-deprecated-k8s-version",
            severity="HIGH",
            title="Deprecated Kubernetes Version",
            detail=f"Cluster '{c.display_name}' runs Kubernetes {c.kubernetes_version}, below the "
                   f"supported floor v{_MIN_SUPPORTED_K8S_MINOR[0]}.{_MIN_SUPPORTED_K8S_MINOR[1]}.",
            remediation="Upgrade the cluster to a currently-supported Kubernetes version.",
        )
    return None


def _check_nodepool_version_skew(c: ClusterDetail) -> Optional[ClusterFinding]:
    """Flag clusters where one or more node pools run a different Kubernetes version than the control plane."""
    if c.node_pool_version_mismatches:
        return ClusterFinding(
            cluster_id=c.cluster_id, cluster_name=c.display_name,
            compartment_name=c.compartment_name,
            check_id="oke-nodepool-version-skew",
            severity="MEDIUM",
            title="Node Pool / Control Plane Version Skew",
            detail=f"Cluster '{c.display_name}' control plane is {c.kubernetes_version}, but node "
                   f"pool(s) are out of sync: {', '.join(c.node_pool_version_mismatches)}.",
            remediation="Upgrade node pools to match the control plane's Kubernetes version.",
        )
    return None


ALL_CHECKS = [
    _check_public_api_endpoint, _check_dashboard_enabled, _check_tiller_enabled,
    _check_image_policy_disabled, _check_deprecated_version, _check_nodepool_version_skew,
]


# ---------------------------------------------------------------------------
# OKE Scanner
# ---------------------------------------------------------------------------
class OKEScanner:
    """Scans OCI OKE clusters across compartments for security and hygiene issues."""

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
            asset_ids: Optional[List[str]] = None) -> ClusterScanReport:
        report = ClusterScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_clusters = len(report.clusters)

        all_findings = [f for c in report.clusters for f in c.findings]
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")
        report.public_endpoint_clusters = sum(1 for c in report.clusters if c.is_public_ip_enabled)
        report.deprecated_version_clusters = sum(
            1 for c in report.clusters if any(f.check_id == "oke-deprecated-k8s-version" for f in c.findings)
        )

        return report

    def _run_live(self, report: ClusterScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        """Scan OKE clusters across all subscribed regions."""
        try:
            import oci

            self._progress("OKE Scanner: Discovering subscribed regions...")
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

            all_clusters = []

            for region in subscribed_regions:
                self._progress(f"OKE Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                ce_client = self.collector.get_client("container_engine")
                if not ce_client:
                    self._progress(f"OKE Scanner: Container Engine client not available in {region}")
                    continue

                self._progress(f"OKE Scanner [{region}]: Scanning {len(active_comps)} compartments ({_MAX_WORKERS} threads)...")

                def _scan_compartment(comp):
                    cid, cname = comp["id"], comp["name"]
                    clusters = []
                    try:
                        cluster_list = oci.pagination.list_call_get_all_results(
                            ce_client.list_clusters, cid
                        ).data
                        for cl in cluster_list:
                            if cl.lifecycle_state in ("DELETED", "DELETING"):
                                continue

                            endpoint_config = getattr(cl, "endpoint_config", None)
                            options = getattr(cl, "options", None)
                            add_ons = getattr(options, "add_ons", None) if options else None
                            image_policy_config = getattr(cl, "image_policy_config", None)
                            metadata = getattr(cl, "metadata", None)

                            node_pools = []
                            try:
                                node_pools = [
                                    np for np in oci.pagination.list_call_get_all_results(
                                        ce_client.list_node_pools, cid, cluster_id=cl.id
                                    ).data
                                    if np.lifecycle_state not in ("DELETED", "DELETING")
                                ]
                            except Exception as e:
                                logger.debug(f"OKE Scanner: could not list node pools for cluster {cl.name}: {e}")

                            mismatches = [
                                f"{np.name}: {np.kubernetes_version}"
                                for np in node_pools
                                if getattr(np, "kubernetes_version", None) and np.kubernetes_version != cl.kubernetes_version
                            ]

                            detail = ClusterDetail(
                                cluster_id=cl.id,
                                display_name=cl.name,
                                compartment_name=cname,
                                compartment_id=cid,
                                lifecycle_state=cl.lifecycle_state,
                                kubernetes_version=cl.kubernetes_version,
                                vcn_id=getattr(cl, "vcn_id", None),
                                is_public_ip_enabled=getattr(endpoint_config, "is_public_ip_enabled", None) if endpoint_config else None,
                                is_kubernetes_dashboard_enabled=getattr(add_ons, "is_kubernetes_dashboard_enabled", None) if add_ons else None,
                                is_tiller_enabled=getattr(add_ons, "is_tiller_enabled", None) if add_ons else None,
                                is_image_policy_enabled=getattr(image_policy_config, "is_policy_enabled", None) if image_policy_config else None,
                                node_pool_count=len(node_pools),
                                node_pool_version_mismatches=mismatches,
                                time_created=str(getattr(metadata, "time_created", "")) if metadata else "",
                                region=region,
                            )
                            if self.run_checks:
                                for check in ALL_CHECKS:
                                    finding = check(detail)
                                    if finding:
                                        detail.findings.append(finding)
                            clusters.append(detail)
                    except Exception as e:
                        logger.debug(f"OKE Scanner: Error in compartment {cname} ({region}): {e}")
                    return clusters

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_compartment, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_clusters.extend(f.result())
                        except Exception as e:
                            logger.error(f"OKE Scanner thread error ({region}): {e}")

            if asset_ids:
                all_clusters = [c for c in all_clusters if c.cluster_id in asset_ids]
            report.clusters = all_clusters

            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress(f"OKE Scanner: Found {len(all_clusters)} clusters. Complete!")

        except Exception as e:
            logger.error("OKE Scanner live scan error: %s", e)
            self._progress(f"OKE Scanner: Error — {e}")

    def _run_mock(self, report: ClusterScanReport):
        self._progress("OKE Scanner: Running in mock mode...")

        clean_cluster = ClusterDetail(
            cluster_id="ocid1.cluster.oc1..mock1",
            display_name="prod-oke-cluster",
            compartment_name="Production",
            compartment_id="ocid1.compartment.oc1..prod",
            lifecycle_state="ACTIVE",
            kubernetes_version="v1.29.1",
            vcn_id="ocid1.vcn.oc1..mock1",
            is_public_ip_enabled=False,
            is_kubernetes_dashboard_enabled=False,
            is_tiller_enabled=False,
            is_image_policy_enabled=True,
            node_pool_count=1,
            node_pool_version_mismatches=[],
            time_created="2025-02-01T00:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(clean_cluster)
                if finding:
                    clean_cluster.findings.append(finding)

        risky_cluster = ClusterDetail(
            cluster_id="ocid1.cluster.oc1..mock2",
            display_name="legacy-dev-cluster",
            compartment_name="Development",
            compartment_id="ocid1.compartment.oc1..dev",
            lifecycle_state="ACTIVE",
            kubernetes_version="v1.24.1",
            vcn_id="ocid1.vcn.oc1..mock2",
            is_public_ip_enabled=True,
            is_kubernetes_dashboard_enabled=True,
            is_tiller_enabled=True,
            is_image_policy_enabled=False,
            node_pool_count=1,
            node_pool_version_mismatches=["pool-a: v1.22.0"],
            time_created="2022-11-15T00:00:00Z",
        )
        if self.run_checks:
            for check in ALL_CHECKS:
                finding = check(risky_cluster)
                if finding:
                    risky_cluster.findings.append(finding)

        report.clusters = [clean_cluster, risky_cluster]
        report.compartments_scanned = 2
        self._progress("OKE Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_oke_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                  progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run OKE cluster scan and return results as a dict."""
    scanner = OKEScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
