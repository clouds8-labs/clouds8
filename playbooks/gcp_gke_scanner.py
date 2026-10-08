"""
Clouds8 — GCP GKE Scanner
Scans GKE clusters for insecure configurations plus static
privilege-escalation indicators. Ported from gcp-pentest-platform's
backend/services/gke/scanner.py - per-cluster checks plus its
testIamPermissions-based risky-permission catalog (detection only, no
exploit-command strings - matches gcp_iam_scanner.py's existing precedent
for porting that module's privesc checks as plain findings+remediation).

Checks:
  - Cluster master endpoint is publicly accessible (no authorized networks)
  - Workload Identity disabled
  - Network Policy disabled (non-Autopilot clusters)
  - Binary Authorization disabled
  - A node pool's service account has the broad cloud-platform OAuth scope
  - Caller holds a known GKE privilege-escalation permission
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from collectors.gcp_collector import GCPAuthError

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Ported from gcp-pentest-platform's RISKY_PERMISSIONS/PERMISSION_SEVERITY/
# PERMISSION_DESCRIPTION maps.
PRIVESC_METHODS = [
    {
        "id": "container_clusters_update",
        "permission": "container.clusters.update",
        "title": "GKE Cluster Configuration Modification",
        "detail": "The caller can modify cluster config, e.g. disabling auth or adding malicious node pools.",
        "severity": "CRITICAL",
        "remediation": "Remove container.clusters.update from non-admin identities.",
    },
    {
        "id": "container_pods_exec",
        "permission": "container.pods.exec",
        "title": "Pod Exec Access",
        "detail": "The caller can exec into any running pod in any cluster for remote code execution.",
        "severity": "CRITICAL",
        "remediation": "Restrict container.pods.exec to break-glass/on-call identities only.",
    },
    {
        "id": "container_pods_create",
        "permission": "container.pods.create",
        "title": "Pod Creation Access",
        "detail": "The caller can deploy privileged pods, enabling node escape and cluster compromise.",
        "severity": "CRITICAL",
        "remediation": "Enforce Pod Security Admission/Policy to block privileged pod creation; "
                       "restrict container.pods.create from non-admin identities.",
    },
    {
        "id": "container_secrets_get",
        "permission": "container.secrets.get",
        "title": "Kubernetes Secrets Read Access",
        "detail": "The caller can read all Kubernetes secrets, including service account tokens.",
        "severity": "CRITICAL",
        "remediation": "Restrict container.secrets.get; prefer Workload Identity over long-lived secrets.",
    },
    {
        "id": "iam_serviceaccounts_actas",
        "permission": "iam.serviceAccounts.actAs",
        "title": "Service Account Impersonation",
        "detail": "The caller can assign a high-privilege service account to a new or existing node pool.",
        "severity": "CRITICAL",
        "remediation": "Remove iam.serviceAccounts.actAs for high-privilege SAs from non-admin identities.",
    },
    {
        "id": "container_clusters_create",
        "permission": "container.clusters.create",
        "title": "GKE Cluster Creation",
        "detail": "The caller can create new GKE clusters, potentially with a privileged node service account.",
        "severity": "HIGH",
        "remediation": "Restrict container.clusters.create to platform-admin identities.",
    },
    {
        "id": "container_clusters_delete",
        "permission": "container.clusters.delete",
        "title": "GKE Cluster Deletion",
        "detail": "The caller can permanently delete GKE clusters and all workloads running on them.",
        "severity": "HIGH",
        "remediation": "Restrict container.clusters.delete to platform-admin identities.",
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class GkeFinding:
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
class GkeClusterDetail:
    cluster_name: str
    project_id: str
    location: str
    status: str
    k8s_version: str
    is_autopilot: bool
    has_public_master: bool
    workload_identity_enabled: bool
    network_policy_enabled: bool
    binary_auth_enabled: bool
    broad_scope_pools: List[str] = field(default_factory=list)
    region: str = ""
    findings: List[GkeFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_name": self.cluster_name,
            "project_id": self.project_id,
            "location": self.location,
            "status": self.status,
            "k8s_version": self.k8s_version,
            "is_autopilot": self.is_autopilot,
            "has_public_master": self.has_public_master,
            "workload_identity_enabled": self.workload_identity_enabled,
            "network_policy_enabled": self.network_policy_enabled,
            "binary_auth_enabled": self.binary_auth_enabled,
            "broad_scope_pools": self.broad_scope_pools,
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
class GcpGkeScanReport:
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_clusters: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    projects_scanned: int = 0
    region: str = ""
    clusters: List[GkeClusterDetail] = field(default_factory=list)
    # Project-level privesc findings aren't tied to one cluster, kept alongside.
    project_findings: List[GkeFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_clusters": self.total_clusters,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "projects_scanned": self.projects_scanned,
            "region": self.region,
            "clusters": [c.to_dict() for c in self.clusters],
            "findings": [f.to_dict() for f in self.project_findings],
        }


# ---------------------------------------------------------------------------
# Per-cluster checks
# ---------------------------------------------------------------------------
def _check_public_master(c: GkeClusterDetail) -> Optional[GkeFinding]:
    if c.has_public_master:
        return GkeFinding(
            resource_id=c.cluster_name, resource_name=c.cluster_name, project_id=c.project_id,
            check_id="gcp-gke-public-master",
            severity="CRITICAL",
            title="Public Cluster Master Endpoint",
            detail=f"Cluster '{c.cluster_name}' has no master-authorized-networks restriction - "
                   "the control plane is reachable from the internet.",
            remediation="Enable master authorized networks and restrict CIDRs to trusted ranges, "
                        "or enable a private cluster.",
        )
    return None


def _check_workload_identity(c: GkeClusterDetail) -> Optional[GkeFinding]:
    if not c.workload_identity_enabled:
        return GkeFinding(
            resource_id=c.cluster_name, resource_name=c.cluster_name, project_id=c.project_id,
            check_id="gcp-gke-no-workload-identity",
            severity="HIGH",
            title="Workload Identity Disabled",
            detail=f"Cluster '{c.cluster_name}' has Workload Identity disabled - "
                   "node service-account credentials are exposed via the metadata server to any pod.",
            remediation="Enable Workload Identity and migrate workloads off node-level service account credentials.",
        )
    return None


def _check_network_policy(c: GkeClusterDetail) -> Optional[GkeFinding]:
    if not c.network_policy_enabled and not c.is_autopilot:
        return GkeFinding(
            resource_id=c.cluster_name, resource_name=c.cluster_name, project_id=c.project_id,
            check_id="gcp-gke-no-network-policy",
            severity="MEDIUM",
            title="Network Policy Disabled",
            detail=f"Cluster '{c.cluster_name}' has no Network Policy - pods can communicate freely "
                   "within the cluster regardless of namespace boundaries.",
            remediation="Enable Network Policy (Calico/Dataplane V2) and define namespace-scoped policies.",
        )
    return None


def _check_binary_auth(c: GkeClusterDetail) -> Optional[GkeFinding]:
    if not c.binary_auth_enabled:
        return GkeFinding(
            resource_id=c.cluster_name, resource_name=c.cluster_name, project_id=c.project_id,
            check_id="gcp-gke-no-binary-auth",
            severity="MEDIUM",
            title="Binary Authorization Disabled",
            detail=f"Cluster '{c.cluster_name}' has Binary Authorization disabled - "
                   "unverified/unsigned container images can run.",
            remediation="Enable Binary Authorization and require attestations from a trusted build pipeline.",
        )
    return None


def _check_broad_node_scopes(c: GkeClusterDetail) -> Optional[GkeFinding]:
    if c.broad_scope_pools:
        return GkeFinding(
            resource_id=c.cluster_name, resource_name=c.cluster_name, project_id=c.project_id,
            check_id="gcp-gke-broad-node-scope",
            severity="HIGH",
            title="Node Pool Has Cloud-Platform OAuth Scope",
            detail=f"Cluster '{c.cluster_name}' node pool(s) {', '.join(c.broad_scope_pools)} grant the "
                   "broad cloud-platform scope - any workload on those nodes can call any GCP API as the node SA.",
            remediation="Scope node pool service accounts to least-privilege OAuth scopes; use Workload "
                        "Identity for per-workload API access instead.",
        )
    return None


ALL_CLUSTER_CHECKS = [_check_public_master, _check_workload_identity, _check_network_policy,
                       _check_binary_auth, _check_broad_node_scopes]


def _privesc_findings_for_project(project_id: str, granted_permissions: List[str]) -> List[GkeFinding]:
    findings = []
    granted = set(granted_permissions)
    for method in PRIVESC_METHODS:
        if method["permission"] in granted:
            findings.append(GkeFinding(
                resource_id=project_id, resource_name=project_id, project_id=project_id,
                check_id=f"gcp-gke-privesc-{method['id']}",
                severity=method["severity"],
                title=method["title"],
                detail=method["detail"],
                remediation=method["remediation"],
            ))
    return findings


# ---------------------------------------------------------------------------
# GKE Scanner
# ---------------------------------------------------------------------------
class GcpGkeScanner:
    """Scans GKE clusters across projects."""

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
            asset_ids: Optional[List[str]] = None) -> GcpGkeScanReport:
        report = GcpGkeScanReport()
        if self.collector and self.collector.config:
            report.scan_mode = "live"
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        report.total_clusters = len(report.clusters)

        all_findings = [f for c in report.clusters for f in c.findings] + report.project_findings
        report.critical_findings = sum(1 for f in all_findings if f.severity == "CRITICAL")
        report.high_findings = sum(1 for f in all_findings if f.severity == "HIGH")
        report.medium_findings = sum(1 for f in all_findings if f.severity == "MEDIUM")

        return report

    def _run_live(self, report: GcpGkeScanReport, compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None, asset_ids: Optional[List[str]] = None):
        try:
            self._progress("GCP GKE Scanner: Discovering projects...")
            if not self.collector.compartments:
                self.collector.compartments = self.collector.collect_compartment_details()

            active_projects = [p for p in self.collector.compartments if p.get("lifecycle_state") in (None, "ACTIVE")]
            if compartment_ids:
                active_projects = [p for p in active_projects if p["id"] in compartment_ids]

            report.projects_scanned = len(active_projects)
            container_client = self.collector.get_client("container")
            crm_client = self.collector.get_client("cloudresourcemanager")
            if not container_client:
                self._progress("GCP GKE Scanner: Container client not available")
                return

            self._progress(f"GCP GKE Scanner: Scanning {len(active_projects)} projects ({_MAX_WORKERS} threads)...")

            risky_permissions = [m["permission"] for m in PRIVESC_METHODS]

            def _scan_project(proj):
                project_id = proj["id"]
                clusters, project_findings = [], []
                try:
                    if crm_client:
                        resp = crm_client.projects().testIamPermissions(
                            resource=project_id, body={"permissions": risky_permissions},
                        ).execute()
                        project_findings = _privesc_findings_for_project(project_id, resp.get("permissions", []))

                    result = container_client.projects().locations().clusters().list(
                        parent=f"projects/{project_id}/locations/-"
                    ).execute()
                    for cluster in result.get("clusters", []):
                        detail = self._analyze_cluster(cluster, project_id)
                        # GCP's list API is already project-wide - this filters
                        # client-side after the fetch, it cannot skip the
                        # underlying API call the way OCI's per-region client
                        # setup can.
                        if regions and detail.region not in regions:
                            continue
                        if asset_ids and detail.cluster_name not in asset_ids:
                            continue
                        if self.run_checks:
                            for check in ALL_CLUSTER_CHECKS:
                                finding = check(detail)
                                if finding:
                                    detail.findings.append(finding)
                        clusters.append(detail)
                except Exception as e:
                    if getattr(getattr(e, "resp", None), "status", None) == 403:
                        raise PermissionError(
                            f"Profile lacks permission to list GKE clusters in project "
                            f"'{project_id}' (container.clusters.list) — grant the service "
                            f"account the Kubernetes Engine Viewer role."
                        ) from e
                    logger.debug(f"GCP GKE Scanner: Error in project {project_id}: {e}")
                return clusters, project_findings

            all_clusters, all_project_findings = [], []
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_project, p) for p in active_projects]
                for f in as_completed(futures):
                    try:
                        clusters, project_findings = f.result()
                        all_clusters.extend(clusters)
                        all_project_findings.extend(project_findings)
                    except PermissionError:
                        raise
                    except Exception as e:
                        logger.error(f"GCP GKE Scanner thread error: {e}")

            report.clusters = all_clusters
            report.project_findings = all_project_findings if self.run_checks else []
            self._progress(f"GCP GKE Scanner: Found {len(all_clusters)} clusters. Complete!")

        except (PermissionError, GCPAuthError):
            raise
        except Exception as e:
            logger.error("GCP GKE Scanner live scan error: %s", e)
            self._progress(f"GCP GKE Scanner: Error — {e}")

    def _analyze_cluster(self, cluster: dict, project_id: str) -> GkeClusterDetail:
        name = cluster.get("name", "")
        location = cluster.get("location", "")

        master_auth_networks = cluster.get("masterAuthorizedNetworksConfig", {})
        master_auth_enabled = master_auth_networks.get("enabled", False)
        cidr_blocks = master_auth_networks.get("cidrBlocks", [])
        cidr_list = [b.get("cidrBlock", "") for b in cidr_blocks]
        has_public_master = (not master_auth_enabled) or any(
            cidr in ("0.0.0.0/0", "::/0") for cidr in cidr_list
        )

        wi_config = cluster.get("workloadIdentityConfig", {})
        workload_identity_enabled = bool(wi_config.get("workloadPool", ""))

        net_policy = cluster.get("networkPolicy", {})
        network_policy_enabled = net_policy.get("enabled", False)

        bin_auth = cluster.get("binaryAuthorization", {})
        binary_auth_enabled = bin_auth.get("enabled", False) or \
            bin_auth.get("evaluationMode", "") not in ("", "DISABLED")

        autopilot = cluster.get("autopilot", {})
        is_autopilot = autopilot.get("enabled", False)

        broad_scope_pools = []
        for pool in cluster.get("nodePools", []):
            scopes = pool.get("config", {}).get("oauthScopes", [])
            if CLOUD_PLATFORM_SCOPE in scopes:
                broad_scope_pools.append(pool.get("name", ""))

        return GkeClusterDetail(
            cluster_name=name,
            project_id=project_id,
            location=location,
            status=cluster.get("status", ""),
            k8s_version=cluster.get("currentMasterVersion", ""),
            is_autopilot=is_autopilot,
            has_public_master=has_public_master,
            workload_identity_enabled=workload_identity_enabled,
            network_policy_enabled=network_policy_enabled,
            binary_auth_enabled=binary_auth_enabled,
            broad_scope_pools=broad_scope_pools,
            region=location,
        )

    def _run_mock(self, report: GcpGkeScanReport):
        self._progress("GCP GKE Scanner: Running in mock mode...")

        mock_cluster = GkeClusterDetail(
            cluster_name="prod-cluster", project_id="mock-project", location="us-central1",
            status="RUNNING", k8s_version="1.29.0-gke.1234", is_autopilot=False,
            has_public_master=True, workload_identity_enabled=False,
            network_policy_enabled=False, binary_auth_enabled=False,
            broad_scope_pools=["default-pool"], region="us-central1",
        )
        if self.run_checks:
            for check in ALL_CLUSTER_CHECKS:
                finding = check(mock_cluster)
                if finding:
                    mock_cluster.findings.append(finding)

        report.clusters = [mock_cluster]
        report.project_findings = (
            _privesc_findings_for_project("mock-project", ["container.pods.exec"])
            if self.run_checks else []
        )
        report.projects_scanned = 1
        self._progress("GCP GKE Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_gcp_gke_scan(collector=None, compartment_ids=None, regions=None, asset_ids=None,
                      progress_callback=None, run_checks: bool = True) -> Dict[str, Any]:
    """Run GCP GKE scan and return results as a dict."""
    scanner = GcpGkeScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
