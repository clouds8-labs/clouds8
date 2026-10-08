"""
Clouds8 — VM Scanner
Scans OCI Compute instances across compartments and collects:
  • Public & private IP addresses (via VNIC attachments)
  • Cloud-init / user_data metadata
  • User-defined metadata & extended metadata (env vars, tags)
  • Instance shape, lifecycle state, availability domain, freeform tags
  • **Sensitive data detection** in metadata, extended metadata, and cloud-init

Uses ThreadPoolExecutor for parallel compartment + VNIC scanning.
"""

import base64
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10  # Parallel OCI API threads


# ---------------------------------------------------------------------------
# Sensitive-data detection patterns for metadata scanning
# ---------------------------------------------------------------------------
METADATA_PATTERNS = [
    # ── AWS ────────────────────────────────────────────────────────────────
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID", "critical"),
    (re.compile(r'(?:aws_secret_access_key|secret_access_key)'
                r'\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', re.IGNORECASE),
     "AWS Secret Access Key", "critical"),

    # ── Private Keys ──────────────────────────────────────────────────────
    (re.compile(r'-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
     "Private Key (PEM)", "critical"),

    # ── OCI ────────────────────────────────────────────────────────────────
    (re.compile(r'(?:key_file|private_key_path)\s*[=:]\s*["\']?[^\s"\',}]+',
                re.IGNORECASE),
     "OCI Private Key Path", "high"),
    (re.compile(r'(?:fingerprint)\s*[=:]\s*["\']?'
                r'[0-9a-f]{2}(?::[0-9a-f]{2}){15}', re.IGNORECASE),
     "OCI API Key Fingerprint", "medium"),

    # ── Generic Passwords / Secrets / Tokens ───────────────────────────────
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?'
                r'([^\s"\',;}{]{8,})', re.IGNORECASE),
     "Password in Metadata", "critical"),
    (re.compile(r'(?:secret|secret_key|client_secret)\s*[=:]\s*["\']?'
                r'([^\s"\',;}{]{8,})', re.IGNORECASE),
     "Secret / Secret Key", "critical"),
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?'
                r'([^\s"\',;}{]{8,})', re.IGNORECASE),
     "API Key", "high"),
    (re.compile(r'(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)'
                r'\s*[=:]\s*["\']?([^\s"\',;}{]{20,})', re.IGNORECASE),
     "Auth / Access Token", "critical"),

    # ── Database Connection Strings ────────────────────────────────────────
    (re.compile(r'(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)'
                r'://[^\s"\',;}{]+', re.IGNORECASE),
     "Database Connection String", "critical"),

    # ── Bearer / Basic Auth ────────────────────────────────────────────────
    (re.compile(r'Authorization\s*[=:]\s*["\']?Bearer\s+[A-Za-z0-9\-._~+/]+=*',
                re.IGNORECASE),
     "Bearer Token (hardcoded)", "high"),

    # ── JWT ────────────────────────────────────────────────────────────────
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
     "JSON Web Token (JWT)", "high"),

    # ── Generic high-entropy (hex keys ≥ 32 chars) ─────────────────────────
    (re.compile(r'(?:key|token|secret|password)\s*[=:]\s*["\']?'
                r'[0-9a-fA-F]{32,}', re.IGNORECASE),
     "Hex Secret/Key (≥32 chars)", "medium"),
]

# Metadata key names that indicate sensitive information (key-level check)
SENSITIVE_KEY_PATTERNS = [
    (re.compile(r'(?:password|passwd|pwd)', re.IGNORECASE), "Password Key", "critical"),
    (re.compile(r'(?:secret|secret_key|client_secret)', re.IGNORECASE), "Secret Key", "critical"),
    (re.compile(r'(?:api[_-]?key|apikey)', re.IGNORECASE), "API Key", "high"),
    (re.compile(r'(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)', re.IGNORECASE), "Token Key", "high"),
    (re.compile(r'(?:private[_-]?key|priv[_-]?key)', re.IGNORECASE), "Private Key Ref", "critical"),
    (re.compile(r'(?:connection[_-]?string|conn[_-]?str|db[_-]?url)', re.IGNORECASE), "Connection String Key", "critical"),
    (re.compile(r'(?:credentials?|cred)', re.IGNORECASE), "Credential Key", "critical"),
]


def _redact(value: str, max_len: int = 40) -> str:
    """Redact a value for display: show first 6 and last 4 chars."""
    s = str(value).strip()
    if len(s) <= 12:
        return s[:4] + "****"
    return s[:6] + "****" + s[-4:]


def _redact_metadata_dict(meta: Dict[str, Any]) -> Dict[str, str]:
    """Redacted copy of a metadata dict, safe to persist/display generally
    (e.g. in a scan report or the asset's Inventory properties). Reuses the
    exact same detection patterns _scan_metadata_dict uses to generate
    findings, but returns a sanitized copy of the whole dict instead of
    Finding records - sensitive keys/values are masked, everything else
    passes through unchanged. This is the only place raw metadata values
    should ever leave this module; VMDetail.to_dict() is the sole caller."""
    safe: Dict[str, str] = {}
    for key, value in (meta or {}).items():
        val_str = str(value)
        key_is_sensitive = any(pat.search(key) for pat, _label, _sev in SENSITIVE_KEY_PATTERNS)
        value_is_sensitive = any(pat.search(val_str) for pat, _label, _sev in METADATA_PATTERNS)
        safe[key] = _redact(val_str) if (key_is_sensitive or value_is_sensitive) else val_str
    return safe


def _redact_cloud_init_text(cloud_init: Optional[str]) -> Optional[str]:
    """Redacted copy of cloud-init text, line by line - same rationale as
    _redact_metadata_dict above. Masks only the matched secret span within
    a line (not the whole line), preserving surrounding context like the
    variable name, the same way findings' snippets already do."""
    if not cloud_init:
        return cloud_init
    out_lines = []
    for line in cloud_init.splitlines():
        redacted_line = line
        for pat, _label, _sev in METADATA_PATTERNS:
            redacted_line = pat.sub(lambda m: _redact(m.group(0)), redacted_line)
        out_lines.append(redacted_line)
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class MetadataFinding:
    """A single sensitive finding from VM metadata scanning."""
    source: str              # "metadata", "extended_metadata", or "cloud_init"
    key: Optional[str]       # metadata key (None for cloud-init content)
    finding_type: str        # human label
    severity: str            # critical, high, medium, low
    snippet: Optional[str] = None  # redacted value snippet
    detection: str = "value"  # "key" = key name matched, "value" = value content matched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "key": self.key,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "snippet": self.snippet,
            "detection": self.detection,
        }


@dataclass
class VMDetail:
    """Full details for a single compute instance."""
    instance_id: str
    display_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    shape: str
    availability_domain: str
    region: str
    time_created: str
    # Networking
    public_ips: List[str] = field(default_factory=list)
    private_ips: List[str] = field(default_factory=list)
    vnic_names: List[str] = field(default_factory=list)
    subnet_ids: List[str] = field(default_factory=list)
    # Cloud-init
    cloud_init_data: Optional[str] = None          # decoded user_data
    cloud_init_truncated: bool = False
    # User metadata & extended metadata
    user_metadata: Dict[str, str] = field(default_factory=dict)
    extended_metadata: Dict[str, Any] = field(default_factory=dict)
    # Tags
    freeform_tags: Dict[str, str] = field(default_factory=dict)
    defined_tags: Dict[str, Any] = field(default_factory=dict)
    # Agent
    agent_monitoring: Optional[bool] = None
    legacy_imds_disabled: Optional[bool] = None
    # Sensitive data findings from metadata scanning
    metadata_findings: List[MetadataFinding] = field(default_factory=list)

    @property
    def sensitive_count(self) -> int:
        return len(self.metadata_findings)

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity == "critical" for f in self.metadata_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "display_name": self.display_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "shape": self.shape,
            "availability_domain": self.availability_domain,
            "region": self.region,
            "time_created": self.time_created,
            "public_ips": self.public_ips,
            "private_ips": self.private_ips,
            "vnic_names": self.vnic_names,
            "subnet_ids": self.subnet_ids,
            # Redacted, not raw - this dict is what reaches scan_reports,
            # findings.py, and ultimately the Inventory UI. The in-memory
            # VMDetail fields stay raw (scanning needs them), but nothing
            # outside this module should ever see unredacted values.
            "cloud_init_data": _redact_cloud_init_text(self.cloud_init_data),
            "cloud_init_truncated": self.cloud_init_truncated,
            "user_metadata": _redact_metadata_dict(self.user_metadata),
            "extended_metadata": _redact_metadata_dict(self.extended_metadata),
            "freeform_tags": self.freeform_tags,
            "defined_tags": self.defined_tags,
            "agent_monitoring": self.agent_monitoring,
            "legacy_imds_disabled": self.legacy_imds_disabled,
            "metadata_findings": [f.to_dict() for f in self.metadata_findings],
            "sensitive_count": self.sensitive_count,
            "has_critical_findings": self.has_critical_findings,
        }


@dataclass
class VMScanReport:
    """Full VM scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_vms: int = 0
    running_vms: int = 0
    stopped_vms: int = 0
    vms_with_public_ip: int = 0
    vms_with_cloud_init: int = 0
    compartments_scanned: int = 0
    region: str = ""
    # Sensitive data summary
    total_metadata_findings: int = 0
    critical_metadata_findings: int = 0
    vms_with_findings: int = 0
    vms: List[VMDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_vms": self.total_vms,
            "running_vms": self.running_vms,
            "stopped_vms": self.stopped_vms,
            "vms_with_public_ip": self.vms_with_public_ip,
            "vms_with_cloud_init": self.vms_with_cloud_init,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "total_metadata_findings": self.total_metadata_findings,
            "critical_metadata_findings": self.critical_metadata_findings,
            "vms_with_findings": self.vms_with_findings,
            "vms": [v.to_dict() for v in self.vms],
        }


# ---------------------------------------------------------------------------
# VM Scanner
# ---------------------------------------------------------------------------
class VMScanner:
    """
    Scans OCI Compute instances across compartments and collects
    detailed networking, metadata, and cloud-init information.
    Also scans metadata/extended_metadata/cloud-init for sensitive data.
    """

    CLOUD_INIT_MAX_CHARS = 4096  # Truncate large cloud-init to keep report lean

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

    # ------------------------------------------------------------------
    # Sensitive data scanning helpers
    # ------------------------------------------------------------------
    def _scan_metadata_dict(self, meta: Dict[str, Any], source: str,
                            vm: VMDetail):
        """Scan a metadata dictionary for sensitive keys & values."""
        if not meta:
            return
        for key, value in meta.items():
            val_str = str(value)

            # 1) Check key name for sensitive patterns
            for pat, label, severity in SENSITIVE_KEY_PATTERNS:
                if pat.search(key):
                    vm.metadata_findings.append(MetadataFinding(
                        source=source,
                        key=key,
                        finding_type=label,
                        severity=severity,
                        snippet=f"{key}={_redact(val_str)}",
                        detection="key",
                    ))
                    break  # one key match is enough

            # 2) Check value content for secret patterns
            
            # Intercept Vault OCIDs and generate a reference instead of a finding
            vault_match = re.search(r'(ocid1\.vault(?:secret)?\.oc1\.[A-Za-z0-9\-.]+\.[A-Za-z0-9]+)', val_str, re.IGNORECASE)
            if vault_match:
                vm.metadata_findings.append(MetadataFinding(
                    source=source,
                    key=key,
                    finding_type="Vault Reference",
                    severity="info",
                    snippet=vault_match.group(1), # Explicitly pass full OCID for UI linking
                    detection="value",
                ))
                continue
            
            found_labels: set = set()
            for pat, label, severity in METADATA_PATTERNS:
                if label in found_labels:
                    continue
                match = pat.search(val_str)
                if match:
                    found_labels.add(label)
                    matched_text = match.group(0)
                    vm.metadata_findings.append(MetadataFinding(
                        source=source,
                        key=key,
                        finding_type=label,
                        severity=severity,
                        snippet=f"{key}=…{_redact(matched_text)}…",
                        detection="value",
                    ))

    def _scan_cloud_init(self, cloud_init: str, vm: VMDetail):
        """Scan cloud-init data for embedded secrets."""
        if not cloud_init:
            return
        found_labels: set = set()
        # Metadata patterns loop
        for line_no, line in enumerate(cloud_init.splitlines(), start=1):
            # Intercept Vault OCIDs
            vault_match = re.search(r'(ocid1\.vault(?:secret)?\.oc1\.[A-Za-z0-9\-.]+\.[A-Za-z0-9]+)', line, re.IGNORECASE)
            if vault_match:
                vm.metadata_findings.append(MetadataFinding(
                    source="cloud_init",
                    key=None,
                    finding_type="Vault Reference",
                    severity="info",
                    snippet=vault_match.group(1),
                    detection="value",
                ))
                continue
            
            for pat, label, severity in METADATA_PATTERNS:
                if label in found_labels:
                    continue
                match = pat.search(line)
                if match:
                    found_labels.add(label)
                    matched_text = match.group(0)
                    vm.metadata_findings.append(MetadataFinding(
                        source="cloud_init",
                        key=None,
                        finding_type=label,
                        severity=severity,
                        snippet=f"L{line_no}: …{_redact(matched_text)}…",
                        detection="value",
                    ))

    def _scan_vm_metadata(self, vm: VMDetail):
        """Run all sensitive data scans on a single VM's metadata."""
        self._scan_metadata_dict(vm.user_metadata, "metadata", vm)
        self._scan_metadata_dict(vm.extended_metadata, "extended_metadata", vm)
        self._scan_cloud_init(vm.cloud_init_data, vm)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, compartment_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None,
            asset_ids: Optional[List[str]] = None) -> VMScanReport:
        """
        Scan VMs across compartments.
        Args:
            compartment_ids: optional list of compartment OCIDs to restrict scan.
                             If None/empty, scans all ACTIVE compartments.
            regions: optional list of region names to restrict scan to.
            asset_ids: optional list of instance OCIDs to restrict scan to.
        """
        report = VMScanReport()

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "error"
            self._progress("VM Scanner: OCI configuration missing. Cannot run scan.")

        report.completed_at = datetime.now()

        # Tally
        report.total_vms = len(report.vms)
        report.running_vms = sum(1 for v in report.vms if v.lifecycle_state == "RUNNING")
        report.stopped_vms = sum(1 for v in report.vms if v.lifecycle_state == "STOPPED")
        report.vms_with_public_ip = sum(1 for v in report.vms if v.public_ips)
        report.vms_with_cloud_init = sum(1 for v in report.vms if v.cloud_init_data)

        # Metadata findings tallies
        report.total_metadata_findings = sum(v.sensitive_count for v in report.vms)
        report.critical_metadata_findings = sum(
            sum(1 for f in v.metadata_findings if f.severity == "critical")
            for v in report.vms
        )
        report.vms_with_findings = sum(
            1 for v in report.vms if v.sensitive_count > 0
        )

        return report

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------
    def _run_live(self, report: VMScanReport,
                  compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        """Scan live OCI instances across all subscribed regions."""
        try:
            self._progress("VM Scanner: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-phoenix-1")]
            if regions:
                subscribed_regions = [r for r in subscribed_regions if r in regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            # Load compartments
            if not self.collector.compartments:
                self.collector.compartments = (
                    self.collector.collect_compartment_details()
                )

            active_comps = [
                c for c in self.collector.compartments
                if c.get("lifecycle_state") == "ACTIVE"
            ]

            # Filter if specific compartments requested
            if compartment_ids:
                active_comps = [
                    c for c in active_comps
                    if c["id"] in compartment_ids
                ]

            report.compartments_scanned = len(active_comps)
            
            all_vms = []

            for region in subscribed_regions:
                self._progress(f"VM Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)

                compute = self.collector.get_client("compute")
                network = self.collector.get_client("network")

                if not compute or not network:
                    self._progress(f"VM Scanner: Compute or Network client not available in {region}")
                    continue

                self._progress(
                    f"VM Scanner [{region}]: Scanning {len(active_comps)} compartments "
                    f"in parallel ({_MAX_WORKERS} threads)..."
                )

                # ── Step 1: List instances from all compartments in parallel ──
                all_instances = []  # (oci_instance_obj, cid, cname)

                def _list_instances(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    try:
                        # List ALL lifecycle states (RUNNING, STOPPED, etc.)
                        insts = compute.list_instances(cid).data
                        filtered = [(inst, cid, cname) for inst in insts
                                    if inst.lifecycle_state not in ("TERMINATED", "TERMINATING")]
                        if asset_ids:
                            filtered = [t for t in filtered if t[0].id in asset_ids]
                        return filtered
                    except Exception as e:
                        logger.debug("VM Scanner: error listing instances in %s: %s", cname, e)
                        return []

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_list_instances, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_instances.extend(f.result())
                        except Exception:
                            pass

                self._progress(f"VM Scanner [{region}]: Found {len(all_instances)} VMs, collecting details...")

                # ── Step 2: Build VMDetail for each instance ──
                vm_details = []

                for inst, cid, cname in all_instances:
                    vm = VMDetail(
                        instance_id=inst.id,
                        display_name=inst.display_name or "(unnamed)",
                        compartment_name=cname,
                        compartment_id=cid,
                        lifecycle_state=inst.lifecycle_state,
                        shape=getattr(inst, "shape", ""),
                        availability_domain=getattr(inst, "availability_domain", ""),
                        region=region,  # Set correct region being scanned
                        time_created=str(getattr(inst, "time_created", "")),
                    )

                    # User metadata (key-value pairs set during launch)
                    meta = getattr(inst, "metadata", None)
                    if meta and isinstance(meta, dict):
                        # Extract cloud-init (user_data is base64-encoded)
                        user_data = meta.get("user_data")
                        if user_data:
                            try:
                                decoded = base64.b64decode(user_data).decode("utf-8", errors="replace")
                                if len(decoded) > self.CLOUD_INIT_MAX_CHARS:
                                    vm.cloud_init_data = decoded[:self.CLOUD_INIT_MAX_CHARS]
                                    vm.cloud_init_truncated = True
                                else:
                                    vm.cloud_init_data = decoded
                            except Exception:
                                vm.cloud_init_data = "(failed to decode user_data)"

                        # Store remaining user metadata (ssh_authorized_keys, custom env, etc.)
                        vm.user_metadata = {
                            k: v for k, v in meta.items()
                            if k != "user_data"
                        }

                    # Extended metadata
                    ext_meta = getattr(inst, "extended_metadata", None)
                    if ext_meta and isinstance(ext_meta, dict):
                        vm.extended_metadata = ext_meta

                    # Tags
                    ft = getattr(inst, "freeform_tags", None)
                    if ft and isinstance(ft, dict):
                        vm.freeform_tags = ft
                    dt = getattr(inst, "defined_tags", None)
                    if dt and isinstance(dt, dict):
                        vm.defined_tags = dt

                    # Agent config
                    agent_cfg = getattr(inst, "agent_config", None)
                    if agent_cfg:
                        vm.agent_monitoring = not getattr(
                            agent_cfg, "is_monitoring_disabled", False
                        )
                    inst_opts = getattr(inst, "instance_options", None)
                    if inst_opts:
                        vm.legacy_imds_disabled = getattr(
                            inst_opts, "are_legacy_imds_endpoints_disabled", None
                        )

                    # ── Scan metadata for sensitive data ──
                    if self.run_checks:
                        self._scan_vm_metadata(vm)

                    vm_details.append(vm)

                # ── Step 3: Fetch VNIC IPs in parallel ──
                if vm_details:
                    self._progress(f"VM Scanner [{region}]: Fetching network details for {len(vm_details)} VMs...")

                    vnic_tasks = []  # (vm_index, vnic_attachment)
                    for idx, vm in enumerate(vm_details):
                        try:
                            attachments = compute.list_vnic_attachments(
                                vm.compartment_id, instance_id=vm.instance_id
                            ).data
                            for va in attachments:
                                if va.lifecycle_state == "ATTACHED":
                                    vnic_tasks.append((idx, va.vnic_id))
                        except Exception:
                            pass

                    def _fetch_vnic(idx, vnic_id):
                        try:
                            vnic = network.get_vnic(vnic_id).data
                            return idx, vnic
                        except Exception:
                            return idx, None

                    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                        futures = [pool.submit(_fetch_vnic, i, vid) for i, vid in vnic_tasks]
                        for f in as_completed(futures):
                            try:
                                idx, vnic = f.result()
                                if vnic is None:
                                    continue
                                vm = vm_details[idx]
                                priv = getattr(vnic, "private_ip", None)
                                pub = getattr(vnic, "public_ip", None)
                                name = getattr(vnic, "display_name", None)
                                subnet = getattr(vnic, "subnet_id", None)
                                if priv:
                                    vm.private_ips.append(priv)
                                if pub:
                                    vm.public_ips.append(pub)
                                if name:
                                    vm.vnic_names.append(name)
                                if subnet:
                                    vm.subnet_ids.append(subnet)
                            except Exception:
                                pass

                    all_vms.extend(vm_details)

            report.vms = all_vms

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress("VM Scanner: Complete!")

        except Exception as e:
            logger.error("VM Scanner live scan error: %s", e)
            self._progress(f"VM Scanner: Error — {e}")




# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_vm_scan(
    collector=None,
    compartment_ids=None,
    regions=None,
    asset_ids=None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run VM scan and return results as a dict."""
    scanner = VMScanner(collector=collector, progress_callback=progress_callback, run_checks=run_checks)
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
