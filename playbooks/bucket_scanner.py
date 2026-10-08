"""
Clouds8 — Bucket Scanner (Unified: Access + Sensitive Data)
Scans OCI Object Storage buckets across compartments and reports:
  • Public-access exposure (NoPublicAccess / ObjectRead / ObjectReadWithoutList)
  • Encryption, versioning and lifecycle posture
  • Sensitive data findings — credentials, keys, PCI data found in objects

Uses ThreadPoolExecutor for parallel compartment + bucket-detail scanning.
"""

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10  # Parallel OCI API threads
_CONTENT_WORKERS = 8  # Parallel content downloads per bucket

# Maximum object size to download for content scanning (MB)
_MAX_CONTENT_SIZE_MB = 50

# Binary extensions to skip for content scanning (not readable as text)
BINARY_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv",
    ".mp3", ".wav", ".ogg", ".flac", ".aac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".bin", ".iso", ".dmg", ".deb", ".rpm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".class", ".pyc", ".pyo", ".o", ".so", ".dylib", ".a",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".parquet", ".avro", ".orc",
    ".sqlite", ".db",
}

# ---------------------------------------------------------------------------
# Sensitive-data detection patterns
# ---------------------------------------------------------------------------

# Content-based secret patterns: (compiled regex, label, severity)
CONTENT_PATTERNS = [
    # ── AWS ────────────────────────────────────────────────────────────────
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID", "critical"),
    (re.compile(r'(?:aws_secret_access_key|secret_access_key)'
                r'\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', re.IGNORECASE),
     "AWS Secret Access Key", "critical"),

    # ── Private Keys ──────────────────────────────────────────────────────
    (re.compile(r'-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
     "Private Key (PEM)", "critical"),
    (re.compile(r'-----BEGIN\s+CERTIFICATE-----'),
     "X.509 Certificate", "medium"),

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
     "Password in Config", "high"),
    (re.compile(r'(?:secret|secret_key|client_secret)\s*[=:]\s*["\']?'
                r'([^\s"\',;}{]{8,})', re.IGNORECASE),
     "Secret / Secret Key", "high"),
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?'
                r'([^\s"\',;}{]{8,})', re.IGNORECASE),
     "API Key", "high"),
    (re.compile(r'(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)'
                r'\s*[=:]\s*["\']?([^\s"\',;}{]{20,})', re.IGNORECASE),
     "Auth / Access Token", "high"),

    # ── Database Connection Strings ────────────────────────────────────────
    (re.compile(r'(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)'
                r'://[^\s"\',;}{]+', re.IGNORECASE),
     "Database Connection String", "critical"),

    # ── Bearer / Basic Auth ────────────────────────────────────────────────
    (re.compile(r'Authorization\s*[=:]\s*["\']?Bearer\s+[A-Za-z0-9\-._~+/]+=*',
                re.IGNORECASE),
     "Bearer Token (hardcoded)", "high"),
    (re.compile(r'Authorization\s*[=:]\s*["\']?Basic\s+[A-Za-z0-9+/]+=*',
                re.IGNORECASE),
     "Basic Auth (hardcoded)", "high"),

    # ── JWT ────────────────────────────────────────────────────────────────
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
     "JSON Web Token (JWT)", "high"),

    # ── Slack ──────────────────────────────────────────────────────────────
    (re.compile(r'xox[bpsorta]-[0-9]{10,}-[A-Za-z0-9-]+'),
     "Slack Token", "high"),

    # ── GitHub ─────────────────────────────────────────────────────────────
    (re.compile(r'gh[pous]_[A-Za-z0-9_]{36,}'),
     "GitHub Personal Access Token", "high"),

    # ── GCP Service Account ────────────────────────────────────────────────
    (re.compile(r'"type"\s*:\s*"service_account"'),
     "GCP Service Account JSON", "critical"),

    # ── PCI / Card Data ────────────────────────────────────────────────────
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b'),
     "Visa Card Number", "critical"),
    (re.compile(r'\b(?:5[1-5][0-9]{14})\b'),
     "MasterCard Number", "critical"),
    (re.compile(r'\b(?:3[47][0-9]{13})\b'),
     "Amex Card Number", "critical"),
    (re.compile(r'\b(?:[0-9]{3}-[0-9]{2}-[0-9]{4})\b'),
     "US SSN Pattern", "critical"),

    # ── Generic high-entropy (hex keys ≥ 32 chars) ─────────────────────────
    (re.compile(r'(?:key|token|secret|password)\s*[=:]\s*["\']?'
                r'[0-9a-fA-F]{32,}', re.IGNORECASE),
     "Hex Secret/Key (≥32 chars)", "medium"),
]

# Filename-pattern matching: (compiled regex, human-readable label, severity)
SENSITIVE_FILENAME_PATTERNS = [
    # Private keys and certificates
    (re.compile(r'.*\.pem$', re.IGNORECASE), "PEM Private Key / Certificate", "critical"),
    (re.compile(r'.*\.key$', re.IGNORECASE), "Private Key File", "critical"),
    (re.compile(r'.*\.ppk$', re.IGNORECASE), "PuTTY Private Key", "critical"),
    (re.compile(r'.*\.pfx$', re.IGNORECASE), "PKCS#12 Certificate", "high"),
    (re.compile(r'.*\.p12$', re.IGNORECASE), "PKCS#12 Certificate", "high"),
    (re.compile(r'.*id_rsa.*', re.IGNORECASE), "SSH Private Key", "critical"),
    (re.compile(r'.*id_dsa.*', re.IGNORECASE), "DSA Private Key", "critical"),
    (re.compile(r'.*id_ecdsa.*', re.IGNORECASE), "ECDSA Private Key", "critical"),
    (re.compile(r'.*id_ed25519.*', re.IGNORECASE), "ED25519 Private Key", "critical"),

    # Credential and config files
    (re.compile(r'.*\.env$', re.IGNORECASE), "Environment Variables File", "high"),
    (re.compile(r'.*\.env\..+', re.IGNORECASE), "Environment Variables File", "high"),
    (re.compile(r'.*credentials$', re.IGNORECASE), "Credentials File", "critical"),
    (re.compile(r'.*\.htpasswd$', re.IGNORECASE), "Apache Password File", "high"),
    (re.compile(r'.*\.netrc$', re.IGNORECASE), "Netrc Credentials", "high"),
    (re.compile(r'.*\.pgpass$', re.IGNORECASE), "PostgreSQL Password File", "critical"),
    (re.compile(r'.*\.my\.cnf$', re.IGNORECASE), "MySQL Config (passwords)", "high"),

    # Cloud provider configs
    (re.compile(r'.*oci.*config.*', re.IGNORECASE), "OCI Config File", "high"),
    (re.compile(r'.*aws.*credentials.*', re.IGNORECASE), "AWS Credentials File", "critical"),
    (re.compile(r'.*gcloud.*credentials.*', re.IGNORECASE), "GCP Credentials File", "critical"),
    (re.compile(r'.*service[_-]?account.*\.json$', re.IGNORECASE), "Service Account Key (JSON)", "critical"),

    # Terraform / IaC state files
    (re.compile(r'.*terraform\.tfstate.*', re.IGNORECASE), "Terraform State (secrets)", "critical"),
    (re.compile(r'.*terraform\.tfvars.*', re.IGNORECASE), "Terraform Variables (secrets)", "high"),
    (re.compile(r'.*\.tfvars$', re.IGNORECASE), "Terraform Variables", "high"),

    # Secrets / Vault exports
    (re.compile(r'.*secret.*', re.IGNORECASE), "File with 'secret' in name", "high"),
    (re.compile(r'.*password.*', re.IGNORECASE), "File with 'password' in name", "high"),
    (re.compile(r'.*token.*', re.IGNORECASE), "File with 'token' in name", "medium"),
    (re.compile(r'.*api[_-]?key.*', re.IGNORECASE), "File with 'api_key' in name", "high"),
    (re.compile(r'.*\.kdbx?$', re.IGNORECASE), "KeePass Database", "critical"),
    (re.compile(r'.*\.jks$', re.IGNORECASE), "Java Keystore", "high"),

    # Database dumps
    (re.compile(r'.*\.sql$', re.IGNORECASE), "SQL Dump (sensitive data)", "high"),
    (re.compile(r'.*\.bak$', re.IGNORECASE), "Backup File", "medium"),
    (re.compile(r'.*\.dump$', re.IGNORECASE), "Database Dump", "high"),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class SensitiveFinding:
    """A single secret/sensitive file found in a bucket."""
    object_name: str
    finding_type: str          # human label
    severity: str              # critical, high, medium, low
    source: str = "filename"   # "filename" or "content"
    snippet: Optional[str] = None  # redacted context for content findings
    file_size: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_name": self.object_name,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "source": self.source,
            "snippet": self.snippet,
            "file_size": self.file_size,
        }


@dataclass
class BucketDetail:
    """Full details for a single Object Storage bucket."""
    bucket_name: str
    namespace: str
    compartment_name: str
    compartment_id: str
    public_access_type: str          # NoPublicAccess | ObjectRead | ObjectReadWithoutList
    storage_tier: str                 # Standard | Archive | InfrequentAccess
    versioning: str                   # Enabled | Suspended | Disabled
    time_created: str
    region: str
    approximate_count: Optional[int] = None
    approximate_size: Optional[int] = None
    kms_key_id: Optional[str] = None  # Customer-managed encryption key
    replication_enabled: bool = False
    object_lifecycle_policy_etag: Optional[str] = None
    freeform_tags: Dict[str, str] = field(default_factory=dict)
    defined_tags: Dict[str, Any] = field(default_factory=dict)
    # ── Sensitive data findings ──
    sensitive_findings: List[SensitiveFinding] = field(default_factory=list)

    # Derived convenience flags
    @property
    def is_public(self) -> bool:
        return self.public_access_type != "NoPublicAccess"

    @property
    def sensitive_count(self) -> int:
        return len(self.sensitive_findings)

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity == "critical" for f in self.sensitive_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "namespace": self.namespace,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "public_access_type": self.public_access_type,
            "is_public": self.is_public,
            "storage_tier": self.storage_tier,
            "versioning": self.versioning,
            "time_created": self.time_created,
            "region": self.region,
            "approximate_count": self.approximate_count,
            "approximate_size": self.approximate_size,
            "kms_key_id": self.kms_key_id,
            "replication_enabled": self.replication_enabled,
            "object_lifecycle_policy_etag": self.object_lifecycle_policy_etag,
            "freeform_tags": self.freeform_tags,
            "defined_tags": self.defined_tags,
            "sensitive_findings": [f.to_dict() for f in self.sensitive_findings],
            "sensitive_count": self.sensitive_count,
            "has_critical_findings": self.has_critical_findings,
        }


@dataclass
class BucketScanReport:
    """Full bucket scan report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_buckets: int = 0
    public_buckets: int = 0
    private_buckets: int = 0
    encrypted_buckets: int = 0      # buckets with customer-managed KMS keys
    versioned_buckets: int = 0
    compartments_scanned: int = 0
    region: str = ""
    # ── Sensitive data summary ──
    total_sensitive_findings: int = 0
    critical_findings: int = 0
    buckets_with_findings: int = 0
    objects_scanned: int = 0
    objects_content_scanned: int = 0
    buckets: List[BucketDetail] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_buckets": self.total_buckets,
            "public_buckets": self.public_buckets,
            "private_buckets": self.private_buckets,
            "encrypted_buckets": self.encrypted_buckets,
            "versioned_buckets": self.versioned_buckets,
            "compartments_scanned": self.compartments_scanned,
            "region": self.region,
            "total_sensitive_findings": self.total_sensitive_findings,
            "critical_findings": self.critical_findings,
            "buckets_with_findings": self.buckets_with_findings,
            "objects_scanned": self.objects_scanned,
            "objects_content_scanned": self.objects_content_scanned,
            "buckets": [b.to_dict() for b in self.buckets],
        }


# ---------------------------------------------------------------------------
# Bucket Scanner
# ---------------------------------------------------------------------------
class BucketScanner:
    """
    Scans OCI Object Storage buckets across compartments and collects
    detailed access, encryption, versioning, lifecycle information,
    AND sensitive data findings (credentials, keys, PCI data).
    """

    def __init__(self, collector=None, progress_callback=None, run_checks: bool = True):
        self.collector = collector
        self.progress_callback = progress_callback
        self.run_checks = run_checks
        import threading
        self._lock = threading.Lock()

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
            asset_ids: Optional[List[str]] = None) -> BucketScanReport:
        """
        Scan buckets across compartments.
        Args:
            compartment_ids: optional list of compartment OCIDs to restrict scan.
                             If None/empty, scans all ACTIVE compartments.
        """
        report = BucketScanReport()

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids, regions, asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()

        # Tally
        report.total_buckets = len(report.buckets)
        report.public_buckets = sum(1 for b in report.buckets if b.is_public)
        report.private_buckets = report.total_buckets - report.public_buckets
        report.encrypted_buckets = sum(1 for b in report.buckets if b.kms_key_id)
        report.versioned_buckets = sum(
            1 for b in report.buckets if b.versioning == "Enabled"
        )
        # Sensitive data tallies
        report.total_sensitive_findings = sum(
            b.sensitive_count for b in report.buckets
        )
        report.critical_findings = sum(
            sum(1 for f in b.sensitive_findings if f.severity == "critical")
            for b in report.buckets
        )
        report.buckets_with_findings = sum(
            1 for b in report.buckets if b.sensitive_count > 0
        )

        return report

    # ------------------------------------------------------------------
    # Sensitive-data scanning helpers
    # ------------------------------------------------------------------
    def _scan_bucket_objects(self, os_client, namespace: str,
                            bucket: BucketDetail, report: BucketScanReport):
        """List objects in a bucket and scan for sensitive data."""
        try:
            all_objects = []
            next_start = None
            while True:
                kwargs = {
                    "namespace_name": namespace,
                    "bucket_name": bucket.bucket_name,
                }
                if next_start:
                    kwargs["start"] = next_start
                resp = os_client.list_objects(**kwargs)
                all_objects.extend(resp.data.objects)
                next_start = resp.data.next_start_with
                if not next_start:
                    break

            with self._lock:
                report.objects_scanned += len(all_objects)

            if not all_objects:
                return

            # 1) Filename-based pattern match (fast — no download needed)
            for obj in all_objects:
                self._check_filename(obj.name, getattr(obj, "size", None), bucket)

            # 2) Content scanning — download non-binary files in parallel
            eligible = []
            for obj in all_objects:
                obj_size = getattr(obj, "size", None) or 0
                if obj_size == 0:
                    continue
                if obj_size > _MAX_CONTENT_SIZE_MB * 1024 * 1024:
                    continue
                obj_ext = os.path.splitext(obj.name)[1].lower()
                if obj_ext in BINARY_EXTENSIONS:
                    continue
                eligible.append(obj)

            if eligible:
                def _scan_one(obj):
                    self._scan_object_content(
                        os_client, namespace, bucket, obj.name,
                        getattr(obj, "size", 0), report,
                    )

                with ThreadPoolExecutor(max_workers=_CONTENT_WORKERS) as pool:
                    list(pool.map(_scan_one, eligible))

        except Exception as e:
            logger.debug(
                "Bucket Scanner: error scanning objects in %s: %s",
                bucket.bucket_name, e,
            )

    def _check_filename(self, object_name: str, file_size: Optional[int],
                        bucket: BucketDetail):
        """Test an object name against all sensitive filename patterns."""
        for pattern, label, severity in SENSITIVE_FILENAME_PATTERNS:
            if pattern.match(object_name):
                with self._lock:
                    bucket.sensitive_findings.append(
                        SensitiveFinding(
                            object_name=object_name,
                            finding_type=label,
                            severity=severity,
                            source="filename",
                            file_size=file_size,
                        )
                    )
                break  # one match per filename is enough

    def _scan_object_content(self, client, namespace: str,
                             bucket: BucketDetail, object_name: str,
                             file_size: int, report: BucketScanReport):
        """Download an object and scan its content for secrets / PCI data."""
        try:
            response = client.get_object(
                namespace_name=namespace,
                bucket_name=bucket.bucket_name,
                object_name=object_name,
            )
            raw_bytes = response.data.content
            if not raw_bytes:
                return

            # Try to decode as text — skip binary files
            try:
                text = raw_bytes.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                try:
                    text = raw_bytes.decode("latin-1")
                except Exception:
                    return  # truly binary

            with self._lock:
                report.objects_content_scanned += 1

            found_labels: set = set()
            for line_no, line in enumerate(text.splitlines(), start=1):
                for pattern, label, severity in CONTENT_PATTERNS:
                    if label in found_labels:
                        continue

                    match = pattern.search(line)
                    if match:
                        found_labels.add(label)
                        # Build redacted snippet
                        snippet_start = max(0, match.start() - 10)
                        snippet_end = min(len(line), match.end() + 10)
                        raw_snip = line[snippet_start:snippet_end]
                        matched_text = match.group(0)
                        if len(matched_text) > 12:
                            redacted = matched_text[:6] + "****" + matched_text[-4:]
                        else:
                            redacted = matched_text[:4] + "****"
                        display_snippet = (
                            f"L{line_no}: …{raw_snip.replace(matched_text, redacted)}…"
                        )
                        with self._lock:
                            bucket.sensitive_findings.append(
                                SensitiveFinding(
                                    object_name=object_name,
                                    finding_type=label,
                                    severity=severity,
                                    source="content",
                                    snippet=display_snippet,
                                    file_size=file_size,
                                )
                            )
        except Exception as e:
            logger.debug(
                "Content scan failed for %s/%s: %s",
                bucket.bucket_name, object_name, e,
            )

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------
    def _run_live(self, report: BucketScanReport,
                  compartment_ids: Optional[List[str]] = None,
                  regions: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        """Scan live OCI buckets across all subscribed regions."""
        try:
            self._progress("Bucket Scanner: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-phoenix-1")]
            if regions:
                subscribed_regions = [r for r in subscribed_regions if r in regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            # Ensure compartments are loaded
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
            
            all_bucket_details: List[BucketDetail] = []

            for region in subscribed_regions:
                self._progress(f"Bucket Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                os_client = self.collector.get_client("object_storage")
                if not os_client:
                    self._progress(f"Bucket Scanner: Object Storage client not available in {region}")
                    continue

                # Get namespace
                try:
                    namespace = os_client.get_namespace().data
                except Exception as e:
                    self._progress(f"Bucket Scanner: Failed to get namespace in {region} — {e}")
                    continue

                self._progress(
                    f"Bucket Scanner [{region}]: Scanning {len(active_comps)} compartments "
                    f"in parallel ({_MAX_WORKERS} threads)..."
                )

                # ── Step 1: List buckets from all compartments in parallel ──
                all_bucket_summaries = []  # (bucket_summary, namespace, cid, cname)

                def _list_buckets(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    try:
                        buckets = os_client.list_buckets(namespace, cid).data
                        return [(b, namespace, cid, cname) for b in buckets]
                    except Exception as e:
                        logger.debug(
                            "Bucket Scanner: error listing buckets in %s: %s",
                            cname, e,
                        )
                        return []

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_list_buckets, c) for c in active_comps]
                    for f in as_completed(futures):
                        try:
                            all_bucket_summaries.extend(f.result())
                        except Exception:
                            pass

                self._progress(
                    f"Bucket Scanner [{region}]: Found {len(all_bucket_summaries)} buckets, "
                    f"fetching access details..."
                )

                # ── Step 2: Get detailed bucket info (public_access_type, etc.) ──
                bucket_details: List[BucketDetail] = []

                def _get_bucket_detail(summary_tuple):
                    bucket_summary, ns, cid, cname = summary_tuple
                    bname = bucket_summary.name
                    try:
                        detail = os_client.get_bucket(
                            ns, bname,
                            fields=["approximateCount", "approximateSize"],
                        ).data
                        return BucketDetail(
                            bucket_name=bname,
                            namespace=ns,
                            compartment_name=cname,
                            compartment_id=cid,
                            public_access_type=getattr(
                                detail, "public_access_type", "Unknown"
                            ) or "NoPublicAccess",
                            storage_tier=getattr(
                                detail, "storage_tier", "Standard"
                            ) or "Standard",
                            versioning=getattr(
                                detail, "versioning", "Disabled"
                            ) or "Disabled",
                            time_created=str(getattr(detail, "time_created", "")),
                            region=region,
                            approximate_count=getattr(
                                detail, "approximate_count", None
                            ),
                            approximate_size=getattr(
                                detail, "approximate_size", None
                            ),
                            kms_key_id=getattr(detail, "kms_key_id", None),
                            replication_enabled=bool(
                                getattr(detail, "replication_enabled", False)
                            ),
                            object_lifecycle_policy_etag=getattr(
                                detail, "object_lifecycle_policy_etag", None
                            ),
                            freeform_tags=getattr(
                                detail, "freeform_tags", {}
                            ) or {},
                            defined_tags=getattr(
                                detail, "defined_tags", {}
                            ) or {},
                        )
                    except Exception as e:
                        logger.debug(
                            "Bucket Scanner: error getting details for %s: %s",
                            bname, e,
                        )
                        # Return a minimal record on failure
                        return BucketDetail(
                            bucket_name=bname,
                            namespace=ns,
                            compartment_name=cname,
                            compartment_id=cid,
                            public_access_type="Unknown",
                            storage_tier="Unknown",
                            versioning="Unknown",
                            time_created=str(
                                getattr(bucket_summary, "time_created", "")
                            ),
                            region=region,
                        )

                done = 0
                total_b = len(all_bucket_summaries)

                if total_b > 0:
                    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                        futures = {
                            pool.submit(_get_bucket_detail, s): s
                            for s in all_bucket_summaries
                        }
                        for f in as_completed(futures):
                            try:
                                bd = f.result()
                                if bd:
                                    bucket_details.append(bd)
                            except Exception:
                                pass
                            done += 1
                            if done % 20 == 0 or done == total_b:
                                self._progress(
                                    f"Bucket Scanner [{region}]: [{done}/{total_b}] bucket details fetched"
                                )

                # ── Step 3: Scan objects in each bucket for sensitive data ──
                if bucket_details:
                    if self.run_checks:
                        self._progress(
                            f"Bucket Scanner [{region}]: Scanning {len(bucket_details)} buckets for "
                            f"sensitive data (credentials, keys, PCI)..."
                        )
                        scan_done = 0
                        for bd in bucket_details:
                            self._scan_bucket_objects(os_client, namespace, bd, report)
                            scan_done += 1
                            if scan_done % 10 == 0 or scan_done == len(bucket_details):
                                self._progress(
                                    f"Bucket Scanner [{region}]: [{scan_done}/{len(bucket_details)}] "
                                    f"buckets content-scanned — "
                                    f"{sum(b.sensitive_count for b in bucket_details)} findings in region"
                                )

                    all_bucket_details.extend(bucket_details)

            if asset_ids:
                all_bucket_details = [b for b in all_bucket_details if b.bucket_name in asset_ids]
            report.buckets = all_bucket_details

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress("Bucket Scanner: Complete!")

        except Exception as e:
            logger.error("Bucket Scanner live scan error: %s", e)
            self._progress(f"Bucket Scanner: Error — {e}")

    # ------------------------------------------------------------------
    # Mock scanning (for demo / no OCI config)
    # ------------------------------------------------------------------
    def _run_mock(self, report: BucketScanReport):
        """Generate mock bucket data for demo."""
        self._progress("Bucket Scanner: Running in mock mode...")

        mock_buckets = [
            BucketDetail(
                bucket_name="app-logs-prod",
                namespace="exampleoraclecloud",
                compartment_name="Production",
                compartment_id="ocid1.compartment.oc1..prod",
                public_access_type="NoPublicAccess",
                storage_tier="Standard",
                versioning="Enabled",
                time_created="2025-03-15T10:30:00Z",
                region="us-ashburn-1",
                approximate_count=142500,
                approximate_size=5368709120,
                kms_key_id="ocid1.key.oc1.iad.mock001",
                freeform_tags={"Environment": "production", "Team": "platform"},
                sensitive_findings=[
                    SensitiveFinding(
                        object_name="config/database_credentials.env",
                        finding_type="Environment Variables File",
                        severity="high",
                        source="filename",
                        file_size=1024,
                    ),
                    SensitiveFinding(
                        object_name="deploy/app-config.yaml",
                        finding_type="Password in Config",
                        severity="high",
                        source="content",
                        snippet="L42: …db_password=MyS****ret!…",
                        file_size=3200,
                    ),
                ],
            ),
            BucketDetail(
                bucket_name="public-assets",
                namespace="exampleoraclecloud",
                compartment_name="Production",
                compartment_id="ocid1.compartment.oc1..prod",
                public_access_type="ObjectRead",
                storage_tier="Standard",
                versioning="Disabled",
                time_created="2025-05-01T14:00:00Z",
                region="us-ashburn-1",
                approximate_count=850,
                approximate_size=1073741824,
                freeform_tags={"Environment": "production", "Service": "cdn"},
                sensitive_findings=[
                    SensitiveFinding(
                        object_name="api/service_account_key.json",
                        finding_type="GCP Service Account JSON",
                        severity="critical",
                        source="content",
                        snippet='L1: …"type": "serv****ount"…',
                        file_size=2340,
                    ),
                    SensitiveFinding(
                        object_name="certs/server.pem",
                        finding_type="PEM Private Key / Certificate",
                        severity="critical",
                        source="filename",
                        file_size=4096,
                    ),
                    SensitiveFinding(
                        object_name="config/.env.production",
                        finding_type="Environment Variables File",
                        severity="high",
                        source="filename",
                        file_size=768,
                    ),
                    SensitiveFinding(
                        object_name="exports/customer_payments.csv",
                        finding_type="Visa Card Number",
                        severity="critical",
                        source="content",
                        snippet="L156: …card_num=4111****1111…",
                        file_size=524288,
                    ),
                ],
            ),
            BucketDetail(
                bucket_name="dev-test-data",
                namespace="exampleoraclecloud",
                compartment_name="Development",
                compartment_id="ocid1.compartment.oc1..dev",
                public_access_type="ObjectReadWithoutList",
                storage_tier="Standard",
                versioning="Disabled",
                time_created="2025-07-20T09:15:00Z",
                region="us-ashburn-1",
                approximate_count=320,
                approximate_size=268435456,
                freeform_tags={"Environment": "development"},
                sensitive_findings=[
                    SensitiveFinding(
                        object_name="deploy/id_rsa",
                        finding_type="SSH Private Key",
                        severity="critical",
                        source="filename",
                        file_size=2048,
                    ),
                    SensitiveFinding(
                        object_name="scripts/deploy.sh",
                        finding_type="AWS Access Key ID",
                        severity="critical",
                        source="content",
                        snippet="L18: …AKIA2O****XMPL…",
                        file_size=4500,
                    ),
                    SensitiveFinding(
                        object_name="terraform/terraform.tfstate",
                        finding_type="Terraform State (secrets)",
                        severity="critical",
                        source="filename",
                        file_size=31457280,
                    ),
                ],
            ),
            BucketDetail(
                bucket_name="backup-archive",
                namespace="exampleoraclecloud",
                compartment_name="Operations",
                compartment_id="ocid1.compartment.oc1..ops",
                public_access_type="NoPublicAccess",
                storage_tier="Archive",
                versioning="Enabled",
                time_created="2024-12-01T08:00:00Z",
                region="us-ashburn-1",
                approximate_count=98000,
                approximate_size=107374182400,
                kms_key_id="ocid1.key.oc1.iad.mock002",
                replication_enabled=True,
                freeform_tags={"Environment": "production", "Purpose": "backup"},
                sensitive_findings=[
                    SensitiveFinding(
                        object_name="backups/users_dump.sql",
                        finding_type="SQL Dump (sensitive data)",
                        severity="high",
                        source="filename",
                        file_size=52428800,
                    ),
                ],
            ),
            BucketDetail(
                bucket_name="internal-reports",
                namespace="exampleoraclecloud",
                compartment_name="Staging",
                compartment_id="ocid1.compartment.oc1..staging",
                public_access_type="NoPublicAccess",
                storage_tier="InfrequentAccess",
                versioning="Disabled",
                time_created="2025-09-10T11:00:00Z",
                region="us-ashburn-1",
                approximate_count=1200,
                approximate_size=536870912,
                freeform_tags={"Environment": "staging"},
                sensitive_findings=[],
            ),
        ]

        if not self.run_checks:
            for b in mock_buckets:
                b.sensitive_findings = []

        report.buckets = mock_buckets
        report.compartments_scanned = 4
        report.objects_scanned = 650
        report.objects_content_scanned = 180 if self.run_checks else 0
        self._progress("Bucket Scanner: Complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_bucket_scan(
    collector=None,
    compartment_ids=None,
    regions=None,
    asset_ids=None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run bucket scan and return results as a dict."""
    scanner = BucketScanner(
        collector=collector, progress_callback=progress_callback, run_checks=run_checks
    )
    report = scanner.run(compartment_ids=compartment_ids, regions=regions, asset_ids=asset_ids)
    return report.to_dict()
