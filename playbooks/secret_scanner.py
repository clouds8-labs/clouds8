import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_OBJECT_SIZE_MB = 50          # Skip files larger than this (MB)
MAX_DOWNLOAD_WORKERS = 12        # Parallel downloads per bucket
TMP_BASE_DIR = "/tmp/clouds8_secret_scan"

# Parallelism knobs
PARALLEL_COMPARTMENTS = 4        # Compartments scanned at once
PARALLEL_BUCKETS = 6             # Buckets scanned at once per compartment
PARALLEL_CONTENT_DOWNLOADS = 8   # Files downloaded at once per bucket

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
# Content scanning — built-in secret detectors
# Scans every non-binary file in every bucket.
# ---------------------------------------------------------------------------

# Content-based secret patterns: (compiled regex, label, severity)
CONTENT_PATTERNS = [
    # ── AWS ────────────────────────────────────────────────────────────────
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID", "high"),
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

    # ── Generic high-entropy (hex keys ≥ 32 chars) ─────────────────────────
    (re.compile(r'(?:key|token|secret|password)\s*[=:]\s*["\']?'
                r'[0-9a-fA-F]{32,}', re.IGNORECASE),
     "Hex Secret/Key (≥32 chars)", "medium"),
]

# Filename-pattern fallback: (compiled regex, human-readable label)
SENSITIVE_PATTERNS = [
    # Private keys and certificates
    (re.compile(r'.*\.pem$', re.IGNORECASE), "PEM Private Key / Certificate"),
    (re.compile(r'.*\.key$', re.IGNORECASE), "Private Key File"),
    (re.compile(r'.*\.ppk$', re.IGNORECASE), "PuTTY Private Key"),
    (re.compile(r'.*\.pfx$', re.IGNORECASE), "PKCS#12 Certificate"),
    (re.compile(r'.*\.p12$', re.IGNORECASE), "PKCS#12 Certificate"),
    (re.compile(r'.*\.crt$', re.IGNORECASE), "Certificate File"),
    (re.compile(r'.*\.cer$', re.IGNORECASE), "Certificate File"),
    (re.compile(r'.*id_rsa.*', re.IGNORECASE), "SSH Private Key"),
    (re.compile(r'.*id_dsa.*', re.IGNORECASE), "DSA Private Key"),
    (re.compile(r'.*id_ecdsa.*', re.IGNORECASE), "ECDSA Private Key"),
    (re.compile(r'.*id_ed25519.*', re.IGNORECASE), "ED25519 Private Key"),

    # Credential and config files
    (re.compile(r'.*\.env$', re.IGNORECASE), "Environment Variables File"),
    (re.compile(r'.*\.env\..+', re.IGNORECASE), "Environment Variables File"),
    (re.compile(r'.*credentials$', re.IGNORECASE), "Credentials File"),
    (re.compile(r'.*\.htpasswd$', re.IGNORECASE), "Apache Password File"),
    (re.compile(r'.*\.netrc$', re.IGNORECASE), "Netrc Credentials"),
    (re.compile(r'.*\.pgpass$', re.IGNORECASE), "PostgreSQL Password File"),
    (re.compile(r'.*\.my\.cnf$', re.IGNORECASE), "MySQL Config (may contain passwords)"),
    (re.compile(r'.*\.npmrc$', re.IGNORECASE), "NPM Config (may contain tokens)"),
    (re.compile(r'.*\.pypirc$', re.IGNORECASE), "PyPI Config (may contain tokens)"),
    (re.compile(r'.*\.dockercfg$', re.IGNORECASE), "Docker Config (may contain registry tokens)"),
    (re.compile(r'.*docker.*config\.json$', re.IGNORECASE), "Docker Config JSON"),

    # Cloud provider configs
    (re.compile(r'.*oci.*config.*', re.IGNORECASE), "OCI Config File"),
    (re.compile(r'.*aws.*credentials.*', re.IGNORECASE), "AWS Credentials File"),
    (re.compile(r'.*gcloud.*credentials.*', re.IGNORECASE), "GCP Credentials File"),
    (re.compile(r'.*service[_-]?account.*\.json$', re.IGNORECASE), "Service Account Key (JSON)"),

    # Terraform / IaC state files
    (re.compile(r'.*terraform\.tfstate.*', re.IGNORECASE), "Terraform State (may contain secrets)"),
    (re.compile(r'.*terraform\.tfvars.*', re.IGNORECASE), "Terraform Variables (may contain secrets)"),
    (re.compile(r'.*\.tfvars$', re.IGNORECASE), "Terraform Variables"),

    # Secrets / Vault exports
    (re.compile(r'.*secret.*', re.IGNORECASE), "File with 'secret' in name"),
    (re.compile(r'.*password.*', re.IGNORECASE), "File with 'password' in name"),
    (re.compile(r'.*token.*', re.IGNORECASE), "File with 'token' in name"),
    (re.compile(r'.*api[_-]?key.*', re.IGNORECASE), "File with 'api_key' in name"),
    (re.compile(r'.*\.kdbx?$', re.IGNORECASE), "KeePass Database"),
    (re.compile(r'.*\.jks$', re.IGNORECASE), "Java Keystore"),
    (re.compile(r'.*\.keystore$', re.IGNORECASE), "Keystore File"),

    # Database dumps
    (re.compile(r'.*\.sql$', re.IGNORECASE), "SQL Dump (may contain sensitive data)"),
    (re.compile(r'.*\.bak$', re.IGNORECASE), "Backup File"),
    (re.compile(r'.*\.dump$', re.IGNORECASE), "Database Dump"),
]


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
@dataclass
class SensitiveFinding:
    """A single secret/sensitive file found in a bucket."""
    file_name: str
    bucket_name: str
    compartment: str
    finding_type: str          # e.g. "PrivateKey", "AWS", or pattern label
    file_size: Optional[int] = None
    detector: Optional[str] = None       # Content-based detector type (e.g. content:high)
    raw_result: Optional[str] = None     # Redacted raw result snippet
    verified: Optional[bool] = None      # Verification status
    source: str = "pattern"              # "content" or "pattern"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "bucket": self.bucket_name,
            "compartment": self.compartment,
            "finding_type": self.finding_type,
            "file_size": self.file_size,
            "detector": self.detector,
            "raw_result": self.raw_result,
            "verified": self.verified,
            "source": self.source,
        }


@dataclass
class SecretScanReport:
    """Report produced by the secret scanner."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    buckets_scanned: int = 0
    objects_scanned: int = 0
    objects_downloaded: int = 0
    objects_skipped: int = 0
    findings: List[SensitiveFinding] = field(default_factory=list)
    scan_mode: str = "pattern"   # "pattern" or "mock"
    namespace: Optional[str] = None   # OCI Object Storage namespace
    region: Optional[str] = None      # OCI region (e.g. us-ashburn-1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "buckets_scanned": self.buckets_scanned,
            "objects_scanned": self.objects_scanned,
            "objects_downloaded": self.objects_downloaded,
            "objects_skipped": self.objects_skipped,
            "total_findings": len(self.findings),
            "scan_mode": self.scan_mode,
            "namespace": self.namespace,
            "region": self.region,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_skippable(obj) -> bool:
    """Decide whether an OCI object should be skipped for download."""
    name = obj.name.lower()
    _, ext = os.path.splitext(name)
    if ext in BINARY_EXTENSIONS:
        return True
    if obj.size is not None:
        if obj.size / (1024 * 1024) > MAX_OBJECT_SIZE_MB:
            return True
    return False


def _download_object(client, namespace: str, bucket_name: str, obj, tmpdir: str) -> Optional[str]:
    """Download a single OCI object to *tmpdir*. Returns local path or None."""
    local_name = obj.name.replace("/", "_")
    file_path = os.path.join(tmpdir, local_name)
    try:
        response = client.get_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=obj.name,
        )
        with open(file_path, "wb") as f:
            for chunk in response.data.raw.stream(1024 * 1024):
                f.write(chunk)
        return file_path
    except Exception as e:
        logger.warning("Failed to download %s/%s: %s", bucket_name, obj.name, e)
        return None


# ---------------------------------------------------------------------------
# SecretScanner
# ---------------------------------------------------------------------------
class SecretScanner:
    """
    Scans OCI Object Storage buckets for secrets using filename-pattern
    matching.  Supports an optional compartment filter so the user can
    choose which compartments to scan, and a progress callback so the
    UI can show live status.
    """

    def __init__(
        self,
        collector=None,
        compartment_ids: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        asset_ids: Optional[List[str]] = None,
        progress_callback=None,
        run_checks: bool = True,
    ):
        self.collector = collector
        self.compartment_ids = compartment_ids   # None = all
        self.regions = regions   # None = all subscribed regions
        self.asset_ids = asset_ids   # None = all buckets; else restrict to these bucket names
        self.progress_callback = progress_callback  # fn(msg: str)
        self.run_checks = run_checks
        import threading
        self._lock = threading.Lock()  # protects report mutations

    def _progress(self, msg: str):
        """Send a progress update if a callback is registered."""
        logger.info(msg)
        if self.progress_callback:
            try:
                self.progress_callback(msg)
            except Exception:
                pass

    def scan_tenancy(self) -> SecretScanReport:
        """Scan buckets across selected (or all) compartments."""
        report = SecretScanReport()
        report.scan_mode = "pattern"  # live scans always use pattern matching

        if not self.run_checks:
            # This scanner's only output IS its findings — there's no
            # separate asset inventory to collect, so under "inventory"
            # depth there's nothing to do. Skip entirely; no OCI calls.
            report.completed_at = datetime.now()
            return report

        os.makedirs(TMP_BASE_DIR, exist_ok=True)

        if self.collector and self.collector.config:
            self._scan_live(report)
        else:
            logger.info("No live OCI connection — using mock data")
            self._scan_mock(report)

        report.completed_at = datetime.now()
        return report

    # ------------------------------------------------------------------
    # Live OCI scanning
    # ------------------------------------------------------------------
    def _scan_live(self, report: SecretScanReport):
        """Scan real OCI buckets across all subscribed regions."""
        try:
            self._progress("Secret Scanner: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-ashburn-1")]
            if self.regions:
                subscribed_regions = [r for r in subscribed_regions if r in self.regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            # Gather compartments
            self._progress("Collecting compartments…")
            if not self.collector.compartments:
                self.collector.compartments = (
                    self.collector.collect_compartment_details()
                )

            # Apply compartment filter if provided
            all_comps = [
                c for c in self.collector.compartments
                if c.get("lifecycle_state") == "ACTIVE"
            ]
            if self.compartment_ids:
                id_set = set(self.compartment_ids)
                all_comps = [c for c in all_comps if c["id"] in id_set]
                self._progress(
                    f"Scanning {len(all_comps)} selected compartment(s)…"
                )
            else:
                self._progress(
                    f"Scanning all {len(all_comps)} active compartments…"
                )

            total = len(all_comps)

            for region in subscribed_regions:
                self._progress(f"Secret Scanner: Setting up regional clients for {region}...")
                self.collector.setup_regional_clients(region)
                client = self.collector.get_client("object_storage")
                if not client:
                    self._progress(f"Secret Scanner: Object Storage client not available in {region}")
                    continue

                try:
                    namespace = client.get_namespace().data
                except Exception as e:
                    self._progress(f"Secret Scanner: Failed to get namespace in {region} — {e}")
                    continue

                report.namespace = namespace

                def _scan_compartment(args):
                    idx, comp = args
                    comp_id = comp["id"]
                    comp_name = comp["name"]
                    self._progress(
                        f"Secret Scanner [{region}]: [{idx}/{total}] Scanning compartment: {comp_name}"
                    )
                    try:
                        buckets = client.list_buckets(namespace, comp_id).data
                        if self.asset_ids:
                            buckets = [b for b in buckets if b.name in self.asset_ids]
                    except Exception as e:
                        logger.warning(
                            "Could not list buckets in %s: %s", comp_name, e
                        )
                        return

                    # Scan buckets within this compartment in parallel
                    def _scan_one_bucket(bucket):
                        with self._lock:
                            report.buckets_scanned += 1
                        self._progress(
                            f"Secret Scanner [{region}]: [{idx}/{total}] {comp_name} → {bucket.name}"
                        )
                        self._scan_bucket(
                            client, namespace, bucket.name, comp_name, report
                        )

                    with ThreadPoolExecutor(
                        max_workers=PARALLEL_BUCKETS
                    ) as bucket_pool:
                        list(bucket_pool.map(_scan_one_bucket, buckets))

                # Scan compartments in parallel
                with ThreadPoolExecutor(
                    max_workers=PARALLEL_COMPARTMENTS
                ) as comp_pool:
                    list(comp_pool.map(
                        _scan_compartment,
                        enumerate(all_comps, 1),
                    ))

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress("Scan complete!")

        except Exception as e:
            logger.error("Secret scanner live scan error: %s", e)

    def _scan_bucket(
        self,
        client,
        namespace: str,
        bucket_name: str,
        compartment: str,
        report: SecretScanReport,
    ):
        """Scan a single bucket: filename-pattern match + parallel content scanning."""
        try:
            # Collect objects (paginated)
            all_objects = []
            next_start = None
            while True:
                kwargs: Dict[str, Any] = {
                    "namespace_name": namespace,
                    "bucket_name": bucket_name,
                }
                if next_start:
                    kwargs["start"] = next_start

                resp = client.list_objects(**kwargs)
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
                self._check_object_pattern(
                    obj.name, bucket_name, compartment,
                    getattr(obj, "size", None), report,
                )

            # 2) Content scanning — download non-binary files in parallel
            eligible = []
            for obj in all_objects:
                obj_size = getattr(obj, "size", None) or 0
                if obj_size == 0:
                    continue
                obj_ext = os.path.splitext(obj.name)[1].lower()
                if obj_ext in BINARY_EXTENSIONS:
                    continue
                eligible.append(obj)

            if eligible:
                def _scan_one(obj):
                    self._scan_object_content(
                        client, namespace, bucket_name, compartment,
                        obj.name, getattr(obj, "size", 0), report,
                    )

                with ThreadPoolExecutor(
                    max_workers=PARALLEL_CONTENT_DOWNLOADS
                ) as pool:
                    list(pool.map(_scan_one, eligible))

        except Exception as e:
            logger.warning(
                "Error scanning bucket %s: %s", bucket_name, e
            )
    def _scan_object_content(
        self,
        client,
        namespace: str,
        bucket_name: str,
        compartment: str,
        object_name: str,
        file_size: int,
        report: SecretScanReport,
    ):
        """Download an object and scan its content for secrets."""
        try:
            response = client.get_object(
                namespace_name=namespace,
                bucket_name=bucket_name,
                object_name=object_name,
            )

            # Read content (capped at MAX_CONTENT_SCAN_SIZE)
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
                    return  # truly binary — skip

            with self._lock:
                report.objects_downloaded += 1

            # Track unique findings per file to avoid duplicates
            found_labels: set = set()

            for line_no, line in enumerate(text.splitlines(), start=1):
                for pattern, label, severity in CONTENT_PATTERNS:
                    if label in found_labels:
                        continue  # already reported this detector for this file

                    match = pattern.search(line)
                    if match:
                        found_labels.add(label)

                        # Build redacted snippet: show context around the match
                        snippet_start = max(0, match.start() - 10)
                        snippet_end = min(len(line), match.end() + 10)
                        raw_snip = line[snippet_start:snippet_end]
                        # Redact the middle of the matched value
                        matched_text = match.group(0)
                        if len(matched_text) > 12:
                            redacted = (
                                matched_text[:6] + "****" + matched_text[-4:]
                            )
                        else:
                            redacted = matched_text[:4] + "****"
                        display_snippet = (
                            f"L{line_no}: …{raw_snip.replace(matched_text, redacted)}…"
                        )

                        with self._lock:
                            report.findings.append(
                                SensitiveFinding(
                                    file_name=object_name,
                                    bucket_name=bucket_name,
                                    compartment=compartment,
                                    finding_type=label,
                                    file_size=file_size,
                                    detector=f"content:{severity}",
                                    raw_result=display_snippet,
                                    source="content",
                                )
                            )

                # No per-file limit — report all detectors found

        except Exception as e:
            logger.debug(
                "Content scan failed for %s/%s: %s",
                bucket_name, object_name, e,
            )

    # ------------------------------------------------------------------
    # Pattern-based fallback
    # ------------------------------------------------------------------
    @staticmethod
    def _check_object_pattern(
        object_name: str,
        bucket_name: str,
        compartment: str,
        file_size: Optional[int],
        report: SecretScanReport,
    ):
        """Test an object name against all sensitive patterns."""
        for pattern, label in SENSITIVE_PATTERNS:
            if pattern.match(object_name):
                report.findings.append(
                    SensitiveFinding(
                        file_name=object_name,
                        bucket_name=bucket_name,
                        compartment=compartment,
                        finding_type=label,
                        file_size=file_size,
                        source="pattern",
                    )
                )
                break

    # ------------------------------------------------------------------
    # Mock data (when no OCI connection)
    # ------------------------------------------------------------------
    def _scan_mock(self, report: SecretScanReport):
        """Populate the report with realistic mock findings."""
        report.scan_mode = "mock"
        report.namespace = "mock-namespace"
        report.region = "us-ashburn-1"

        mock_objects = [
            # Content-based findings (secrets found inside file content)
            {"name": "PK.pem", "bucket": "private_key", "compartment": "CBS-DICEPRD",
             "finding_type": "Private Key (PEM)", "size": 1868, "detector": "content:critical",
             "raw_result": "L45: …-----BEGIN RSA PRIVATE KEY-----…", "verified": False, "source": "content"},
            {"name": "EXP_TBL_RES_SCAN.dmp", "bucket": "RTCT-Export", "compartment": "CBS-GRT",
             "finding_type": "Database Connection String", "size": 592, "detector": "content:critical",
             "raw_result": "L122: …mysql://dbadmin:****@10.0.0.4…", "verified": False, "source": "content"},
            {"name": "wallet_config.json", "bucket": "SaaS-EVA", "compartment": "CBS-DICEDEV",
             "finding_type": "Private Key (PEM)", "size": 1830, "detector": "content:critical",
             "raw_result": "L2: …-----BEGIN RSA PRIVATE KEY-----…", "verified": False, "source": "content"},
            {"name": "data_export/FSCDWDATA.dmp", "bucket": "FSCDWDATA", "compartment": "FSC_Database_DevTest",
             "finding_type": "Password in Config", "size": 34034, "detector": "content:high",
             "raw_result": "L88: …password = ****…", "verified": False, "source": "content"},

            # Pattern-match findings (sensitive filenames)
            {"name": "config/database_credentials.env", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "Environment Variables File",
             "size": 1024, "source": "pattern"},
            {"name": "deploy/id_rsa", "bucket": "devops-artifacts",
             "compartment": "DevOps", "finding_type": "SSH Private Key",
             "size": 2048, "source": "pattern"},
            {"name": "backups/users_dump.sql", "bucket": "backup-storage",
             "compartment": "Production", "finding_type": "SQL Dump (may contain sensitive data)",
             "size": 52428800, "source": "pattern"},
            {"name": "certs/server.pem", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "PEM Private Key / Certificate",
             "size": 4096, "source": "pattern"},
            {"name": "certs/server.key", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "Private Key File",
             "size": 1704, "source": "pattern"},
            {"name": "terraform/terraform.tfstate", "bucket": "infra-state",
             "compartment": "DevOps", "finding_type": "Terraform State (may contain secrets)",
             "size": 31457280, "source": "pattern"},
            {"name": "keys/api_key_prod.json", "bucket": "devops-artifacts",
             "compartment": "DevOps", "finding_type": "File with 'api_key' in name",
             "size": 512, "source": "pattern"},
            {"name": ".env.production", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "Environment Variables File",
             "size": 768, "source": "pattern"},
            {"name": "secrets/db_password.txt", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "File with 'secret' in name",
             "size": 64, "source": "pattern"},
            {"name": "config/oci_config", "bucket": "devops-artifacts",
             "compartment": "DevOps", "finding_type": "OCI Config File",
             "size": 384, "source": "pattern"},
            {"name": "exports/customer_data.dump", "bucket": "backup-storage",
             "compartment": "Production", "finding_type": "Database Dump",
             "size": 104857600, "source": "pattern"},
            {"name": "tokens/service_account_key.json", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "Service Account Key (JSON)",
             "size": 2340, "source": "pattern"},
            {"name": "deploy/terraform.tfvars", "bucket": "infra-state",
             "compartment": "DevOps", "finding_type": "Terraform Variables (may contain secrets)",
             "size": 890, "source": "pattern"},
            {"name": ".htpasswd", "bucket": "web-assets",
             "compartment": "Staging", "finding_type": "Apache Password File",
             "size": 256, "source": "pattern"},
            {"name": "auth/aws_credentials", "bucket": "devops-artifacts",
             "compartment": "DevOps", "finding_type": "Credentials File",
             "size": 450, "source": "pattern"},
            {"name": "backup/prod_db.bak", "bucket": "backup-storage",
             "compartment": "Production", "finding_type": "Backup File",
             "size": 209715200, "source": "pattern"},
            {"name": "config/.npmrc", "bucket": "app-config-bucket",
             "compartment": "Production", "finding_type": "NPM Config (may contain tokens)",
             "size": 128, "source": "pattern"},
        ]

        buckets_seen = set()
        for obj in mock_objects:
            buckets_seen.add(obj["bucket"])
            report.objects_scanned += 1
            report.findings.append(
                SensitiveFinding(
                    file_name=obj["name"],
                    bucket_name=obj["bucket"],
                    compartment=obj["compartment"],
                    finding_type=obj["finding_type"],
                    file_size=obj.get("size"),
                    detector=obj.get("detector"),
                    raw_result=obj.get("raw_result"),
                    verified=obj.get("verified"),
                    source=obj.get("source", "pattern"),
                )
            )

        report.buckets_scanned = len(buckets_seen)
        report.objects_downloaded = 4  # simulate downloads
        report.objects_skipped = 5     # simulate skipped objects


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_secret_scan(
    collector=None,
    compartment_ids: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    asset_ids: Optional[List[str]] = None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run a secret scan and return the report as a dict.

    Args:
        collector: An ``OCICollector`` instance (or None for mock data).
        compartment_ids: Optional list of compartment OCIDs to scan.
                         If ``None``, all active compartments are scanned.
        regions: Optional list of region names to restrict scan to.
        asset_ids: Optional list of bucket names to restrict scan to.
        progress_callback: Optional ``fn(msg: str)`` called with status
                           updates while the scan is running.
        run_checks: If False, skip the scan entirely (this scanner has no
                    separate inventory — its only output is findings).
    """
    scanner = SecretScanner(
        collector=collector,
        compartment_ids=compartment_ids,
        regions=regions,
        asset_ids=asset_ids,
        progress_callback=progress_callback,
        run_checks=run_checks,
    )
    report = scanner.scan_tenancy()
    return report.to_dict()
