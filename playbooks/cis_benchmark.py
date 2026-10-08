"""
Clouds8 — CIS OCI Foundations Benchmark Runner
Implements automated CIS benchmark checks against live OCI tenancy.
Modeled after Trend Micro Conformity / CIS Compliance Script.

Categories:
  1. Identity & Access Management (IAM)
  2. Networking
  3. Storage (Object Storage, Block Volumes)
  4. Compute
  5. Logging & Monitoring
  6. Database
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Max parallel OCI API threads (conservative to avoid rate-limiting)
_MAX_WORKERS = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CISCheckResult:
    """Result of a single CIS benchmark check."""
    check_id: str                # e.g. "CIS-1.1"
    title: str
    category: str                # e.g. "Identity & Access Management"
    severity: str                # critical, high, medium, low, informational
    status: str                  # "PASS", "FAIL", "ERROR", "SKIPPED"
    affected_resources: List[str] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    cis_section: str = ""        # e.g. "1.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "affected_resources": self.affected_resources,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cis_section": self.cis_section,
        }


@dataclass
class CISBenchmarkReport:
    """Full CIS benchmark report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"       # "live" or "mock"
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    results: List[CISCheckResult] = field(default_factory=list)
    region: str = ""
    tenancy_name: str = ""

    @property
    def compliance_pct(self) -> float:
        evaluated = self.passed + self.failed
        if evaluated == 0:
            return 0.0
        return round(100.0 * self.passed / evaluated, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "compliance_pct": self.compliance_pct,
            "region": self.region,
            "tenancy_name": self.tenancy_name,
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# CIS Benchmark Runner
# ---------------------------------------------------------------------------
class CISBenchmarkRunner:
    """
    Runs CIS OCI Foundations Benchmark checks against a live OCI tenancy.
    Uses OCICollector for data gathering and implements each check as a
    dedicated method.
    """

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
    # Main entry point
    # ------------------------------------------------------------------
    def run(self, regions: Optional[List[str]] = None) -> CISBenchmarkReport:
        """Run all CIS benchmark checks and return a report."""
        report = CISBenchmarkReport()

        if not self.run_checks:
            # Pure tenancy-wide compliance checks — there's no separate
            # asset inventory here, so under "inventory" depth there's
            # nothing to collect. Skip entirely; no OCI calls.
            report.completed_at = datetime.now()
            return report

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, regions)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        # Tally
        for r in report.results:
            if r.status == "PASS":
                report.passed += 1
            elif r.status == "FAIL":
                report.failed += 1
            elif r.status == "ERROR":
                report.errors += 1
            else:
                report.skipped += 1
        report.total_checks = len(report.results)
        return report

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------
    def _run_live(self, report: CISBenchmarkReport, regions: Optional[List[str]] = None):
        """Run checks against real OCI tenancy."""
        try:
            self._progress("CIS Benchmark: Discovering subscribed regions...")
            subscribed_regions = self.collector.get_subscribed_regions()
            if not subscribed_regions:
                subscribed_regions = [self.collector.config.get("region", "us-phoenix-1")]
            if regions:
                subscribed_regions = [r for r in subscribed_regions if r in regions]

            original_region = self.collector.config.get("region")
            report.region = ", ".join(subscribed_regions)

            identity = self.collector.get_client("identity")
            tenancy_id = self.collector.config["tenancy"]

            # Ensure compartments are loaded
            if not self.collector.compartments:
                self.collector.compartments = (
                    self.collector.collect_compartment_details()
                )

            active_comps = [
                c for c in self.collector.compartments
                if c.get("lifecycle_state") == "ACTIVE"
            ]

            n = len(active_comps)
            self._progress(f"CIS Benchmark: Found {n} compartments, scanning in parallel...")

            # ── 1. IAM Checks ──────────────────────────────────────────
            self._progress("CIS Benchmark: Running IAM checks (parallel)...")
            if identity:
                self._check_iam(identity, tenancy_id, active_comps, report)

            # ── 2. Networking Checks ───────────────────────────────────
            self._progress(f"CIS Benchmark: Running Networking checks ({n} compartments)...")
            self._check_networking_multi(active_comps, report, subscribed_regions)

            # ── 3. Storage Checks ──────────────────────────────────────
            self._progress(f"CIS Benchmark: Running Storage checks ({n} compartments)...")
            self._check_storage_multi(active_comps, report, subscribed_regions)

            # ── 4. Compute Checks ──────────────────────────────────────
            self._progress(f"CIS Benchmark: Running Compute checks ({n} compartments)...")
            self._check_compute_multi(active_comps, report, subscribed_regions)

            # ── 5. Logging & Monitoring ────────────────────────────────
            self._progress("CIS Benchmark: Running Logging checks...")
            self._check_logging(tenancy_id, report)

            # ── 6. Key Management ──────────────────────────────────────
            self._progress("CIS Benchmark: Running Key Management checks...")
            self._check_key_management_multi(active_comps, report, subscribed_regions)

            # Restore original region client setup
            if original_region:
                self.collector.setup_regional_clients(original_region)

            self._progress("CIS Benchmark: Complete!")

        except Exception as e:
            logger.error("CIS Benchmark live scan error: %s", e)

    # ==================================================================
    # SECTION 1: Identity & Access Management
    # ==================================================================
    def _check_iam(self, identity, tenancy_id, compartments, report):
        """Run all IAM-related CIS checks."""

        # ── CIS 1.1: MFA for console users ───────────────────────────
        try:
            users = identity.list_users(tenancy_id).data
            console_users = [
                u for u in users
                if getattr(u, "can_use_console_password", True)
            ]
            no_mfa = [
                u.name for u in console_users
                if not getattr(u, "is_mfa_activated", False)
            ]
            report.results.append(CISCheckResult(
                check_id="CIS-1.1",
                title="Ensure MFA is enabled for all users with console password",
                category="Identity & Access Management",
                severity="critical",
                status="FAIL" if no_mfa else "PASS",
                affected_resources=no_mfa[:20],
                evidence=(
                    f"{len(no_mfa)} user(s) without MFA"
                    if no_mfa else "All console users have MFA enabled"
                ),
                remediation="Enable MFA: Identity > Users > [User] > Enable MFA",
                cis_section="1.1",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.1",
                title="Ensure MFA is enabled for all users with console password",
                category="Identity & Access Management",
                severity="critical",
                status="ERROR",
                evidence=str(e),
                cis_section="1.1",
            ))

        # ── CIS 1.2: API key rotation (90 days) ────────────────────
        try:
            stale_keys = []
            cutoff = datetime.utcnow() - timedelta(days=90)

            # Pre-fetch all API keys in parallel
            def _fetch_api_keys(user):
                try:
                    return user, identity.list_api_keys(user.id).data
                except Exception:
                    return user, []

            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_fetch_api_keys, u) for u in users]
                user_keys_map = {}
                for f in as_completed(futures):
                    user, keys = f.result()
                    user_keys_map[user.id] = (user, keys)

            for uid, (user, keys) in user_keys_map.items():
                for key in keys:
                    created = key.time_created
                    if hasattr(created, 'replace'):
                        created = created.replace(tzinfo=None)
                    if created < cutoff:
                        stale_keys.append(
                            f"{user.name} (key: {key.fingerprint[-8:]}…)"
                        )

            report.results.append(CISCheckResult(
                check_id="CIS-1.2",
                title="Ensure API keys are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if stale_keys else "PASS",
                affected_resources=stale_keys[:20],
                evidence=(
                    f"{len(stale_keys)} stale API key(s) older than 90 days"
                    if stale_keys
                    else "All API keys rotated within 90 days"
                ),
                remediation="Rotate API keys: Identity > Users > [User] > API Keys",
                cis_section="1.2",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.2",
                title="Ensure API keys are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="ERROR",
                evidence=str(e),
                cis_section="1.2",
            ))

        # ── CIS 1.3: No API keys for tenancy admins ──────────────────
        try:
            admin_group = None
            groups = identity.list_groups(tenancy_id).data
            for g in groups:
                if g.name.lower() == "administrators":
                    admin_group = g
                    break

            admin_with_keys = []
            if admin_group:
                memberships = identity.list_user_group_memberships(
                    tenancy_id, group_id=admin_group.id
                ).data
                admin_user_ids = {m.user_id for m in memberships}
                # Reuse pre-fetched keys from CIS 1.2
                for uid, (user, keys) in user_keys_map.items():
                    if user.id in admin_user_ids and keys:
                        admin_with_keys.append(user.name)

            report.results.append(CISCheckResult(
                check_id="CIS-1.3",
                title="Ensure no API keys exist for tenancy administrator users",
                category="Identity & Access Management",
                severity="critical",
                status="FAIL" if admin_with_keys else "PASS",
                affected_resources=admin_with_keys,
                evidence=(
                    f"{len(admin_with_keys)} admin(s) with API keys"
                    if admin_with_keys
                    else "No administrator users have API keys"
                ),
                remediation="Remove API keys from administrator accounts",
                cis_section="1.3",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.3",
                title="Ensure no API keys exist for tenancy administrator users",
                category="Identity & Access Management",
                severity="critical",
                status="ERROR",
                evidence=str(e),
                cis_section="1.3",
            ))

        # ── CIS 1.4: Auth token rotation (90 days) ──────────────────
        try:
            stale_tokens = []

            # Fetch all auth tokens in parallel
            def _fetch_auth_tokens(user):
                try:
                    return user, identity.list_auth_tokens(user.id).data
                except Exception:
                    return user, []

            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_fetch_auth_tokens, u) for u in users]
                for f in as_completed(futures):
                    user, tokens = f.result()
                    for tok in tokens:
                        created = tok.time_created
                        if hasattr(created, 'replace'):
                            created = created.replace(tzinfo=None)
                        if created < cutoff:
                            stale_tokens.append(user.name)

            report.results.append(CISCheckResult(
                check_id="CIS-1.4",
                title="Ensure auth tokens are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if stale_tokens else "PASS",
                affected_resources=list(set(stale_tokens))[:20],
                evidence=(
                    f"{len(stale_tokens)} stale auth token(s)"
                    if stale_tokens
                    else "All auth tokens rotated within 90 days"
                ),
                remediation="Rotate auth tokens: Identity > Users > [User] > Auth Tokens",
                cis_section="1.4",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.4",
                title="Ensure auth tokens are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.4",
            ))

        # ── CIS 1.5: Overly permissive policies ──────────────────────
        try:
            overly_permissive = []
            policies = identity.list_policies(tenancy_id).data
            danger_patterns = [
                "manage all-resources",
                "use all-resources",
            ]
            for pol in policies:
                for stmt in (pol.statements or []):
                    lower = stmt.lower()
                    for pat in danger_patterns:
                        if pat in lower and "administrators" not in lower:
                            overly_permissive.append(
                                f"{pol.name}: {stmt[:80]}…"
                            )

            report.results.append(CISCheckResult(
                check_id="CIS-1.5",
                title="Ensure IAM policies do not grant overly broad permissions",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if overly_permissive else "PASS",
                affected_resources=overly_permissive[:20],
                evidence=(
                    f"{len(overly_permissive)} overly permissive statement(s)"
                    if overly_permissive
                    else "No overly permissive policy statements found"
                ),
                remediation="Restrict policies to least-privilege using specific resource types",
                cis_section="1.5",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.5",
                title="Ensure IAM policies do not grant overly broad permissions",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.5",
            ))

        # ── CIS 1.6: Inactive users (no login > 90 days) ─────────────
        try:
            inactive = []
            for user in users:
                last_login = getattr(user, "last_successful_login_time", None)
                created = user.time_created
                if hasattr(created, 'replace'):
                    created = created.replace(tzinfo=None)
                if last_login:
                    if hasattr(last_login, 'replace'):
                        last_login = last_login.replace(tzinfo=None)
                    if last_login < cutoff:
                        inactive.append(user.name)
                elif created < cutoff:
                    # Never logged in and created > 90 days ago
                    inactive.append(f"{user.name} (never logged in)")

            report.results.append(CISCheckResult(
                check_id="CIS-1.6",
                title="Ensure users inactive for 90+ days are disabled",
                category="Identity & Access Management",
                severity="medium",
                status="FAIL" if inactive else "PASS",
                affected_resources=inactive[:20],
                evidence=(
                    f"{len(inactive)} inactive user(s)"
                    if inactive else "No inactive users found"
                ),
                remediation="Disable or remove users inactive > 90 days",
                cis_section="1.6",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.6",
                title="Ensure users inactive for 90+ days are disabled",
                category="Identity & Access Management",
                severity="medium",
                status="ERROR", evidence=str(e), cis_section="1.6",
            ))

        # ── CIS 1.7: Password policy strength ────────────────────────
        try:
            auth_policy = identity.get_authentication_policy(tenancy_id).data
            pwd = auth_policy.password_policy
            issues = []
            if pwd:
                if pwd.minimum_password_length and pwd.minimum_password_length < 14:
                    issues.append(f"Min length {pwd.minimum_password_length} (should be ≥14)")
                if not getattr(pwd, "is_uppercase_characters_required", True):
                    issues.append("Uppercase not required")
                if not getattr(pwd, "is_lowercase_characters_required", True):
                    issues.append("Lowercase not required")
                if not getattr(pwd, "is_numeric_characters_required", True):
                    issues.append("Numbers not required")
                if not getattr(pwd, "is_special_characters_required", True):
                    issues.append("Special chars not required")
            else:
                issues.append("No password policy configured")

            report.results.append(CISCheckResult(
                check_id="CIS-1.7",
                title="Ensure IAM password policy is strong",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if issues else "PASS",
                affected_resources=issues,
                evidence=(
                    "; ".join(issues) if issues
                    else "Password policy meets CIS requirements"
                ),
                remediation="Identity > Authentication Settings > Password Policy",
                cis_section="1.7",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.7",
                title="Ensure IAM password policy is strong",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.7",
            ))

    # ==================================================================
    # SECTION 2: Networking
    # ==================================================================
    def _check_networking(self, network, compartments, report):
        """Run all networking CIS checks."""

        ssh_open = []       # CIS-2.1
        rdp_open = []       # CIS-2.2
        all_open = []       # CIS-2.3 — any port from 0.0.0.0/0
        public_subnets = [] # CIS-2.4

        def _scan_comp_network(comp):
            """Scan one compartment for networking issues."""
            cid = comp["id"]
            cname = comp["name"]
            local_ssh, local_rdp, local_all, local_pub = [], [], [], []

            # Security Lists
            try:
                seclists = network.list_security_lists(cid).data
                for sl in seclists:
                    for rule in (sl.ingress_security_rules or []):
                        src = getattr(rule, "source", "")
                        if src != "0.0.0.0/0":
                            continue
                        tcp = getattr(rule, "tcp_options", None)
                        if tcp:
                            dst_range = getattr(tcp, "destination_port_range", None)
                            if dst_range:
                                lo = getattr(dst_range, "min", 0)
                                hi = getattr(dst_range, "max", 0)
                                if lo <= 22 <= hi:
                                    local_ssh.append(f"{sl.display_name} ({cname})")
                                if lo <= 3389 <= hi:
                                    local_rdp.append(f"{sl.display_name} ({cname})")
                            else:
                                local_all.append(f"{sl.display_name} ({cname}) — all TCP")
                        elif not tcp:
                            proto = getattr(rule, "protocol", "all")
                            if proto == "all":
                                local_all.append(f"{sl.display_name} ({cname}) — all protocols")
            except Exception:
                pass

            # Subnets
            try:
                subnets = network.list_subnets(cid).data
                for sub in subnets:
                    if not getattr(sub, "prohibit_public_ip_on_vnic", False):
                        local_pub.append(f"{sub.display_name} ({cname})")
            except Exception:
                pass

            return local_ssh, local_rdp, local_all, local_pub

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_scan_comp_network, c) for c in compartments]
            for f in as_completed(futures):
                try:
                    s, r, a, p = f.result()
                    ssh_open.extend(s)
                    rdp_open.extend(r)
                    all_open.extend(a)
                    public_subnets.extend(p)
                except Exception:
                    pass

        # CIS-2.1: SSH from 0.0.0.0/0
        report.results.append(CISCheckResult(
            check_id="CIS-2.1",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
            category="Networking",
            severity="critical",
            status="FAIL" if ssh_open else "PASS",
            affected_resources=list(set(ssh_open))[:20],
            evidence=(
                f"{len(ssh_open)} security list(s) allow SSH from anywhere"
                if ssh_open else "No unrestricted SSH access found"
            ),
            remediation="Restrict SSH (port 22) to specific CIDR ranges",
            cis_section="2.1",
        ))

        # CIS-2.2: RDP from 0.0.0.0/0
        report.results.append(CISCheckResult(
            check_id="CIS-2.2",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
            category="Networking",
            severity="critical",
            status="FAIL" if rdp_open else "PASS",
            affected_resources=list(set(rdp_open))[:20],
            evidence=(
                f"{len(rdp_open)} security list(s) allow RDP from anywhere"
                if rdp_open else "No unrestricted RDP access found"
            ),
            remediation="Restrict RDP (port 3389) to specific CIDR ranges",
            cis_section="2.2",
        ))

        # CIS-2.3: Overly permissive ingress (all ports from 0.0.0.0/0)
        report.results.append(CISCheckResult(
            check_id="CIS-2.3",
            title="Ensure no security lists allow unrestricted ingress (all ports from 0.0.0.0/0)",
            category="Networking",
            severity="critical",
            status="FAIL" if all_open else "PASS",
            affected_resources=list(set(all_open))[:20],
            evidence=(
                f"{len(all_open)} overly permissive rule(s)"
                if all_open else "No unrestricted ingress rules found"
            ),
            remediation="Remove or restrict rules allowing all traffic from 0.0.0.0/0",
            cis_section="2.3",
        ))

        # CIS-2.4: Public subnets
        report.results.append(CISCheckResult(
            check_id="CIS-2.4",
            title="Ensure subnets prohibit public IP assignment where not required",
            category="Networking",
            severity="medium",
            status="FAIL" if public_subnets else "PASS",
            affected_resources=public_subnets[:20],
            evidence=(
                f"{len(public_subnets)} subnet(s) allow public IPs"
                if public_subnets
                else "All subnets prohibit public IP assignment"
            ),
            remediation="Set 'Prohibit Public IP on VNIC' for private subnets",
            cis_section="2.4",
        ))

    # ==================================================================
    # SECTION 3: Storage
    # ==================================================================
    def _check_storage(self, objstore, compartments, report):
        """Run storage CIS checks (Object Storage buckets)."""

        public_buckets = []     # CIS-3.1
        no_versioning = []      # CIS-3.2
        no_cmk = []             # CIS-3.3

        try:
            namespace = objstore.get_namespace().data
        except Exception as e:
            logger.warning("Could not get namespace: %s", e)
            return

        # Step 1: List buckets from all compartments in parallel
        all_bucket_refs = []  # (bucket_summary, cname)

        def _list_comp_buckets(comp):
            cid = comp["id"]
            cname = comp["name"]
            try:
                return [(b, cname) for b in objstore.list_buckets(namespace, cid).data]
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_list_comp_buckets, c) for c in compartments]
            for f in as_completed(futures):
                try:
                    all_bucket_refs.extend(f.result())
                except Exception:
                    pass

        # Step 2: Get bucket details in parallel
        def _get_bucket_detail(b_summary, cname):
            try:
                bucket = objstore.get_bucket(namespace, b_summary.name).data
                result = {"name": bucket.name, "cname": cname}

                access = getattr(bucket, "public_access_type", "NoPublicAccess")
                if access and access != "NoPublicAccess":
                    result["public"] = access
                ver = getattr(bucket, "versioning", None)
                if ver != "Enabled":
                    result["no_ver"] = True
                kms = getattr(bucket, "kms_key_id", None)
                if not kms:
                    result["no_cmk"] = True
                return result
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_get_bucket_detail, b, cn) for b, cn in all_bucket_refs]
            for f in as_completed(futures):
                try:
                    r = f.result()
                    if r is None:
                        continue
                    if "public" in r:
                        public_buckets.append(f"{r['name']} ({r['cname']}) — {r['public']}")
                    if r.get("no_ver"):
                        no_versioning.append(f"{r['name']} ({r['cname']})")
                    if r.get("no_cmk"):
                        no_cmk.append(f"{r['name']} ({r['cname']})")
                except Exception:
                    pass

        report.results.append(CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure Object Storage buckets are not publicly accessible",
            category="Storage",
            severity="critical",
            status="FAIL" if public_buckets else "PASS",
            affected_resources=public_buckets[:20],
            evidence=(
                f"{len(public_buckets)} public bucket(s)"
                if public_buckets
                else "No publicly accessible buckets found"
            ),
            remediation="Set bucket access type to 'NoPublicAccess'",
            cis_section="3.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.2",
            title="Ensure Object Storage buckets have versioning enabled",
            category="Storage",
            severity="medium",
            status="FAIL" if no_versioning else "PASS",
            affected_resources=no_versioning[:20],
            evidence=(
                f"{len(no_versioning)} bucket(s) without versioning"
                if no_versioning
                else "All buckets have versioning enabled"
            ),
            remediation="Enable versioning on Object Storage buckets",
            cis_section="3.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.3",
            title="Ensure Object Storage buckets are encrypted with customer-managed keys",
            category="Storage",
            severity="high",
            status="FAIL" if no_cmk else "PASS",
            affected_resources=no_cmk[:20],
            evidence=(
                f"{len(no_cmk)} bucket(s) using Oracle-managed encryption"
                if no_cmk
                else "All buckets encrypted with customer-managed keys"
            ),
            remediation="Configure customer-managed encryption keys (Vault > Keys)",
            cis_section="3.3",
        ))

    # ==================================================================
    # SECTION 4: Compute
    # ==================================================================
    def _check_compute(self, compute, network, compartments, report):
        """Run compute-related CIS checks."""

        legacy_metadata = []   # CIS-4.1
        no_monitoring = []     # CIS-4.2
        public_instances = []  # CIS-4.3

        # Step 1: List instances from all compartments in parallel
        all_instances = []  # (inst, cid, cname)

        def _list_comp_instances(comp):
            cid = comp["id"]
            cname = comp["name"]
            try:
                insts = compute.list_instances(cid, lifecycle_state="RUNNING").data
                return [(inst, cid, cname) for inst in insts]
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_list_comp_instances, c) for c in compartments]
            for f in as_completed(futures):
                try:
                    all_instances.extend(f.result())
                except Exception:
                    pass

        # Step 2: Check instance properties + fetch VNIC public IPs in parallel
        vnic_tasks = []  # (instance_name, cname, vnic_id)

        for inst, cid, cname in all_instances:
            name = inst.display_name

            # CIS-4.1: Legacy metadata service
            inst_opts = getattr(inst, "instance_options", None)
            if inst_opts:
                legacy = getattr(inst_opts, "are_legacy_imds_endpoints_disabled", None)
                if legacy is False:
                    legacy_metadata.append(f"{name} ({cname})")

            # CIS-4.2: Monitoring agent
            agent_cfg = getattr(inst, "agent_config", None)
            if agent_cfg:
                monitoring = getattr(agent_cfg, "is_monitoring_disabled", None)
                if monitoring is True:
                    no_monitoring.append(f"{name} ({cname})")

            # Collect VNIC attachments for CIS-4.3
            try:
                vnics = compute.list_vnic_attachments(cid, instance_id=inst.id).data
                for va in vnics:
                    vnic_tasks.append((name, cname, va.vnic_id))
            except Exception:
                pass

        # Fetch VNIC details in parallel for CIS-4.3
        def _get_vnic_ip(name, cname, vnic_id):
            try:
                vnic = network.get_vnic(vnic_id).data
                pub = getattr(vnic, "public_ip", None)
                if pub:
                    return f"{name} ({cname}) — {pub}"
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_get_vnic_ip, n, cn, vid) for n, cn, vid in vnic_tasks]
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        public_instances.append(result)
                except Exception:
                    pass

        report.results.append(CISCheckResult(
            check_id="CIS-4.1",
            title="Ensure Compute Instance Legacy Metadata service endpoint is disabled",
            category="Compute",
            severity="high",
            status="FAIL" if legacy_metadata else "PASS",
            affected_resources=legacy_metadata[:20],
            evidence=(
                f"{len(legacy_metadata)} instance(s) with legacy IMDS enabled"
                if legacy_metadata
                else "All instances have legacy IMDS disabled"
            ),
            remediation="Disable legacy metadata service on instances",
            cis_section="4.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.2",
            title="Ensure monitoring agent is enabled on all instances",
            category="Compute",
            severity="medium",
            status="FAIL" if no_monitoring else "PASS",
            affected_resources=no_monitoring[:20],
            evidence=(
                f"{len(no_monitoring)} instance(s) with monitoring disabled"
                if no_monitoring
                else "All instances have monitoring enabled"
            ),
            remediation="Enable Oracle Cloud Agent monitoring plugin",
            cis_section="4.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.3",
            title="Ensure compute instances do not have public IP addresses unless required",
            category="Compute",
            severity="medium",
            status="FAIL" if public_instances else "PASS",
            affected_resources=list(set(public_instances))[:20],
            evidence=(
                f"{len(public_instances)} instance(s) with public IPs"
                if public_instances
                else "No instances with public IPs found"
            ),
            remediation="Remove public IPs or ensure they are required for the workload",
            cis_section="4.3",
        ))

        # CIS-4.4: IMDS v2 restriction (from OCI_Real_CIS_Benchmark_Playbook.xlsx §6.1)
        # Token-based access (IMDSv2) prevents SSRF-based metadata theft.
        imds_unrestricted = [
            f"{name} ({cname})"
            for inst, cid, cname in all_instances
            for name in [inst.display_name]
            if getattr(getattr(inst, "instance_options", None), "are_legacy_imds_endpoints_disabled", None) is not True
        ]
        report.results.append(CISCheckResult(
            check_id="CIS-4.4",
            title="Ensure Instance Metadata Service (IMDS) v1 endpoints are disabled",
            category="Compute",
            severity="high",
            status="FAIL" if imds_unrestricted else "PASS",
            affected_resources=list(set(imds_unrestricted))[:20],
            evidence=(
                f"{len(imds_unrestricted)} instance(s) still expose IMDSv1 endpoints — token theft → privilege escalation risk"
                if imds_unrestricted
                else "All instances restrict IMDS to token-based (v2) access"
            ),
            remediation="Set instanceOptions.areLegacyImdsEndpointsDisabled=true on each instance",
            cis_section="4.4",
        ))

    # ==================================================================
    # SECTION 5: Logging & Monitoring
    # ==================================================================
    def _check_logging(self, tenancy_id, report):
        """Run logging/monitoring CIS checks."""

        # CIS-5.1: Audit log retention
        try:
            import oci
            audit_client = oci.audit.AuditClient(self.collector.config)
            cfg = audit_client.get_configuration(tenancy_id).data
            retention = getattr(cfg, "retention_period_days", 0)

            report.results.append(CISCheckResult(
                check_id="CIS-5.1",
                title="Ensure audit log retention is set to 365 days",
                category="Logging & Monitoring",
                severity="high",
                status="PASS" if retention >= 365 else "FAIL",
                evidence=f"Current retention: {retention} days",
                remediation="Set audit retention to 365 days: Governance > Audit > Configuration",
                cis_section="5.1",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-5.1",
                title="Ensure audit log retention is set to 365 days",
                category="Logging & Monitoring",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="5.1",
            ))

        # CIS-5.2: Cloud Guard enabled
        try:
            import oci
            cg_client = oci.cloud_guard.CloudGuardClient(self.collector.config)
            cg_cfg = cg_client.get_configuration(tenancy_id).data
            cg_status = getattr(cg_cfg, "status", "DISABLED")

            report.results.append(CISCheckResult(
                check_id="CIS-5.2",
                title="Ensure Cloud Guard is enabled in the root compartment",
                category="Logging & Monitoring",
                severity="high",
                status="PASS" if cg_status == "ENABLED" else "FAIL",
                evidence=f"Cloud Guard status: {cg_status}",
                remediation="Enable Cloud Guard: Security > Cloud Guard > Enable",
                cis_section="5.2",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-5.2",
                title="Ensure Cloud Guard is enabled in the root compartment",
                category="Logging & Monitoring",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="5.2",
            ))

    # ==================================================================
    # SECTION 6: Key Management (from OCI_Real_CIS_Benchmark_Playbook.xlsx §8.1)
    # ==================================================================
    def _check_key_management(self, compartments, report):
        """CIS §8.1 — Ensure KMS keys are rotated periodically (≤365 days)."""
        try:
            import oci
            stale_keys = []
            rotation_cutoff = datetime.utcnow() - timedelta(days=365)

            def _scan_comp_keys(comp):
                cid = comp["id"]
                cname = comp["name"]
                findings = []
                try:
                    kms_mgmt = oci.key_management.KmsVaultClient(self.collector.config)
                    vaults = kms_mgmt.list_vaults(cid).data
                    for vault in vaults:
                        try:
                            keys_client = oci.key_management.KmsManagementClient(
                                self.collector.config,
                                service_endpoint=vault.management_endpoint
                            )
                            keys = keys_client.list_keys(cid).data
                            for key in keys:
                                current_ver_id = getattr(key, "current_key_version", None)
                                time_created = getattr(key, "time_created", None)
                                if time_created:
                                    if hasattr(time_created, "replace"):
                                        time_created = time_created.replace(tzinfo=None)
                                    if time_created < rotation_cutoff:
                                        findings.append(
                                            f"{key.display_name} in {vault.display_name} ({cname}) — created {time_created.date()}"
                                        )
                        except Exception:
                            pass
                except Exception:
                    pass
                return findings

            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_comp_keys, c) for c in compartments]
                for f in as_completed(futures):
                    try:
                        stale_keys.extend(f.result())
                    except Exception:
                        pass

            report.results.append(CISCheckResult(
                check_id="CIS-6.1",
                title="Ensure KMS encryption keys are rotated at least annually",
                category="Key Management",
                severity="medium",
                status="FAIL" if stale_keys else "PASS",
                affected_resources=stale_keys[:20],
                evidence=(
                    f"{len(stale_keys)} key(s) not rotated within the past 365 days — long-term key compromise risk"
                    if stale_keys
                    else "All KMS keys have been rotated within the past year"
                ),
                remediation="Enable automatic key rotation: KMS > Key > Enable Auto-Rotation (annual schedule)",
                cis_section="6.1",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-6.1",
                title="Ensure KMS encryption keys are rotated at least annually",
                category="Key Management",
                severity="medium",
                status="ERROR", evidence=str(e), cis_section="6.1",
            ))

    # ── Networking Multi-Region Helper ──────────────────────────────────
    def _check_networking_multi(self, compartments, report, subscribed_regions):
        """Run all networking CIS checks across multiple regions and consolidate."""
        ssh_open = []       # CIS-2.1
        rdp_open = []       # CIS-2.2
        all_open = []       # CIS-2.3
        public_subnets = [] # CIS-2.4

        for region in subscribed_regions:
            try:
                self.collector.setup_regional_clients(region)
                network = self.collector.get_client("network")
                if not network:
                    continue

                def _scan_comp_network(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    local_ssh, local_rdp, local_all, local_pub = [], [], [], []

                    # Security Lists
                    try:
                        seclists = network.list_security_lists(cid).data
                        for sl in seclists:
                            for rule in (sl.ingress_security_rules or []):
                                src = getattr(rule, "source", "")
                                if src != "0.0.0.0/0":
                                    continue
                                tcp = getattr(rule, "tcp_options", None)
                                if tcp:
                                    dst_range = getattr(tcp, "destination_port_range", None)
                                    if dst_range:
                                        lo = getattr(dst_range, "min", 0)
                                        hi = getattr(dst_range, "max", 0)
                                        if lo <= 22 <= hi:
                                            local_ssh.append(f"{sl.display_name} ({cname} - {region})")
                                        if lo <= 3389 <= hi:
                                            local_rdp.append(f"{sl.display_name} ({cname} - {region})")
                                    else:
                                        local_all.append(f"{sl.display_name} ({cname} - {region}) — all TCP")
                                elif not tcp:
                                    proto = getattr(rule, "protocol", "all")
                                    if proto == "all":
                                        local_all.append(f"{sl.display_name} ({cname} - {region}) — all protocols")
                    except Exception:
                        pass

                    # Subnets
                    try:
                        subnets = network.list_subnets(cid).data
                        for sub in subnets:
                            if not getattr(sub, "prohibit_public_ip_on_vnic", False):
                                local_pub.append(f"{sub.display_name} ({cname} - {region})")
                    except Exception:
                        pass

                    return local_ssh, local_rdp, local_all, local_pub

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_comp_network, c) for c in compartments]
                    for f in as_completed(futures):
                        try:
                            s, r, a, p = f.result()
                            ssh_open.extend(s)
                            rdp_open.extend(r)
                            all_open.extend(a)
                            public_subnets.extend(p)
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"CIS Networking scan error in {region}: {e}")

        # Add single consolidated results
        report.results.append(CISCheckResult(
            check_id="CIS-2.1",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
            category="Networking",
            severity="critical",
            status="FAIL" if ssh_open else "PASS",
            affected_resources=list(set(ssh_open))[:20],
            evidence=(
                f"{len(ssh_open)} security list(s) allow SSH from anywhere"
                if ssh_open else "No unrestricted SSH access found"
            ),
            remediation="Restrict SSH (port 22) to specific CIDR ranges",
            cis_section="2.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-2.2",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
            category="Networking",
            severity="critical",
            status="FAIL" if rdp_open else "PASS",
            affected_resources=list(set(rdp_open))[:20],
            evidence=(
                f"{len(rdp_open)} security list(s) allow RDP from anywhere"
                if rdp_open else "No unrestricted RDP access found"
            ),
            remediation="Restrict RDP (port 3389) to specific CIDR ranges",
            cis_section="2.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-2.3",
            title="Ensure no security lists allow unrestricted ingress (all ports from 0.0.0.0/0)",
            category="Networking",
            severity="critical",
            status="FAIL" if all_open else "PASS",
            affected_resources=list(set(all_open))[:20],
            evidence=(
                f"{len(all_open)} overly permissive rule(s)"
                if all_open else "No unrestricted ingress rules found"
            ),
            remediation="Remove or restrict rules allowing all traffic from 0.0.0.0/0",
            cis_section="2.3",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-2.4",
            title="Ensure subnets prohibit public IP assignment where not required",
            category="Networking",
            severity="medium",
            status="FAIL" if public_subnets else "PASS",
            affected_resources=public_subnets[:20],
            evidence=(
                f"{len(public_subnets)} subnet(s) allow public IPs"
                if public_subnets
                else "All subnets prohibit public IP assignment"
            ),
            remediation="Set 'Prohibit Public IP on VNIC' for private subnets",
            cis_section="2.4",
        ))

    # ── Storage Multi-Region Helper ────────────────────────────────────
    def _check_storage_multi(self, compartments, report, subscribed_regions):
        """Run storage CIS checks across multiple regions and consolidate."""
        public_buckets = []     # CIS-3.1
        no_versioning = []      # CIS-3.2
        no_cmk = []             # CIS-3.3

        for region in subscribed_regions:
            try:
                self.collector.setup_regional_clients(region)
                objstore = self.collector.get_client("object_storage")
                if not objstore:
                    continue

                try:
                    namespace = objstore.get_namespace().data
                except Exception as e:
                    logger.warning(f"Could not get namespace in {region}: {e}")
                    continue

                # Step 1: List buckets
                all_bucket_refs = []

                def _list_comp_buckets(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    try:
                        return [(b, cname) for b in objstore.list_buckets(namespace, cid).data]
                    except Exception:
                        return []

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_list_comp_buckets, c) for c in compartments]
                    for f in as_completed(futures):
                        try:
                            all_bucket_refs.extend(f.result())
                        except Exception:
                            pass

                # Step 2: Get bucket details
                def _get_bucket_detail(b_summary, cname):
                    try:
                        bucket = objstore.get_bucket(namespace, b_summary.name).data
                        result = {"name": bucket.name, "cname": cname}

                        access = getattr(bucket, "public_access_type", "NoPublicAccess")
                        if access and access != "NoPublicAccess":
                            result["public"] = access
                        ver = getattr(bucket, "versioning", None)
                        if ver != "Enabled":
                            result["no_ver"] = True
                        kms = getattr(bucket, "kms_key_id", None)
                        if not kms:
                            result["no_cmk"] = True
                        return result
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_get_bucket_detail, b, cn) for b, cn in all_bucket_refs]
                    for f in as_completed(futures):
                        try:
                            r = f.result()
                            if r is None:
                                continue
                            if "public" in r:
                                public_buckets.append(f"{r['name']} ({r['cname']} - {region}) — {r['public']}")
                            if r.get("no_ver"):
                                no_versioning.append(f"{r['name']} ({r['cname']} - {region})")
                            if r.get("no_cmk"):
                                no_cmk.append(f"{r['name']} ({r['cname']} - {region})")
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"CIS Storage scan error in {region}: {e}")

        # Add single consolidated results
        report.results.append(CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure Object Storage buckets are not publicly accessible",
            category="Storage",
            severity="critical",
            status="FAIL" if public_buckets else "PASS",
            affected_resources=public_buckets[:20],
            evidence=(
                f"{len(public_buckets)} public bucket(s)"
                if public_buckets
                else "No publicly accessible buckets found"
            ),
            remediation="Set bucket access type to 'NoPublicAccess'",
            cis_section="3.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.2",
            title="Ensure Object Storage buckets have versioning enabled",
            category="Storage",
            severity="medium",
            status="FAIL" if no_versioning else "PASS",
            affected_resources=no_versioning[:20],
            evidence=(
                f"{len(no_versioning)} bucket(s) without versioning"
                if no_versioning
                else "All buckets have versioning enabled"
            ),
            remediation="Enable versioning on Object Storage buckets",
            cis_section="3.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.3",
            title="Ensure Object Storage buckets are encrypted with customer-managed keys",
            category="Storage",
            severity="high",
            status="FAIL" if no_cmk else "PASS",
            affected_resources=no_cmk[:20],
            evidence=(
                f"{len(no_cmk)} bucket(s) using Oracle-managed encryption"
                if no_cmk
                else "All buckets encrypted with customer-managed keys"
            ),
            remediation="Configure customer-managed encryption keys (Vault > Keys)",
            cis_section="3.3",
        ))

    # ── Compute Multi-Region Helper ─────────────────────────────────────
    def _check_compute_multi(self, compartments, report, subscribed_regions):
        """Run compute CIS checks across multiple regions and consolidate."""
        legacy_metadata = []   # CIS-4.1
        no_monitoring = []     # CIS-4.2
        public_instances = []  # CIS-4.3
        imds_unrestricted = [] # CIS-4.4

        for region in subscribed_regions:
            try:
                self.collector.setup_regional_clients(region)
                compute = self.collector.get_client("compute")
                network = self.collector.get_client("network")
                if not compute or not network:
                    continue

                # Step 1: List instances
                all_instances = []

                def _list_comp_instances(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    try:
                        insts = compute.list_instances(cid, lifecycle_state="RUNNING").data
                        return [(inst, cid, cname) for inst in insts]
                    except Exception:
                        return []

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_list_comp_instances, c) for c in compartments]
                    for f in as_completed(futures):
                        try:
                            all_instances.extend(f.result())
                        except Exception:
                            pass

                # Step 2: Check instance properties
                vnic_tasks = []

                for inst, cid, cname in all_instances:
                    name = inst.display_name

                    # CIS-4.1: Legacy metadata
                    inst_opts = getattr(inst, "instance_options", None)
                    legacy = getattr(inst_opts, "are_legacy_imds_endpoints_disabled", None)
                    if legacy is False:
                        legacy_metadata.append(f"{name} ({cname} - {region})")
                        imds_unrestricted.append(f"{name} ({cname} - {region})")

                    # CIS-4.2: Monitoring agent
                    agent_cfg = getattr(inst, "agent_config", None)
                    if agent_cfg:
                        monitoring = getattr(agent_cfg, "is_monitoring_disabled", None)
                        if monitoring is True:
                            no_monitoring.append(f"{name} ({cname} - {region})")

                    # Collect VNIC attachments for CIS-4.3
                    try:
                        vnics = compute.list_vnic_attachments(cid, instance_id=inst.id).data
                        for va in vnics:
                            vnic_tasks.append((name, cname, va.vnic_id))
                    except Exception:
                        pass

                # Fetch VNIC public IPs
                def _get_vnic_ip(name, cname, vnic_id):
                    try:
                        vnic = network.get_vnic(vnic_id).data
                        pub = getattr(vnic, "public_ip", None)
                        if pub:
                            return f"{name} ({cname} - {region}) — {pub}"
                    except Exception:
                        pass
                    return None

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_get_vnic_ip, n, cn, vid) for n, cn, vid in vnic_tasks]
                    for f in as_completed(futures):
                        try:
                            res = f.result()
                            if res:
                                public_instances.append(res)
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"CIS Compute scan error in {region}: {e}")

        # Add single consolidated results
        report.results.append(CISCheckResult(
            check_id="CIS-4.1",
            title="Ensure Compute Instance Legacy Metadata service endpoint is disabled",
            category="Compute",
            severity="high",
            status="FAIL" if legacy_metadata else "PASS",
            affected_resources=legacy_metadata[:20],
            evidence=(
                f"{len(legacy_metadata)} instance(s) with legacy IMDS enabled"
                if legacy_metadata
                else "All instances have legacy IMDS disabled"
            ),
            remediation="Disable legacy metadata service on instances",
            cis_section="4.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.2",
            title="Ensure monitoring agent is enabled on all instances",
            category="Compute",
            severity="medium",
            status="FAIL" if no_monitoring else "PASS",
            affected_resources=no_monitoring[:20],
            evidence=(
                f"{len(no_monitoring)} instance(s) with monitoring disabled"
                if no_monitoring
                else "All instances have monitoring enabled"
            ),
            remediation="Enable Oracle Cloud Agent monitoring plugin",
            cis_section="4.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.3",
            title="Ensure compute instances do not have public IP addresses unless required",
            category="Compute",
            severity="medium",
            status="FAIL" if public_instances else "PASS",
            affected_resources=list(set(public_instances))[:20],
            evidence=(
                f"{len(public_instances)} instance(s) with public IPs"
                if public_instances
                else "No instances with public IPs found"
            ),
            remediation="Remove public IPs or ensure they are required for the workload",
            cis_section="4.3",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.4",
            title="Ensure Instance Metadata Service (IMDS) v1 endpoints are disabled",
            category="Compute",
            severity="high",
            status="FAIL" if imds_unrestricted else "PASS",
            affected_resources=list(set(imds_unrestricted))[:20],
            evidence=(
                f"{len(imds_unrestricted)} instance(s) still expose IMDSv1 endpoints — token theft → privilege escalation risk"
                if imds_unrestricted
                else "All instances restrict IMDS to token-based (v2) access"
            ),
            remediation="Set instanceOptions.areLegacyImdsEndpointsDisabled=true on each instance",
            cis_section="4.4",
        ))

    # ── Key Management Multi-Region Helper ──────────────────────────────
    def _check_key_management_multi(self, compartments, report, subscribed_regions):
        """CIS §8.1 — Ensure KMS keys are rotated periodically (≤365 days) across multiple regions."""
        stale_keys = []
        rotation_cutoff = datetime.utcnow() - timedelta(days=365)

        for region in subscribed_regions:
            try:
                self.collector.setup_regional_clients(region)
                kms_mgmt = self.collector.get_client("kms_vault")
                if not kms_mgmt:
                    continue

                regional_config = dict(self.collector.config)
                regional_config["region"] = region

                def _scan_comp_keys(comp):
                    cid = comp["id"]
                    cname = comp["name"]
                    findings = []
                    try:
                        vaults = kms_mgmt.list_vaults(cid).data
                        for vault in vaults:
                            try:
                                import oci
                                keys_client = oci.key_management.KmsManagementClient(
                                    regional_config,
                                    service_endpoint=vault.management_endpoint
                                )
                                keys = keys_client.list_keys(cid).data
                                for key in keys:
                                    time_created = getattr(key, "time_created", None)
                                    if time_created:
                                        if hasattr(time_created, "replace"):
                                            time_created = time_created.replace(tzinfo=None)
                                        if time_created < rotation_cutoff:
                                            findings.append(
                                                f"{key.display_name} in {vault.display_name} ({cname} - {region}) — created {time_created.date()}"
                                            )
                            except Exception:
                                pass
                    except Exception:
                        pass
                    return findings

                with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_comp_keys, c) for c in compartments]
                    for f in as_completed(futures):
                        try:
                            stale_keys.extend(f.result())
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"CIS Key Management scan error in {region}: {e}")

        # Add single consolidated result
        report.results.append(CISCheckResult(
            check_id="CIS-6.1",
            title="Ensure KMS encryption keys are rotated at least annually",
            category="Key Management",
            severity="medium",
            status="FAIL" if stale_keys else "PASS",
            affected_resources=stale_keys[:20],
            evidence=(
                f"{len(stale_keys)} key(s) not rotated within the past 365 days — long-term key compromise risk"
                if stale_keys
                else "All KMS keys have been rotated within the past year"
            ),
            remediation="Enable automatic key rotation: KMS > Key > Enable Auto-Rotation (annual schedule)",
            cis_section="6.1",
        ))

    # ==================================================================
    # MOCK mode (offline / demo)
    # ==================================================================
    def _run_mock(self, report: CISBenchmarkReport):
        """Generate realistic mock results for demo/testing."""
        report.scan_mode = "mock"
        report.region = "us-ashburn-1"
        report.tenancy_name = "mock-tenancy"

        mock_checks = [
            # IAM
            ("CIS-1.1", "Ensure MFA is enabled for all users", "Identity & Access Management",
             "critical", "FAIL", "3 user(s) without MFA",
             ["user_admin", "user_dev1", "user_ops"], "Enable MFA for all users"),
            ("CIS-1.2", "Ensure API keys are rotated within 90 days", "Identity & Access Management",
             "high", "FAIL", "2 stale API key(s) older than 90 days",
             ["admin_user (key: a1b2c3…)", "svc_account (key: d4e5f6…)"], "Rotate API keys"),
            ("CIS-1.3", "Ensure no API keys for tenancy admins", "Identity & Access Management",
             "critical", "FAIL", "1 admin(s) with API keys",
             ["tenancy_admin"], "Remove API keys from admin accounts"),
            ("CIS-1.4", "Ensure auth tokens are rotated within 90 days", "Identity & Access Management",
             "high", "PASS", "All auth tokens rotated within 90 days", [], ""),
            ("CIS-1.5", "Ensure IAM policies do not grant overly broad permissions", "Identity & Access Management",
             "high", "FAIL", "2 overly permissive statement(s)",
             ["DevPolicy: allow group Devs to manage all-resources…",
              "TestPolicy: allow group QA to use all-resources…"],
             "Restrict to least-privilege"),
            ("CIS-1.6", "Ensure users inactive for 90+ days are disabled", "Identity & Access Management",
             "medium", "FAIL", "4 inactive user(s)",
             ["old_user1 (never logged in)", "old_user2", "contractor1", "temp_admin"],
             "Disable or remove inactive users"),
            ("CIS-1.7", "Ensure IAM password policy is strong", "Identity & Access Management",
             "high", "FAIL", "Min length 8 (should be ≥14)",
             ["Min length 8 (should be ≥14)"], "Strengthen password policy"),

            # Networking
            ("CIS-2.1", "Ensure no security lists allow SSH from 0.0.0.0/0", "Networking",
             "critical", "FAIL", "3 security list(s) allow SSH from anywhere",
             ["Default-SL (DevTest)", "WebApp-SL (Prod)", "Test-SL (Sandbox)"],
             "Restrict SSH to specific CIDR ranges"),
            ("CIS-2.2", "Ensure no security lists allow RDP from 0.0.0.0/0", "Networking",
             "critical", "PASS", "No unrestricted RDP access found", [], ""),
            ("CIS-2.3", "Ensure no security lists allow unrestricted ingress", "Networking",
             "critical", "FAIL", "1 overly permissive rule(s)",
             ["Legacy-SL (OldComp) — all protocols"],
             "Remove rules allowing all traffic from 0.0.0.0/0"),
            ("CIS-2.4", "Ensure subnets prohibit public IP assignment where not required", "Networking",
             "medium", "FAIL", "12 subnet(s) allow public IPs",
             ["pub-sub-1 (DevTest)", "pub-sub-2 (Prod)", "app-sub (Staging)"],
             "Set 'Prohibit Public IP on VNIC' for private subnets"),

            # Storage
            ("CIS-3.1", "Ensure Object Storage buckets are not publicly accessible", "Storage",
             "critical", "FAIL", "2 public bucket(s)",
             ["static-assets (Prod) — ObjectRead", "data-export (DevTest) — ObjectReadWrite"],
             "Set bucket access to 'NoPublicAccess'"),
            ("CIS-3.2", "Ensure Object Storage buckets have versioning enabled", "Storage",
             "medium", "FAIL", "8 bucket(s) without versioning",
             ["logs-bucket (Prod)", "backup-bucket (DR)", "temp-data (DevTest)"],
             "Enable versioning on buckets"),
            ("CIS-3.3", "Ensure Object Storage buckets use customer-managed encryption", "Storage",
             "high", "FAIL", "15 bucket(s) using Oracle-managed encryption",
             ["app-data (Prod)", "db-backups (Prod)", "config-store (DevTest)"],
             "Configure CMK encryption via Vault"),

            # Compute
            ("CIS-4.1", "Ensure legacy metadata service endpoint is disabled", "Compute",
             "high", "FAIL", "5 instance(s) with legacy IMDS enabled",
             ["web-server-1 (Prod)", "app-server-2 (Prod)", "dev-box (DevTest)"],
             "Disable legacy metadata service on instances"),
            ("CIS-4.2", "Ensure monitoring agent is enabled on all instances", "Compute",
             "medium", "FAIL", "3 instance(s) with monitoring disabled",
             ["batch-job-1 (Prod)", "test-vm (DevTest)", "jump-host (Staging)"],
             "Enable Oracle Cloud Agent monitoring plugin"),
            ("CIS-4.3", "Ensure instances do not have public IPs unless required", "Compute",
             "medium", "FAIL", "7 instance(s) with public IPs",
             ["web-1 (Prod) — 129.213.x.x", "bastion (DevTest) — 144.24.x.x"],
             "Remove public IPs or ensure they are required"),
            ("CIS-4.4", "Ensure IMDS v1 endpoints are disabled (token-based access only)", "Compute",
             "high", "FAIL", "4 instance(s) still expose IMDSv1 endpoints — token theft → privilege escalation risk",
             ["app-server-1 (Prod)", "worker-2 (Prod)", "dev-box (DevTest)", "old-vm (Sandbox)"],
             "Set instanceOptions.areLegacyImdsEndpointsDisabled=true on each instance"),

            # Logging
            ("CIS-5.1", "Ensure audit log retention is set to 365 days", "Logging & Monitoring",
             "high", "FAIL", "Current retention: 90 days",
             [], "Set audit retention to 365 days"),
            ("CIS-5.2", "Ensure Cloud Guard is enabled in the root compartment", "Logging & Monitoring",
             "high", "PASS", "Cloud Guard status: ENABLED", [], ""),

            # Key Management (§8.1 from OCI_Real_CIS_Benchmark_Playbook.xlsx)
            ("CIS-6.1", "Ensure KMS encryption keys are rotated at least annually", "Key Management",
             "medium", "FAIL", "2 key(s) not rotated within the past 365 days — long-term key compromise risk",
             ["db-encryption-key in prod-vault (Prod) — created 2023-01-15",
              "app-secret-key in app-vault (Staging) — created 2022-11-03"],
             "Enable automatic key rotation: KMS > Key > Enable Auto-Rotation (annual schedule)"),
        ]

        for (cid, title, cat, sev, status, evidence,
             resources, remediation) in mock_checks:
            report.results.append(CISCheckResult(
                check_id=cid,
                title=title,
                category=cat,
                severity=sev,
                status=status,
                affected_resources=resources,
                evidence=evidence,
                remediation=remediation,
                cis_section=cid.replace("CIS-", ""),
            ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_cis_benchmark(
    collector=None,
    regions=None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run CIS OCI benchmark and return results as a dict."""
    runner = CISBenchmarkRunner(
        collector=collector,
        progress_callback=progress_callback,
        run_checks=run_checks,
    )
    report = runner.run(regions=regions)
    return report.to_dict()
