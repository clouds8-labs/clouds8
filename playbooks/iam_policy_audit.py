"""
Clouds8 — IAM Policy Audit Playbook
Scans OCI tenancy for overly permissive IAM policies, focusing on:
  - Broad 'read/manage all-resources' grants
  - Secret-family / secret-bundle access grants
  - Missing deny policies for secret protection
  - Overly permissive dynamic group matching rules

Produces a risk-scored report of policy findings.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Tenancies can have thousands of users/groups; list_api_keys and
# list_user_group_memberships are one API call per resource, so this must
# be parallelized the same way every other scanner parallelizes
# per-compartment work — otherwise large tenancies make this check
# effectively hang (verified against a live tenancy with ~7.8k users).
_IDENTITY_MAX_WORKERS = 10


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

RISK_SCORES = {
    RISK_CRITICAL: 95,
    RISK_HIGH: 75,
    RISK_MEDIUM: 50,
    RISK_LOW: 25,
    RISK_INFO: 10,
}

# A statement can explicitly re-scope itself to a compartment different from
# wherever the policy object is attached - e.g. a tenancy-root policy using
# "in compartment id <ocid>" to target one specific compartment, without
# needing a separate per-compartment policy file. Without parsing this,
# every finding gets tagged with the policy's own attachment compartment
# regardless of what the statement itself scopes to, which silently breaks
# attack-path target resolution for exactly this (common, valid) pattern.
_COMPARTMENT_ID_CLAUSE_RE = re.compile(r"in compartment id\s+'?(ocid1\.compartment\.[\w.-]+)'?", re.IGNORECASE)


def _extract_explicit_compartment_id(stmt: str) -> Optional[str]:
    m = _COMPARTMENT_ID_CLAUSE_RE.search(stmt)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class PolicyFinding:
    """A single IAM policy finding."""
    policy_name: str
    policy_id: str
    compartment_name: str
    compartment_id: str
    statement: str
    risk_level: str
    finding_type: str
    description: str
    recommendation: str
    affected_group: str = ""
    risk_score: int = 0

    def __post_init__(self):
        self.risk_score = RISK_SCORES.get(self.risk_level, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "policy_id": self.policy_id,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "statement": self.statement,
            "risk_level": self.risk_level,
            "finding_type": self.finding_type,
            "description": self.description,
            "recommendation": self.recommendation,
            "affected_group": self.affected_group,
            "risk_score": self.risk_score,
        }


@dataclass
class IAMAuditReport:
    """Full IAM Policy audit report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"
    total_policies_scanned: int = 0
    total_statements_scanned: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    region: str = ""
    deny_policies_exist: bool = False
    findings: List[PolicyFinding] = field(default_factory=list)
    total_users_scanned: int = 0
    total_groups_scanned: int = 0
    total_dynamic_groups_scanned: int = 0
    users: List["UserDetail"] = field(default_factory=list)
    groups: List["GroupDetail"] = field(default_factory=list)
    dynamic_groups: List["DynamicGroupDetail"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_policies_scanned": self.total_policies_scanned,
            "total_statements_scanned": self.total_statements_scanned,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "region": self.region,
            "deny_policies_exist": self.deny_policies_exist,
            "findings": [f.to_dict() for f in self.findings],
            "total_users_scanned": self.total_users_scanned,
            "total_groups_scanned": self.total_groups_scanned,
            "total_dynamic_groups_scanned": self.total_dynamic_groups_scanned,
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "dynamic_groups": [dg.to_dict() for dg in self.dynamic_groups],
        }


# ---------------------------------------------------------------------------
# Identity resource findings (Users / Groups / Dynamic Groups) — follows the
# check_id/severity/title/detail/remediation convention used by
# image_scanner.py/volume_scanner.py, distinct from the statement-centric
# PolicyFinding above since these audit resources, not policy text.
# ---------------------------------------------------------------------------
_IDENTITY_STALE_API_KEY_DAYS = 180


@dataclass
class IdentityFinding:
    """A single security finding for a User/Group/Dynamic Group."""
    resource_id: str
    resource_name: str
    compartment_name: str
    check_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "compartment_name": self.compartment_name,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class UserDetail:
    """Enriched details for an IAM User."""
    user_id: str
    user_name: str
    compartment_name: str
    compartment_id: str
    email: str
    is_mfa_activated: Optional[bool]
    lifecycle_state: str
    time_created: str
    active_api_key_count: int
    oldest_active_api_key_age_days: Optional[int]
    findings: List[IdentityFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "user_name": self.user_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "email": self.email,
            "is_mfa_activated": self.is_mfa_activated,
            "lifecycle_state": self.lifecycle_state,
            "time_created": self.time_created,
            "active_api_key_count": self.active_api_key_count,
            "oldest_active_api_key_age_days": self.oldest_active_api_key_age_days,
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
class GroupDetail:
    """Enriched details for an IAM Group."""
    group_id: str
    group_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    time_created: str
    member_count: int
    findings: List[IdentityFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "time_created": self.time_created,
            "member_count": self.member_count,
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
class DynamicGroupDetail:
    """Enriched details for a Dynamic Group (service/resource principal grouping)."""
    dynamic_group_id: str
    dynamic_group_name: str
    compartment_name: str
    compartment_id: str
    lifecycle_state: str
    time_created: str
    matching_rule: Optional[str]
    findings: List[IdentityFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dynamic_group_id": self.dynamic_group_id,
            "dynamic_group_name": self.dynamic_group_name,
            "compartment_name": self.compartment_name,
            "compartment_id": self.compartment_id,
            "lifecycle_state": self.lifecycle_state,
            "time_created": self.time_created,
            "matching_rule": self.matching_rule,
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


# ---------------------------------------------------------------------------
# Identity resource checks
# ---------------------------------------------------------------------------
def _check_user_mfa_disabled(u: UserDetail) -> Optional[IdentityFinding]:
    """Flag active users without MFA enabled."""
    if u.lifecycle_state == "ACTIVE" and u.is_mfa_activated is False:
        return IdentityFinding(
            resource_id=u.user_id, resource_name=u.user_name,
            compartment_name=u.compartment_name,
            check_id="user-mfa-disabled",
            severity="HIGH",
            title="MFA Not Enabled",
            detail=f"User '{u.user_name}' does not have multi-factor authentication activated.",
            remediation="Require the user to enroll an MFA device, or enforce MFA via an authentication policy.",
        )
    return None


def _check_user_api_key_stale(u: UserDetail) -> Optional[IdentityFinding]:
    """Flag users whose oldest active API key hasn't been rotated recently."""
    if u.oldest_active_api_key_age_days is not None and u.oldest_active_api_key_age_days > _IDENTITY_STALE_API_KEY_DAYS:
        return IdentityFinding(
            resource_id=u.user_id, resource_name=u.user_name,
            compartment_name=u.compartment_name,
            check_id="user-api-key-stale",
            severity="MEDIUM",
            title="Stale API Key",
            detail=f"User '{u.user_name}' has an active API key that is "
                   f"{u.oldest_active_api_key_age_days} days old (threshold: {_IDENTITY_STALE_API_KEY_DAYS}).",
            remediation="Rotate the API key and remove the old one.",
        )
    return None


def _check_user_api_key_sprawl(u: UserDetail) -> Optional[IdentityFinding]:
    """Flag users with more than one active API key (expanded credential attack surface)."""
    if u.active_api_key_count > 1:
        return IdentityFinding(
            resource_id=u.user_id, resource_name=u.user_name,
            compartment_name=u.compartment_name,
            check_id="user-api-key-sprawl",
            severity="MEDIUM",
            title="Multiple Active API Keys",
            detail=f"User '{u.user_name}' has {u.active_api_key_count} active API keys.",
            remediation="Remove unused API keys; keep only the single key actively in use.",
        )
    return None


USER_CHECKS = [_check_user_mfa_disabled, _check_user_api_key_stale, _check_user_api_key_sprawl]


def _check_group_empty(g: GroupDetail) -> Optional[IdentityFinding]:
    """Flag active groups with no members (housekeeping / unused policy target)."""
    if g.lifecycle_state == "ACTIVE" and g.member_count == 0:
        return IdentityFinding(
            resource_id=g.group_id, resource_name=g.group_name,
            compartment_name=g.compartment_name,
            check_id="group-empty",
            severity="LOW",
            title="Empty Group",
            detail=f"Group '{g.group_name}' has no members.",
            remediation="Remove the group if unused, or confirm it's intentionally pre-provisioned.",
        )
    return None


GROUP_CHECKS = [_check_group_empty]

# Narrowing clauses that make a dynamic-group matching rule something other
# than "every resource in this compartment" — best-effort heuristic over the
# rule's text, not a full parser of OCI's matching-rule grammar.
_DG_NARROWING_CLAUSES = ("tag.", "freeform_tag.", "defined_tag.", "resource.id", "instance.id")


def _check_dg_no_matching_rule(dg: DynamicGroupDetail) -> Optional[IdentityFinding]:
    """Flag active dynamic groups with no matching rule defined."""
    if dg.lifecycle_state == "ACTIVE" and not (dg.matching_rule or "").strip():
        return IdentityFinding(
            resource_id=dg.dynamic_group_id, resource_name=dg.dynamic_group_name,
            compartment_name=dg.compartment_name,
            check_id="dynamicgroup-no-matching-rule",
            severity="LOW",
            title="Dynamic Group Has No Matching Rule",
            detail=f"Dynamic group '{dg.dynamic_group_name}' has no matching rule — it currently "
                   "matches no principals, but any policy grants to it are dormant, not removed.",
            remediation="Remove the dynamic group and its policy grants if unused, or define a matching rule.",
        )
    return None


def _check_dg_broad_matching_rule(dg: DynamicGroupDetail) -> Optional[IdentityFinding]:
    """Flag dynamic groups whose matching rule grants membership to every
    resource in a compartment with no narrowing clause (service-principal
    over-scoping — the closest OCI equivalent to an overly broad service
    principal)."""
    rule = (dg.matching_rule or "").lower()
    if dg.lifecycle_state != "ACTIVE" or not rule:
        return None
    if "compartment.id" in rule and not any(clause in rule for clause in _DG_NARROWING_CLAUSES):
        return IdentityFinding(
            resource_id=dg.dynamic_group_id, resource_name=dg.dynamic_group_name,
            compartment_name=dg.compartment_name,
            check_id="dynamicgroup-broad-compartment-match",
            severity="MEDIUM",
            title="Overly Broad Dynamic Group Matching Rule",
            detail=f"Dynamic group '{dg.dynamic_group_name}' matches every resource in a compartment "
                   f"with no narrowing clause (tag/resource/instance). Rule: {dg.matching_rule}",
            remediation="Narrow the matching rule with a tag, resource.id, or instance.id clause "
                        "so only intended instances/resources are granted this dynamic group's policy access.",
        )
    return None


DYNAMIC_GROUP_CHECKS = [_check_dg_no_matching_rule, _check_dg_broad_matching_rule]


# ---------------------------------------------------------------------------
# Statement parser helpers
# ---------------------------------------------------------------------------
_STMT_PATTERN = re.compile(
    r"(?P<effect>allow|deny|endorse)\s+"
    r"(?P<subject>(?:any-user|group\s+\S+|dynamic-group\s+\S+|service\s+\S+))\s+"
    r"to\s+(?P<verb>\S+)\s+(?P<resource>\S+)"
    r"(?:\s+in\s+(?P<scope>.+?))??"
    r"(?:\s+where\s+(?P<conditions>.+))?$",
    re.IGNORECASE,
)

# Things we consider secret-related resource types
SECRET_RESOURCE_TYPES = {
    "secret-family", "secrets", "secret-bundles",
    "secret-versions", "vaults", "keys", "key-family",
}


def _parse_statement(stmt: str) -> Optional[Dict[str, str]]:
    """Parse a policy statement into its components."""
    stmt = stmt.strip()
    m = _STMT_PATTERN.match(stmt)
    if m:
        return m.groupdict()
    return None


def _extract_group_name(subject: str) -> str:
    """Extract the group name from a subject clause."""
    subject = subject.strip()
    for prefix in ("group ", "dynamic-group ", "service "):
        if subject.lower().startswith(prefix):
            return subject[len(prefix):].strip()
    return subject


# ---------------------------------------------------------------------------
# IAM Policy Auditor
# ---------------------------------------------------------------------------
class IAMPolicyAuditor:
    """
    Audits OCI IAM policies for security misconfigurations,
    especially around vault/secret access.
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
    # Public API
    # ------------------------------------------------------------------
    def run(self, compartment_ids: Optional[List[str]] = None,
            asset_ids: Optional[List[str]] = None) -> IAMAuditReport:
        """Run the IAM policy audit."""
        report = IAMAuditReport()

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report, compartment_ids=compartment_ids, asset_ids=asset_ids)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()

        # Tally findings — policy findings use .risk_level, identity
        # (user/group/dynamic-group) findings use .severity.
        identity_findings = (
            [f for u in report.users for f in u.findings]
            + [f for g in report.groups for f in g.findings]
            + [f for dg in report.dynamic_groups for f in dg.findings]
        )
        report.total_findings = len(report.findings) + len(identity_findings)
        report.critical_findings = (
            sum(1 for f in report.findings if f.risk_level == RISK_CRITICAL)
            + sum(1 for f in identity_findings if f.severity == "CRITICAL")
        )
        report.high_findings = (
            sum(1 for f in report.findings if f.risk_level == RISK_HIGH)
            + sum(1 for f in identity_findings if f.severity == "HIGH")
        )
        report.medium_findings = (
            sum(1 for f in report.findings if f.risk_level == RISK_MEDIUM)
            + sum(1 for f in identity_findings if f.severity == "MEDIUM")
        )
        report.low_findings = (
            sum(1 for f in report.findings if f.risk_level == RISK_LOW)
            + sum(1 for f in identity_findings if f.severity == "LOW")
        )

        return report

    # ------------------------------------------------------------------
    # Live audit
    # ------------------------------------------------------------------
    def _run_live(self, report: IAMAuditReport, compartment_ids: Optional[List[str]] = None,
                  asset_ids: Optional[List[str]] = None):
        """Audit live OCI IAM policies."""
        try:
            import oci

            self._progress("IAM Audit: Connecting to OCI Identity service...")
            identity = self.collector.get_client("identity")
            if not identity:
                self._progress("IAM Audit: Identity client not available")
                return

            tenancy_id = self.collector.config.get("tenancy")

            # The real tenancy display name, not a hardcoded literal - must
            # match the name the root compartment is imported under (see
            # collect_compartment_details), or the Scans page's
            # name-based compartment lookup for tenancy-root IAM assets
            # silently fails to resolve.
            tenancy_name = "tenancy (root)"
            try:
                tenancy_name = identity.get_compartment(tenancy_id).data.name
            except Exception as e:
                logger.debug(f"IAM Audit: could not resolve tenancy name, using fallback: {e}")

            # Collect all policies from tenancy root
            self._progress("IAM Audit: Scanning tenancy-level policies...")
            all_policies = []

            try:
                tenancy_policies = oci.pagination.list_call_get_all_results(
                    identity.list_policies, tenancy_id
                ).data
                for p in tenancy_policies:
                    all_policies.append({
                        "id": p.id,
                        "name": p.name,
                        "statements": p.statements,
                        "compartment_id": p.compartment_id,
                        "compartment_name": tenancy_name,
                    })
            except Exception as e:
                logger.error(f"IAM Audit: Error listing tenancy policies: {e}")

            # Collect policies from all compartments
            self._progress("IAM Audit: Scanning compartment-level policies...")
            try:
                if not self.collector.compartments:
                    self.collector.compartments = self.collector.collect_compartment_details()

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

                for comp in active_comps:
                    try:
                        comp_policies = identity.list_policies(comp["id"]).data
                        for p in comp_policies:
                            all_policies.append({
                                "id": p.id,
                                "name": p.name,
                                "statements": p.statements,
                                "compartment_id": comp["id"],
                                "compartment_name": comp["name"],
                            })
                    except Exception:
                        pass  # Some compartments may not be accessible
            except Exception as e:
                logger.error(f"IAM Audit: Error scanning compartments: {e}")

            report.total_policies_scanned = len(all_policies)

            # Audit each policy
            has_deny_for_secrets = False
            total_stmts = 0

            for policy in all_policies:
                for stmt in policy.get("statements", []):
                    total_stmts += 1
                    if self.run_checks:
                        findings = self._audit_statement(
                            stmt,
                            policy["name"],
                            policy["id"],
                            policy["compartment_name"],
                            policy["compartment_id"],
                        )
                        report.findings.extend(findings)

                        # Track if any deny policy for secrets exists
                        sl = stmt.lower()
                        if "deny" in sl and any(kw in sl for kw in ["secret", "secret-bundle"]):
                            has_deny_for_secrets = True

            report.total_statements_scanned = total_stmts
            report.deny_policies_exist = has_deny_for_secrets

            # Add meta-finding if no deny policy exists
            if self.run_checks and not has_deny_for_secrets:
                report.findings.append(PolicyFinding(
                    policy_name="(missing)",
                    policy_id="N/A",
                    compartment_name=tenancy_name,
                    compartment_id=tenancy_id or "",
                    statement="No deny policy found for secret-bundles",
                    risk_level=RISK_HIGH,
                    finding_type="MISSING_DENY_POLICY",
                    description=(
                        "No IAM deny policy exists to prevent reading secret bundles. "
                        "Any group with 'read all-resources' can retrieve plaintext secret values."
                    ),
                    recommendation=(
                        "Create a deny policy: "
                        "'Deny group <reader-group> to {SECRET_BUNDLE_READ} in tenancy' "
                        "for each reader group."
                    ),
                ))

            self._progress(
                f"IAM Audit: Scanned {len(all_policies)} policies, "
                f"{total_stmts} statements. "
                f"Found {len(report.findings)} findings. Complete!"
            )

            # ------------------------------------------------------------
            # Users, Groups, Dynamic Groups (root/tenancy compartment only —
            # IAM principals are conventionally created at the tenancy root,
            # unlike policies which are genuinely compartment-scoped).
            # ------------------------------------------------------------
            self._progress("IAM Audit: Scanning Users...")
            try:
                users = oci.pagination.list_call_get_all_results(
                    identity.list_users, tenancy_id
                ).data
                users = [u for u in users if u.lifecycle_state != "DELETED"]
                report.total_users_scanned = len(users)
                self._progress(f"IAM Audit: Scanning {len(users)} users ({_IDENTITY_MAX_WORKERS} threads)...")

                def _scan_user(u):
                    try:
                        api_keys = identity.list_api_keys(u.id).data
                    except Exception as e:
                        logger.debug(f"IAM Audit: could not list API keys for user {u.name}: {e}")
                        api_keys = []
                    active_keys = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
                    oldest_age = None
                    if active_keys:
                        ages = [
                            (datetime.now(timezone.utc) - k.time_created).days
                            for k in active_keys if getattr(k, "time_created", None)
                        ]
                        oldest_age = max(ages) if ages else None

                    detail = UserDetail(
                        user_id=u.id,
                        user_name=u.name,
                        compartment_name=tenancy_name,
                        compartment_id=tenancy_id or "",
                        email=getattr(u, "email", "") or "",
                        is_mfa_activated=getattr(u, "is_mfa_activated", None),
                        lifecycle_state=u.lifecycle_state,
                        time_created=str(getattr(u, "time_created", "")),
                        active_api_key_count=len(active_keys),
                        oldest_active_api_key_age_days=oldest_age,
                    )
                    if self.run_checks:
                        for check in USER_CHECKS:
                            finding = check(detail)
                            if finding:
                                detail.findings.append(finding)
                    return detail

                with ThreadPoolExecutor(max_workers=_IDENTITY_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_user, u) for u in users]
                    for f in as_completed(futures):
                        try:
                            report.users.append(f.result())
                        except Exception as e:
                            logger.error(f"IAM Audit: User scan thread error: {e}")
            except Exception as e:
                logger.error(f"IAM Audit: Error scanning users: {e}")

            self._progress("IAM Audit: Scanning Groups...")
            try:
                groups = oci.pagination.list_call_get_all_results(
                    identity.list_groups, tenancy_id
                ).data
                groups = [g for g in groups if g.lifecycle_state != "DELETED"]
                report.total_groups_scanned = len(groups)
                self._progress(f"IAM Audit: Scanning {len(groups)} groups ({_IDENTITY_MAX_WORKERS} threads)...")

                def _scan_group(g):
                    try:
                        memberships = identity.list_user_group_memberships(
                            tenancy_id, group_id=g.id
                        ).data
                        member_count = len(memberships)
                    except Exception as e:
                        logger.debug(f"IAM Audit: could not list memberships for group {g.name}: {e}")
                        member_count = 0

                    detail = GroupDetail(
                        group_id=g.id,
                        group_name=g.name,
                        compartment_name=tenancy_name,
                        compartment_id=tenancy_id or "",
                        lifecycle_state=g.lifecycle_state,
                        time_created=str(getattr(g, "time_created", "")),
                        member_count=member_count,
                    )
                    if self.run_checks:
                        for check in GROUP_CHECKS:
                            finding = check(detail)
                            if finding:
                                detail.findings.append(finding)
                    return detail

                with ThreadPoolExecutor(max_workers=_IDENTITY_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_group, g) for g in groups]
                    for f in as_completed(futures):
                        try:
                            report.groups.append(f.result())
                        except Exception as e:
                            logger.error(f"IAM Audit: Group scan thread error: {e}")
            except Exception as e:
                logger.error(f"IAM Audit: Error scanning groups: {e}")

            self._progress("IAM Audit: Scanning Dynamic Groups...")
            try:
                dynamic_groups = oci.pagination.list_call_get_all_results(
                    identity.list_dynamic_groups, tenancy_id
                ).data
                dynamic_groups = [dg for dg in dynamic_groups if dg.lifecycle_state != "DELETED"]
                report.total_dynamic_groups_scanned = len(dynamic_groups)
                self._progress(f"IAM Audit: Scanning {len(dynamic_groups)} dynamic groups ({_IDENTITY_MAX_WORKERS} threads)...")

                def _scan_dynamic_group(dg):
                    # list_dynamic_groups does not populate matching_rule —
                    # verified against a live tenancy: the list response
                    # always returns None for it. Only get_dynamic_group
                    # returns the real rule text, so one extra call per
                    # dynamic group is required (same N+1 pattern as
                    # functions_scanner's per-function get_function call).
                    matching_rule = getattr(dg, "matching_rule", None)
                    try:
                        matching_rule = identity.get_dynamic_group(dg.id).data.matching_rule
                    except Exception as e:
                        logger.debug(f"IAM Audit: could not get matching rule for dynamic group {dg.name}: {e}")

                    detail = DynamicGroupDetail(
                        dynamic_group_id=dg.id,
                        dynamic_group_name=dg.name,
                        compartment_name=tenancy_name,
                        compartment_id=tenancy_id or "",
                        lifecycle_state=dg.lifecycle_state,
                        time_created=str(getattr(dg, "time_created", "")),
                        matching_rule=matching_rule,
                    )
                    if self.run_checks:
                        for check in DYNAMIC_GROUP_CHECKS:
                            finding = check(detail)
                            if finding:
                                detail.findings.append(finding)
                    return detail

                with ThreadPoolExecutor(max_workers=_IDENTITY_MAX_WORKERS) as pool:
                    futures = [pool.submit(_scan_dynamic_group, dg) for dg in dynamic_groups]
                    for f in as_completed(futures):
                        try:
                            report.dynamic_groups.append(f.result())
                        except Exception as e:
                            logger.error(f"IAM Audit: Dynamic group scan thread error: {e}")
            except Exception as e:
                logger.error(f"IAM Audit: Error scanning dynamic groups: {e}")

            if asset_ids:
                report.users = [u for u in report.users if u.user_id in asset_ids]
                report.groups = [g for g in report.groups if g.group_id in asset_ids]
                report.dynamic_groups = [dg for dg in report.dynamic_groups if dg.dynamic_group_id in asset_ids]

            self._progress(
                f"IAM Audit: Scanned {report.total_users_scanned} users, "
                f"{report.total_groups_scanned} groups, "
                f"{report.total_dynamic_groups_scanned} dynamic groups. Complete!"
            )

        except Exception as e:
            logger.error("IAM Audit error: %s", e)
            self._progress(f"IAM Audit: Error — {e}")

    # ------------------------------------------------------------------
    # Statement auditor
    # ------------------------------------------------------------------
    def _audit_statement(
        self,
        stmt: str,
        policy_name: str,
        policy_id: str,
        compartment_name: str,
        compartment_id: str,
    ) -> List[PolicyFinding]:
        """Audit a single policy statement and return findings."""
        findings = []
        sl = stmt.lower().strip()
        compartment_id = _extract_explicit_compartment_id(stmt) or compartment_id

        # Skip deny statements (they're protective)
        if sl.startswith("deny"):
            return findings

        # Skip endorse statements (cross-tenancy, different risk model)
        if sl.startswith("endorse"):
            return findings

        # ----------------------------------------------------------
        # Check 1: 'manage all-resources in tenancy'
        # ----------------------------------------------------------
        if "manage all-resources" in sl and "in tenancy" in sl:
            group = self._extract_subject(sl)
            # Services managing their own resources is normal
            if not sl.startswith("allow service"):
                findings.append(PolicyFinding(
                    policy_name=policy_name,
                    policy_id=policy_id,
                    compartment_name=compartment_name,
                    compartment_id=compartment_id,
                    statement=stmt,
                    risk_level=RISK_CRITICAL,
                    finding_type="MANAGE_ALL_TENANCY",
                    description=(
                        f"Group '{group}' has full management access to ALL resources "
                        f"in the entire tenancy, including vaults, secrets, and IAM."
                    ),
                    recommendation=(
                        "Restrict to specific compartments and resource types. "
                        "Only the Administrators group should have tenancy-wide manage access."
                    ),
                    affected_group=group,
                ))

        # ----------------------------------------------------------
        # Check 2: 'read all-resources in tenancy'
        # ----------------------------------------------------------
        elif "read all-resources" in sl and "in tenancy" in sl:
            group = self._extract_subject(sl)
            # Check if there's a where clause excluding secrets
            has_secret_exclusion = "secret" in sl and ("!=" in sl or "not" in sl)

            if not has_secret_exclusion:
                findings.append(PolicyFinding(
                    policy_name=policy_name,
                    policy_id=policy_id,
                    compartment_name=compartment_name,
                    compartment_id=compartment_id,
                    statement=stmt,
                    risk_level=RISK_CRITICAL,
                    finding_type="READ_ALL_TENANCY_SECRETS_EXPOSED",
                    description=(
                        f"Group '{group}' can read ALL resources in the tenancy. "
                        f"This includes 'secret-bundles' which returns plaintext secret values. "
                        f"The OCI 'read' verb on 'all-resources' encompasses secret content."
                    ),
                    recommendation=(
                        "Replace with 'inspect all-resources' + specific 'read' grants "
                        "for non-sensitive resource types. Or add a deny policy to block "
                        "secret-bundles reading for this group."
                    ),
                    affected_group=group,
                ))

        # ----------------------------------------------------------
        # Check 3: 'manage all-resources in compartment'
        # ----------------------------------------------------------
        elif "manage all-resources" in sl and "compartment" in sl:
            group = self._extract_subject(sl)
            if not sl.startswith("allow service"):
                findings.append(PolicyFinding(
                    policy_name=policy_name,
                    policy_id=policy_id,
                    compartment_name=compartment_name,
                    compartment_id=compartment_id,
                    statement=stmt,
                    risk_level=RISK_MEDIUM,
                    finding_type="MANAGE_ALL_COMPARTMENT",
                    description=(
                        f"Group '{group}' has full management access to all resources "
                        f"in a compartment. This includes vault secrets within that compartment."
                    ),
                    recommendation=(
                        "Consider scoping to specific resource types. "
                        "Separate vault/secret management from general resource management."
                    ),
                    affected_group=group,
                ))

        # ----------------------------------------------------------
        # Check 4: Explicit secret-family / secret-bundles access
        # ----------------------------------------------------------
        elif any(kw in sl for kw in ["secret-family", "secret-bundles", "secrets"]):
            group = self._extract_subject(sl)
            verb = "manage" if "manage" in sl else "use" if "use" in sl else "read"
            resource = next(
                (kw for kw in ["secret-family", "secret-bundles", "secrets"] if kw in sl),
                "secrets",
            )

            risk = RISK_HIGH if verb == "manage" else RISK_MEDIUM
            findings.append(PolicyFinding(
                policy_name=policy_name,
                policy_id=policy_id,
                compartment_name=compartment_name,
                compartment_id=compartment_id,
                statement=stmt,
                risk_level=risk,
                finding_type="EXPLICIT_SECRET_ACCESS",
                description=(
                    f"Group '{group}' has explicit '{verb}' access to '{resource}'. "
                    f"{'This allows reading and modifying secret values.' if verb == 'manage' else 'This allows reading secret values.'}"
                ),
                recommendation=(
                    "Verify this access is intentional and scoped appropriately. "
                    "Prefer 'use' over 'manage' for application service accounts."
                ),
                affected_group=group,
            ))

        # ----------------------------------------------------------
        # Check 5: 'any-user' with broad access
        # ----------------------------------------------------------
        if "any-user" in sl and ("manage" in sl or "read" in sl):
            if "where" not in sl:
                findings.append(PolicyFinding(
                    policy_name=policy_name,
                    policy_id=policy_id,
                    compartment_name=compartment_name,
                    compartment_id=compartment_id,
                    statement=stmt,
                    risk_level=RISK_HIGH,
                    finding_type="ANY_USER_BROAD_ACCESS",
                    description=(
                        "Policy grants access to 'any-user' without a condition clause. "
                        "This means ANY authenticated user in the tenancy gets this permission."
                    ),
                    recommendation=(
                        "Add a 'where' condition to restrict by principal type, "
                        "group tag, or other attribute. Avoid unconditional 'any-user' policies."
                    ),
                    affected_group="any-user",
                ))

        # ----------------------------------------------------------
        # Check 6: Manage Dynamic Groups
        # ----------------------------------------------------------
        if "manage dynamic-groups" in sl:
            group = self._extract_subject(sl)
            findings.append(PolicyFinding(
                policy_name=policy_name,
                policy_id=policy_id,
                compartment_name=compartment_name,
                compartment_id=compartment_id,
                statement=stmt,
                risk_level=RISK_CRITICAL,
                finding_type="MANAGE_DYNAMIC_GROUPS",
                description=(
                    f"Group '{group}' can manage dynamic groups. "
                    f"This allows privilege escalation by modifying matching rules to include attacker-controlled instances."
                ),
                recommendation="Restrict dynamic group management to Administrators.",
                affected_group=group,
            ))

        # ----------------------------------------------------------
        # Check 7: Manage Identity Providers
        # ----------------------------------------------------------
        if "manage identity-providers" in sl or "manage federation" in sl:
            group = self._extract_subject(sl)
            findings.append(PolicyFinding(
                policy_name=policy_name,
                policy_id=policy_id,
                compartment_name=compartment_name,
                compartment_id=compartment_id,
                statement=stmt,
                risk_level=RISK_CRITICAL,
                finding_type="MANAGE_IDENTITY_PROVIDERS",
                description=(
                    f"Group '{group}' can manage identity providers/federation. "
                    f"This allows privilege escalation by mapping an external identity to privileged groups like Administrators."
                ),
                recommendation="Restrict IdP/federation management to Administrators.",
                affected_group=group,
            ))

        # ----------------------------------------------------------
        # Check 8: Manage Groups
        # ----------------------------------------------------------
        if "manage groups" in sl:
            group = self._extract_subject(sl)
            findings.append(PolicyFinding(
                policy_name=policy_name,
                policy_id=policy_id,
                compartment_name=compartment_name,
                compartment_id=compartment_id,
                statement=stmt,
                risk_level=RISK_CRITICAL,
                finding_type="MANAGE_GROUPS",
                description=(
                    f"Group '{group}' can manage groups. "
                    f"This allows an attacker to add themselves to privileged groups like Administrators."
                ),
                recommendation="Restrict group management. If needed for automation, use 'where target.group.name' conditions.",
                affected_group=group,
            ))

        # ----------------------------------------------------------
        # Check 9: Manage Authentication Policies
        # ----------------------------------------------------------
        if "manage authentication-policies" in sl:
            group = self._extract_subject(sl)
            findings.append(PolicyFinding(
                policy_name=policy_name,
                policy_id=policy_id,
                compartment_name=compartment_name,
                compartment_id=compartment_id,
                statement=stmt,
                risk_level=RISK_CRITICAL,
                finding_type="MANAGE_AUTHENTICATION_POLICIES",
                description=(
                    f"Group '{group}' can manage authentication policies. "
                    f"This allows disabling tenancy-wide MFA requirements or password complexity rules."
                ),
                recommendation="Restrict authentication policy management to Administrators.",
                affected_group=group,
            ))

        # ----------------------------------------------------------
        # Check 10: High Risk Resource Families at Tenancy Scope
        # ----------------------------------------------------------
        for resource_family in ["instance-family", "functions-family", "bastion", "keys", "vaults", "audit", "audit-events"]:
            if f"manage {resource_family}" in sl and "in tenancy" in sl:
                group = self._extract_subject(sl)
                findings.append(PolicyFinding(
                    policy_name=policy_name,
                    policy_id=policy_id,
                    compartment_name=compartment_name,
                    compartment_id=compartment_id,
                    statement=stmt,
                    risk_level=RISK_HIGH,
                    finding_type=f"MANAGE_{resource_family.upper().replace('-', '_')}_TENANCY",
                    description=(
                        f"Group '{group}' has tenancy-wide management of '{resource_family}'. "
                        f"This presents a high risk of lateral movement, persistence, or data exfiltration."
                    ),
                    recommendation=f"Restrict management of '{resource_family}' to specific compartments and authorized groups.",
                    affected_group=group,
                ))

        return findings

    def _extract_subject(self, stmt_lower: str) -> str:
        """Extract the group/subject name from a lowercase statement."""
        # Try to find 'group <name>'
        for prefix in ("allow group ", "allow dynamic-group ", "allow service "):
            if prefix in stmt_lower:
                rest = stmt_lower.split(prefix, 1)[1]
                # Group name is everything up to ' to '
                if " to " in rest:
                    return rest.split(" to ", 1)[0].strip()
        if "any-user" in stmt_lower:
            return "any-user"
        return "unknown"

    # ------------------------------------------------------------------
    # Mock data
    # ------------------------------------------------------------------
    def _run_mock(self, report: IAMAuditReport):
        """Generate mock findings for demo purposes."""
        self._progress("IAM Audit: Running in mock mode...")

        report.total_policies_scanned = 5
        report.total_statements_scanned = 12
        report.deny_policies_exist = False

        report.findings = [] if not self.run_checks else [
            PolicyFinding(
                policy_name="Tenancy-Reader",
                policy_id="ocid1.policy.oc1..mock1",
                compartment_name="tenancy (root)",
                compartment_id="ocid1.tenancy.oc1..mock",
                statement="Allow group oci_org_reader to read all-resources in tenancy",
                risk_level=RISK_CRITICAL,
                finding_type="READ_ALL_TENANCY_SECRETS_EXPOSED",
                description=(
                    "Group 'oci_org_reader' can read ALL resources including plaintext secrets."
                ),
                recommendation="Replace with 'inspect all-resources' + specific read grants.",
                affected_group="oci_org_reader",
            ),
            PolicyFinding(
                policy_name="Tenancy_Admin_Policy",
                policy_id="ocid1.policy.oc1..mock2",
                compartment_name="tenancy (root)",
                compartment_id="ocid1.tenancy.oc1..mock",
                statement="Allow group oci_org_admin to manage all-resources in tenancy",
                risk_level=RISK_CRITICAL,
                finding_type="MANAGE_ALL_TENANCY",
                description=(
                    "Group 'oci_org_admin' has full management access to the entire tenancy."
                ),
                recommendation="Restrict to Administrators group only.",
                affected_group="oci_org_admin",
            ),
            PolicyFinding(
                policy_name="(missing)",
                policy_id="N/A",
                compartment_name="tenancy",
                compartment_id="ocid1.tenancy.oc1..mock",
                statement="No deny policy found for secret-bundles",
                risk_level=RISK_HIGH,
                finding_type="MISSING_DENY_POLICY",
                description="No deny policy exists to prevent reading secret bundles.",
                recommendation="Create deny policies for reader groups.",
            ),
        ]

        report.compartments_scanned = 1

        # Users: one risky (no MFA, stale+sprawled keys), one clean.
        report.total_users_scanned = 2
        risky_user = UserDetail(
            user_id="ocid1.user.oc1..mock1", user_name="svc-legacy-deploy",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            email="", is_mfa_activated=False, lifecycle_state="ACTIVE",
            time_created="2023-01-10T00:00:00Z", active_api_key_count=2,
            oldest_active_api_key_age_days=400,
        )
        if self.run_checks:
            for check in USER_CHECKS:
                f = check(risky_user)
                if f:
                    risky_user.findings.append(f)
        clean_user = UserDetail(
            user_id="ocid1.user.oc1..mock2", user_name="jane.doe",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            email="jane.doe@example.com", is_mfa_activated=True, lifecycle_state="ACTIVE",
            time_created="2025-05-01T00:00:00Z", active_api_key_count=1,
            oldest_active_api_key_age_days=20,
        )
        if self.run_checks:
            for check in USER_CHECKS:
                f = check(clean_user)
                if f:
                    clean_user.findings.append(f)
        report.users = [risky_user, clean_user]

        # Groups: one empty (risky), one populated (clean).
        report.total_groups_scanned = 2
        empty_group = GroupDetail(
            group_id="ocid1.group.oc1..mock1", group_name="legacy-unused-group",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            lifecycle_state="ACTIVE", time_created="2022-03-01T00:00:00Z", member_count=0,
        )
        if self.run_checks:
            for check in GROUP_CHECKS:
                f = check(empty_group)
                if f:
                    empty_group.findings.append(f)
        active_group = GroupDetail(
            group_id="ocid1.group.oc1..mock2", group_name="oci_org_developers",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            lifecycle_state="ACTIVE", time_created="2024-01-01T00:00:00Z", member_count=8,
        )
        if self.run_checks:
            for check in GROUP_CHECKS:
                f = check(active_group)
                if f:
                    active_group.findings.append(f)
        report.groups = [empty_group, active_group]

        # Dynamic Groups: one overly broad (risky), one scoped (clean).
        report.total_dynamic_groups_scanned = 2
        broad_dg = DynamicGroupDetail(
            dynamic_group_id="ocid1.dynamicgroup.oc1..mock1", dynamic_group_name="all-compute-instances",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            lifecycle_state="ACTIVE", time_created="2023-06-01T00:00:00Z",
            matching_rule="ALL {instance.compartment.id = 'ocid1.tenancy.oc1..mock'}",
        )
        if self.run_checks:
            for check in DYNAMIC_GROUP_CHECKS:
                f = check(broad_dg)
                if f:
                    broad_dg.findings.append(f)
        scoped_dg = DynamicGroupDetail(
            dynamic_group_id="ocid1.dynamicgroup.oc1..mock2", dynamic_group_name="ci-runner-instances",
            compartment_name="tenancy (root)", compartment_id="ocid1.tenancy.oc1..mock",
            lifecycle_state="ACTIVE", time_created="2024-08-01T00:00:00Z",
            matching_rule="ALL {instance.compartment.id = 'ocid1.compartment.oc1..ci', tag.CI.Role.value = 'runner'}",
        )
        if self.run_checks:
            for check in DYNAMIC_GROUP_CHECKS:
                f = check(scoped_dg)
                if f:
                    scoped_dg.findings.append(f)
        report.dynamic_groups = [broad_dg, scoped_dg]

        self._progress("IAM Audit: Mock audit complete!")


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------
def run_iam_audit(
    collector=None,
    compartment_ids=None,
    asset_ids=None,
    progress_callback=None,
    run_checks: bool = True,
) -> Dict[str, Any]:
    """Run IAM policy audit and return results as a dict."""
    auditor = IAMPolicyAuditor(
        collector=collector,
        progress_callback=progress_callback,
        run_checks=run_checks,
    )
    report = auditor.run(compartment_ids=compartment_ids, asset_ids=asset_ids)
    return report.to_dict()


def _demo():
    assert _extract_explicit_compartment_id(
        "Allow dynamic-group vault-dg to read secret-family in compartment id "
        "ocid1.compartment.oc1..aaaaaaaaexampleexampleexampleexampleexampleexample "
        "where all {target.vault.id = 'x', target.secret.name = 'y'}"
    ) == "ocid1.compartment.oc1..aaaaaaaaexampleexampleexampleexampleexampleexample"
    assert _extract_explicit_compartment_id("Allow group Admins to manage all-resources in tenancy") is None
    assert _extract_explicit_compartment_id("Allow group X to read buckets in compartment Finance") is None
    print("iam_policy_audit self-check OK")


if __name__ == "__main__":
    _demo()
