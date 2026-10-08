"""
Clouds8 – Report Generator
Produces CSV and PDF exports for CIS Benchmark and Secret Scanner results.
"""

import csv
import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Colour palette (RGB tuples)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_CLR_BRAND    = (0, 212, 255)       # cyan accent
_CLR_DARK     = (30, 40, 55)        # page bg
_CLR_CARD     = (40, 52, 68)        # card bg
_CLR_WHITE    = (230, 235, 240)
_CLR_MUTED    = (140, 155, 170)
_CLR_PASS     = (40, 200, 120)
_CLR_FAIL     = (110, 26, 55)    # #6E1A37 — brand burgundy for non-compliant
_CLR_WARN     = (240, 180, 40)
_CLR_INFO     = (60, 170, 240)

_SEV_COLORS = {
    "critical": (230, 70, 70),
    "high":     (240, 180, 40),
    "medium":   (60, 170, 240),
    "low":      (40, 200, 120),
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _safe(val: Any, max_len: int = 120) -> str:
    """Sanitise a value for PDF cell rendering (latin-1 only)."""
    s = str(val) if val else ""
    # Replace common Unicode chars with ASCII equivalents
    replacements = {
        "\u2026": "...",   # ellipsis
        "\u2018": "'",     # left single quote
        "\u2019": "'",     # right single quote
        "\u201c": '"',     # left double quote
        "\u201d": '"',     # right double quote
        "\u2014": "--",    # em dash
        "\u2013": "-",     # en dash
        "\u2022": "*",     # bullet
        "\u2192": "->",    # right arrow
        "\u2190": "<-",    # left arrow
        "\u2265": ">=",    # greater than or equal
        "\u2264": "<=",    # less than or equal
        "\u00a7": "S.",    # section sign
        "\u00d7": "x",     # multiplication sign
        "\u00b0": "deg",   # degree sign
        "\u2705": "[OK]",  # check mark
        "\u274c": "[X]",   # cross mark
        "\u26a0\ufe0f": "[!]",  # warning
        "\u26a0": "[!]",   # warning (without variation selector)
        "\u200b": "",      # zero-width space
        "\u00e2\u0080\u0094": "--",  # UTF-8 encoded em dash bytes (misread)
    }
    for uchar, replacement in replacements.items():
        s = s.replace(uchar, replacement)
    # Final encode/decode to strip anything remaining
    s = s.encode("latin-1", errors="replace").decode("latin-1")
    if len(s) > max_len:
        s = s[:max_len - 3] + "..."
    return s


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _format_file_size(size_bytes: Optional[int]) -> str:
    if size_bytes is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Base PDF class with dark theme
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class _LynxPDF(FPDF):
    """Custom FPDF subclass with Clouds8 branding."""

    def __init__(self, title: str):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.report_title = title
        self.set_auto_page_break(auto=True, margin=15)

    # ── Header / Footer ───────────────────────────────────────────────────
    def header(self):
        # Dark banner
        self.set_fill_color(*_CLR_DARK)
        self.rect(0, 0, self.w, 18, "F")

        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*_CLR_BRAND)
        self.set_xy(8, 4)
        self.cell(0, 10, "Clouds8", new_x="RIGHT", new_y="TOP")

        self.set_font("Helvetica", "", 10)
        self.set_text_color(*_CLR_WHITE)
        self.cell(0, 10, f"  {self.report_title}", new_x="LMARGIN", new_y="NEXT")
        self.ln(6)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*_CLR_MUTED)
        self.cell(0, 10, f"Generated {_now_str()}  |  Page {self.page_no()}/{{nb}}", align="C")

    # ── Utility methods ───────────────────────────────────────────────────
    def section_title(self, text: str):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*_CLR_BRAND)
        self.cell(0, 8, _safe(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_CLR_BRAND)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def summary_cell(self, label: str, value: str, color: tuple, width: float = 55):
        x0, y0 = self.get_x(), self.get_y()
        self.set_fill_color(*_CLR_CARD)
        self.rect(x0, y0, width, 18, "F")

        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*color)
        self.set_xy(x0 + 3, y0 + 1)
        self.cell(width - 6, 9, value, new_x="LEFT", new_y="NEXT")

        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_CLR_MUTED)
        self.set_xy(x0 + 3, y0 + 11)
        self.cell(width - 6, 5, label)

        self.set_xy(x0 + width + 4, y0)

    def table_header(self, cols: List[tuple]):
        """cols = [(label, width), ...]"""
        self.set_fill_color(*_CLR_CARD)
        self.set_text_color(*_CLR_WHITE)
        self.set_font("Helvetica", "B", 7)
        for label, w in cols:
            self.cell(w, 7, label, border=0, fill=True, align="C")
        self.ln()

    def table_row(self, cells: List[tuple], highlight: bool = False):
        """cells = [(text, width, align), ...]"""
        if highlight:
            self.set_fill_color(80, 18, 38)   # slightly lighter than #6E1A37 for row bg
        else:
            self.set_fill_color(*_CLR_DARK)
        self.set_text_color(*_CLR_WHITE)
        self.set_font("Helvetica", "", 7)
        max_h = 6
        for text, w, align in cells:
            self.cell(w, max_h, _safe(text, 60), border=0, fill=True, align=align)
        self.ln()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CIS BENCHMARK – CSV
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_cis_csv(report: Dict) -> str:
    """Return a CSV string from a CIS benchmark report dict."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Metadata rows
    writer.writerow(["Clouds8 CIS OCI Benchmark Report"])
    writer.writerow(["Generated", _now_str()])
    writer.writerow(["Scan Mode", report.get("scan_mode", "")])
    writer.writerow(["Scan Time", report.get("scan_time", "")])
    writer.writerow(["Compliance %", report.get("compliance_pct", "")])
    writer.writerow(["Total Checks", report.get("total_checks", 0)])
    writer.writerow(["Passed", report.get("passed", 0)])
    writer.writerow(["Failed", report.get("failed", 0)])
    writer.writerow(["Errors", report.get("errors", 0)])
    writer.writerow([])

    # Findings header
    writer.writerow([
        "Check ID", "Title", "Category", "Severity",
        "Status", "Evidence", "Affected Resources", "Remediation",
    ])

    for r in report.get("results", []):
        resources = "; ".join(r.get("affected_resources", []))
        writer.writerow([
            r.get("check_id", ""),
            r.get("title", ""),
            r.get("category", ""),
            r.get("severity", ""),
            r.get("status", ""),
            r.get("evidence", ""),
            resources,
            r.get("remediation", ""),
        ])

    return buf.getvalue()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CIS BENCHMARK – PDF
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# Compliance framework cross-references (CIS ID -> frameworks)
_CIS_FRAMEWORKS = {
    "CIS-1.1": {"pci": "PCI 8.3",  "iso": "A.9.4.2", "nist": "IA-2"},
    "CIS-1.2": {"pci": "PCI 8.2",  "iso": "A.9.2.6", "nist": "IA-5"},
    "CIS-1.3": {"pci": "PCI 8.1",  "iso": "A.9.2.3", "nist": "AC-6"},
    "CIS-1.4": {"pci": "PCI 8.2",  "iso": "A.9.2.6", "nist": "IA-5"},
    "CIS-1.5": {"pci": "PCI 7.1",  "iso": "A.9.1.2", "nist": "AC-6"},
    "CIS-1.6": {"pci": "PCI 8.1",  "iso": "A.9.2.6", "nist": "AC-2"},
    "CIS-1.7": {"pci": "PCI 8.2",  "iso": "A.9.4.3", "nist": "IA-5"},
    "CIS-2.1": {"pci": "PCI 1.2",  "iso": "A.13.1.1","nist": "SC-7"},
    "CIS-2.2": {"pci": "PCI 1.2",  "iso": "A.13.1.1","nist": "SC-7"},
    "CIS-2.3": {"pci": "PCI 1.2",  "iso": "A.13.1.3","nist": "SC-7"},
    "CIS-2.4": {"pci": "PCI 1.3",  "iso": "A.13.1.2","nist": "SC-7"},
    "CIS-3.1": {"pci": "PCI 3.3",  "iso": "A.8.2.3", "nist": "AC-3"},
    "CIS-3.2": {"pci": "PCI 3.1",  "iso": "A.8.2.2", "nist": "SI-12"},
    "CIS-3.3": {"pci": "PCI 3.4",  "iso": "A.10.1.1","nist": "SC-28"},
    "CIS-4.1": {"pci": "PCI 2.2",  "iso": "A.12.6.2","nist": "CM-6"},
    "CIS-4.2": {"pci": "PCI 10.6", "iso": "A.12.4.1","nist": "SI-4"},
    "CIS-4.3": {"pci": "PCI 1.3",  "iso": "A.13.1.2","nist": "SC-7"},
    "CIS-4.4": {"pci": "PCI 2.2",  "iso": "A.12.6.2","nist": "CM-6"},
    "CIS-5.1": {"pci": "PCI 10.7", "iso": "A.12.4.1","nist": "AU-11"},
    "CIS-5.2": {"pci": "PCI 11.4", "iso": "A.12.6.1","nist": "SI-4"},
    "CIS-6.1": {"pci": "PCI 3.6",  "iso": "A.10.1.2","nist": "SC-12"},
}

# Extended guidance per control
_CIS_GUIDANCE = {
    "CIS-1.1": (
        "What it means: Any user who can log into the OCI Console without MFA is a single-factor "
        "authentication risk. If credentials are phished or brute-forced, an attacker gains immediate "
        "persistent access with no second barrier.\n"
        "How to fix: Navigate to Identity > Users, select each listed user, and enable MFA under the "
        "'Multi-Factor Authentication' section. Consider enforcing MFA via an Identity Provider (IdP) "
        "policy if using federated login."
    ),
    "CIS-1.2": (
        "What it means: API keys older than 90 days represent a window where a leaked or stolen key "
        "may have been used undetected. Long-lived credentials are a top attack vector.\n"
        "How to fix: Rotate API keys at Identity > Users > [User] > API Keys. Delete old keys and "
        "generate new ones. Automate rotation via scripts triggered on a schedule."
    ),
    "CIS-1.3": (
        "What it means: Administrator accounts should never use API keys, since these credentials can "
        "be extracted from developer environments and grant full tenancy control.\n"
        "How to fix: Remove all API keys from Administrators group members. Create separate service "
        "accounts for automation tasks with narrowly scoped least-privilege policies."
    ),
    "CIS-1.4": (
        "What it means: Auth tokens are long-lived secrets used for legacy services like OCIR and IDCS. "
        "Unrotated tokens pose long-term credential compromise risk.\n"
        "How to fix: Delete and regenerate auth tokens at Identity > Users > [User] > Auth Tokens. "
        "Ensure rotation is performed every 90 days."
    ),
    "CIS-1.5": (
        "What it means: Policies granting 'manage all-resources' or 'use all-resources' give a group "
        "administrator-equivalent access over an entire compartment scope, enabling privilege escalation.\n"
        "How to fix: Audit policies via 'oci iam policy list --all'. Replace wildcard permissions with "
        "specific resource-type verbs. Follow the principle of least privilege."
    ),
    "CIS-1.6": (
        "What it means: Dormant accounts that haven't logged in for 90+ days are high-value targets — "
        "they may be forgotten, not monitored, and still hold active permissions.\n"
        "How to fix: Disable or delete users via Identity > Users. Consider implementing a periodic "
        "access review process or automated lifecycle management."
    ),
    "CIS-1.7": (
        "What it means: Weak password policies allow credential stuffing and brute-force attacks to "
        "succeed quickly. CIS requires minimum 14 characters with complexity requirements.\n"
        "How to fix: Navigate to Identity > Authentication Settings > Password Policy and enforce: "
        "min length 14, uppercase, lowercase, number, and special character requirements."
    ),
    "CIS-2.1": (
        "What it means: Security lists permitting inbound SSH (port 22) from 0.0.0.0/0 expose every "
        "host in the subnet to internet-wide brute-force and exploitation attacks.\n"
        "How to fix: Edit each flagged security list and restrict the SSH ingress rule source CIDR to "
        "your corporate IP range or VPN gateway. Consider using OCI Bastion service instead."
    ),
    "CIS-2.2": (
        "What it means: RDP (port 3389) open to the world is one of the most exploited vectors for "
        "ransomware delivery and lateral movement on Windows workloads.\n"
        "How to fix: Restrict RDP ingress rules to known IP ranges only. Use OCI Bastion sessions "
        "for RDP access to Windows instances rather than direct internet exposure."
    ),
    "CIS-2.3": (
        "What it means: Rules allowing all protocols from 0.0.0.0/0 (wildcard ingress) create an "
        "unrestricted attack surface, enabling port scanners, exploit kits, and data exfiltration.\n"
        "How to fix: Replace catch-all rules with specific protocol/port/CIDR rules. Audit each "
        "security list to ensure only required traffic is permitted."
    ),
    "CIS-2.4": (
        "What it means: Subnets that automatically assign public IPs expand your attack surface. "
        "Private workloads (app servers, databases) should never be directly reachable from the internet.\n"
        "How to fix: Set 'Prohibit Public IP on VNIC' to true for all private subnets. Route public "
        "traffic through a load balancer or NAT gateway instead."
    ),
    "CIS-3.1": (
        "What it means: Public buckets can be accessed by anyone on the internet without authentication. "
        "This is the #1 cause of cloud data breaches and accidental data exposure incidents.\n"
        "How to fix: In Object Storage > [Bucket] > Edit Visibility, set access type to 'Private'. "
        "Use Pre-Authenticated Requests (PARs) with expiry dates for any required temporary sharing."
    ),
    "CIS-3.2": (
        "What it means: Without versioning, a ransomware attack or accidental deletion permanently "
        "destroys data. Versioning ensures objects can be recovered to any prior state.\n"
        "How to fix: Enable versioning at Object Storage > [Bucket] > Edit and toggle 'Versioning'. "
        "Set a lifecycle policy to expire old versions after a defined retention period."
    ),
    "CIS-3.3": (
        "What it means: Oracle-managed encryption keys are outside your control. If OCI's key "
        "management is ever compromised, your data has no additional protection layer.\n"
        "How to fix: Create a master encryption key in OCI Vault (KMS). Assign it to each bucket via "
        "Object Storage > [Bucket] > Encryption Key."
    ),
    "CIS-4.1": (
        "What it means: The legacy IMDSv1 endpoint can be queried without tokens, making it vulnerable "
        "to SSRF attacks that steal instance principal credentials and escalate privileges.\n"
        "How to fix: On each instance, set instanceOptions.areLegacyImdsEndpointsDisabled=true via "
        "'oci compute instance update'. New instances should default to IMDSv2 only."
    ),
    "CIS-4.2": (
        "What it means: Without the monitoring agent, you have no visibility into CPU, memory, or "
        "process-level anomalies that indicate compromise or misconfiguration.\n"
        "How to fix: Enable the 'Oracle Cloud Agent' monitoring plugin at Compute > Instance > "
        "Oracle Cloud Agent tab. Ensure the agent is running and healthy."
    ),
    "CIS-4.3": (
        "What it means: Publicly accessible instances without a clear business need increase the "
        "attack surface. Any open port on a public IP can be scanned and exploited.\n"
        "How to fix: Remove public IPs from instances that only require private connectivity. "
        "Use a NAT gateway for outbound traffic and a load balancer for inbound."
    ),
    "CIS-4.4": (
        "What it means: IMDSv1 is vulnerable to SSRF (Server-Side Request Forgery) attacks, which "
        "allow web application vulnerabilities to leak instance principal tokens. These tokens can be "
        "used to assume IAM roles and escalate privileges across your tenancy.\n"
        "How to fix: Disable legacy IMDS endpoints on all instances. Use IMDSv2 with token-based "
        "authentication. Audit applications to ensure they use the v2 token header."
    ),
    "CIS-5.1": (
        "What it means: Retaining audit logs for less than 365 days means security investigations, "
        "compliance audits, and forensic analysis may lack the historical data needed.\n"
        "How to fix: In Governance > Audit > Configuration, set retention to 365+ days. For longer "
        "retention, archive audit events to Object Storage using Service Connector Hub."
    ),
    "CIS-5.2": (
        "What it means: Cloud Guard continuously monitors your tenancy for security misconfigurations, "
        "threats, and insecure activity. Without it, you have no automated threat detection.\n"
        "How to fix: Navigate to Security > Cloud Guard > Enable. Select a reporting region and "
        "configure detector and responder recipes appropriate for your workload."
    ),
    "CIS-6.1": (
        "What it means: Encryption keys that have not been rotated for over a year represent a "
        "long-term compromise risk. If a key is ever exposed, all data encrypted with it is at risk.\n"
        "How to fix: Enable automatic key rotation in KMS > [Key] > Rotation Policy. Set the rotation "
        "interval to 365 days or fewer. For critical keys, consider 90-day rotation cycles."
    ),
}


def _draw_risk_gauge(pdf: _LynxPDF, pct: float, x: float, y: float, r: float = 18):
    """Draw a simple semicircular compliance score gauge."""
    import math
    # Background arc (grey)
    cx, cy = x + r, y + r
    pdf.set_draw_color(*_CLR_CARD)
    pdf.set_line_width(4)
    # Draw a filled circle as background
    pdf.set_fill_color(*_CLR_CARD)
    pdf.ellipse(cx - r, cy - r, r * 2, r * 2, "F")

    # Score text
    color = _CLR_PASS if pct >= 80 else (_CLR_WARN if pct >= 50 else _CLR_FAIL)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*color)
    pdf.set_xy(cx - r, cy - 5)
    pdf.cell(r * 2, 10, f"{pct:.0f}%", align="C")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*_CLR_MUTED)
    pdf.set_xy(cx - r, cy + 6)
    pdf.cell(r * 2, 5, "Compliance", align="C")


def _control_card(pdf: _LynxPDF, r: Dict, page_w: float):
    """Render a detailed card for a single CIS control."""
    status = r.get("status", "")
    sev = r.get("severity", "informational").lower()
    check_id = r.get("check_id", "")

    status_color = _CLR_PASS if status == "PASS" else (_CLR_FAIL if status == "FAIL" else _CLR_WARN)
    sev_color = _SEV_COLORS.get(sev, _CLR_MUTED)

    # Card header bar
    x0 = pdf.l_margin
    y0 = pdf.get_y()
    card_w = page_w - pdf.l_margin - pdf.r_margin

    pdf.set_fill_color(*_CLR_CARD)
    pdf.rect(x0, y0, card_w, 9, "F")

    # Status pill
    pdf.set_fill_color(*status_color)
    pdf.rect(x0, y0, 18, 9, "F")
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(10, 10, 10)
    pdf.set_xy(x0, y0 + 1)
    pdf.cell(18, 7, status, align="C")

    # Severity pill
    pdf.set_fill_color(*sev_color)
    pdf.rect(x0 + 19, y0, 18, 9, "F")
    pdf.set_text_color(10, 10, 10)
    pdf.set_xy(x0 + 19, y0 + 1)
    pdf.cell(18, 7, sev.upper(), align="C")

    # Check ID + Title
    pdf.set_text_color(*_CLR_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_xy(x0 + 40, y0 + 1)
    pdf.cell(card_w - 40, 7, _safe(f"{check_id}  —  {r.get('title', '')}"), align="L")

    pdf.ln(10)
    body_x = x0 + 4
    body_w = card_w - 8

    # Evidence
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*_CLR_BRAND)
    pdf.set_x(body_x)
    pdf.cell(body_w, 5, "Finding:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*_CLR_WHITE)
    pdf.set_x(body_x)
    pdf.multi_cell(body_w, 4, _safe(r.get("evidence", "No evidence recorded."), 300))

    # Guidance block (only for FAIL)
    if status == "FAIL":
        guidance = _CIS_GUIDANCE.get(check_id, "")
        if guidance:
            pdf.set_x(body_x)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*_CLR_WARN)
            pdf.cell(body_w, 5, "Compliance Guidance:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*_CLR_WHITE)
            pdf.set_x(body_x)
            pdf.multi_cell(body_w, 4, _safe(guidance, 800))

        # Affected resources
        resources = r.get("affected_resources", [])
        if resources:
            pdf.set_x(body_x)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*_CLR_FAIL)
            pdf.cell(body_w, 5, f"Affected Resources ({len(resources)}):", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*_CLR_MUTED)
            for res in resources[:8]:
                pdf.set_x(body_x + 4)
                pdf.cell(body_w - 4, 4, _safe(f"* {res}", 120), new_x="LMARGIN", new_y="NEXT")
            if len(resources) > 8:
                pdf.set_x(body_x + 4)
                pdf.cell(body_w - 4, 4, _safe(f"  ... and {len(resources) - 8} more", 80),
                         new_x="LMARGIN", new_y="NEXT")

    # Compliance frameworks
    frameworks = _CIS_FRAMEWORKS.get(check_id, {})
    if frameworks:
        pdf.set_x(body_x)
        pdf.set_font("Helvetica", "I", 6)
        pdf.set_text_color(*_CLR_MUTED)
        fw_str = "  |  ".join([
            f"PCI-DSS: {frameworks.get('pci', 'N/A')}",
            f"ISO 27001: {frameworks.get('iso', 'N/A')}",
            f"NIST 800-53: {frameworks.get('nist', 'N/A')}",
        ])
        pdf.cell(body_w, 4, _safe(fw_str, 200), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)


def generate_cis_pdf(report: Dict) -> bytes:
    """Return a comprehensive PDF from a CIS benchmark report dict."""
    pdf = _LynxPDF("CIS OCI Foundations Benchmark Report")
    pdf.alias_nb_pages()

    results = report.get("results", [])
    pct = report.get("compliance_pct", 0)
    passed = report.get("passed", 0)
    failed = report.get("failed", 0)
    errors = report.get("errors", 0)
    total = report.get("total_checks", 0)
    mode = report.get("scan_mode", "unknown").upper()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # COVER PAGE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pdf.add_page()
    page_w = pdf.w

    # Full dark banner
    pdf.set_fill_color(*_CLR_DARK)
    pdf.rect(0, 0, page_w, pdf.h, "F")

    # Brand name
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(*_CLR_BRAND)
    pdf.set_xy(0, 50)
    pdf.cell(page_w, 20, "Clouds8", align="C")

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*_CLR_WHITE)
    pdf.set_xy(0, 72)
    pdf.cell(page_w, 10, _safe("OCI CIS Foundations Benchmark -- Compliance Report"), align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_CLR_MUTED)
    pdf.set_xy(0, 85)
    pdf.cell(page_w, 8, f"Generated: {_now_str()}   |   Scan Mode: {mode}", align="C")

    # Risk posture box
    box_x = page_w / 2 - 60
    box_y = 105
    pdf.set_fill_color(*_CLR_CARD)
    pdf.rect(box_x, box_y, 120, 60, "F")

    score_clr = _CLR_PASS if pct >= 80 else (_CLR_WARN if pct >= 50 else _CLR_FAIL)
    pdf.set_font("Helvetica", "B", 42)
    pdf.set_text_color(*score_clr)
    pdf.set_xy(box_x, box_y + 8)
    pdf.cell(120, 22, f"{pct:.0f}%", align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_CLR_WHITE)
    pdf.set_xy(box_x, box_y + 33)
    pdf.cell(120, 8, "Overall Compliance Score", align="C")

    # Passed / Failed / Total
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_CLR_PASS)
    pdf.set_xy(box_x + 5, box_y + 44)
    pdf.cell(35, 6, f"PASS: {passed}", align="C")
    pdf.set_text_color(*_CLR_FAIL)
    pdf.set_xy(box_x + 42, box_y + 44)
    pdf.cell(35, 6, f"FAIL: {failed}", align="C")
    pdf.set_text_color(*_CLR_WARN)
    pdf.set_xy(box_x + 79, box_y + 44)
    pdf.cell(35, 6, f"ERR: {errors}", align="C")

    # Risk level label
    risk_label = "LOW RISK" if pct >= 80 else ("MEDIUM RISK" if pct >= 50 else "HIGH RISK")
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*score_clr)
    pdf.set_xy(0, 178)
    pdf.cell(page_w, 8, f"Tenancy Risk Posture: {risk_label}", align="C")

    # Scope note
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*_CLR_MUTED)
    pdf.set_xy(0, 188)
    pdf.cell(page_w, 6,
             "CIS OCI Foundations Benchmark v2.0 | Automated evaluation against live tenancy data",
             align="C")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PAGE 2: EXECUTIVE SUMMARY + CATEGORY BREAKDOWN
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pdf.add_page()
    pdf.section_title("Executive Summary")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_CLR_WHITE)
    summary_text = (
        f"This report presents the findings of an automated CIS OCI Foundations Benchmark assessment "
        f"covering {total} controls across Identity & Access Management, Networking, Storage, Compute, "
        f"Logging & Monitoring, and Key Management. "
        f"The tenancy achieved a compliance score of {pct:.0f}%, with {passed} controls passing and "
        f"{failed} requiring immediate remediation. "
        f"The overall risk posture is rated {risk_label}. "
        "Priority should be given to CRITICAL and HIGH severity failures as they represent active "
        "security risks exposed to exploitation paths such as privilege escalation, data exfiltration, "
        "and unauthorized access."
    )
    pdf.multi_cell(0, 5, _safe(summary_text, 800))
    pdf.ln(5)

    # Summary metric cells
    pdf.summary_cell("Compliance Score", f"{pct:.0f}%", score_clr)
    pdf.summary_cell("Passed", str(passed), _CLR_PASS)
    pdf.summary_cell("Failed", str(failed), _CLR_FAIL)
    pdf.summary_cell("Errors", str(errors), _CLR_WARN)
    pdf.summary_cell("Total Controls", str(total), _CLR_INFO)
    pdf.ln(25)

    # ── Category Breakdown ─────────────────────────────────────────
    pdf.section_title("Category Breakdown")

    categories: Dict[str, Dict] = {}
    for r in results:
        cat = r.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0, "error": 0, "controls": []}
        st = r.get("status", "")
        if st == "PASS":
            categories[cat]["pass"] += 1
        elif st == "FAIL":
            categories[cat]["fail"] += 1
        else:
            categories[cat]["error"] += 1
        categories[cat]["controls"].append(r)

    cols = [("Category", 75), ("Controls", 22), ("Passed", 22), ("Failed", 22),
            ("Errors", 22), ("Pass Rate", 28), ("Risk Level", 30)]
    pdf.table_header(cols)
    for cat, c in categories.items():
        total_cat = c["pass"] + c["fail"] + c["error"]
        rate_pct = round(100 * c["pass"] / total_cat) if total_cat else 0
        rate = f"{rate_pct}%"
        risk = "LOW" if rate_pct >= 80 else ("MEDIUM" if rate_pct >= 50 else "HIGH")
        pdf.table_row([
            (cat, 75, "L"),
            (str(total_cat), 22, "C"),
            (str(c["pass"]), 22, "C"),
            (str(c["fail"]), 22, "C"),
            (str(c["error"]), 22, "C"),
            (rate, 28, "C"),
            (risk, 30, "C"),
        ], highlight=(rate_pct < 50))
    pdf.ln(6)

    # ── Critical + High failures callout ─────────────────────────
    critical_fails = [r for r in results if r.get("status") == "FAIL"
                      and r.get("severity", "").lower() in ("critical", "high")]
    if critical_fails:
        pdf.section_title(f"Immediate Action Required — {len(critical_fails)} Critical/High Failures")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*_CLR_WHITE)
        pdf.multi_cell(0, 4, _safe(
            "The following controls represent the highest-priority risk items. "
            "These should be remediated before all others as they are actively exploitable "
            "and may result in data breach, account takeover, or privilege escalation."
        ))
        pdf.ln(3)
        cols = [("Check ID", 20), ("Severity", 20), ("Category", 45), ("Control Title", 140)]
        pdf.table_header(cols)
        for r in critical_fails:
            pdf.table_row([
                (r.get("check_id", ""), 20, "C"),
                (r.get("severity", "").upper(), 20, "C"),
                (r.get("category", ""), 45, "L"),
                (r.get("title", ""), 140, "L"),
            ], highlight=True)
        pdf.ln(6)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PAGES 3+: DETAILED CONTROL FINDINGS (grouped by category)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pdf.add_page()
    pdf.section_title("Detailed Control Findings")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*_CLR_MUTED)
    pdf.multi_cell(0, 4, _safe(
        "Each control below shows its pass/fail status, the evidence collected from your tenancy, "
        "detailed compliance guidance explaining what the risk means and how to fix it, "
        "all affected resources, and the applicable compliance framework references."
    ))
    pdf.ln(5)

    for cat, c in categories.items():
        # Category section header
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_CLR_BRAND)
        cat_pass = c["pass"]
        cat_fail = c["fail"]
        cat_total = cat_pass + cat_fail + c["error"]
        cat_pct = round(100 * cat_pass / cat_total) if cat_total else 0
        pdf.cell(0, 7,
                 _safe(f"Section: {cat}   ({cat_pass}/{cat_total} passing -- {cat_pct}%)"),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(*_CLR_CARD)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(3)

        for ctrl in c["controls"]:
            # Ensure enough space for a card; if not, start a new page
            if pdf.get_y() > pdf.h - 60:
                pdf.add_page()
            _control_card(pdf, ctrl, page_w)

        pdf.ln(4)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINAL PAGE: PRIORITISED REMEDIATION PLAN
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    failed_all = [r for r in results if r.get("status") == "FAIL"]
    if failed_all:
        pdf.add_page()
        pdf.section_title("Prioritised Remediation Action Plan")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*_CLR_MUTED)
        pdf.multi_cell(0, 4, _safe(
            "The following remediation actions are ordered by severity. Address CRITICAL items first, "
            "followed by HIGH, MEDIUM, and LOW. Each item includes the step-by-step console path "
            "or CLI command required to achieve compliance."
        ))
        pdf.ln(4)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_fails = sorted(failed_all,
                              key=lambda x: sev_order.get(x.get("severity", "low").lower(), 9))

        for idx, r in enumerate(sorted_fails, 1):
            sev = r.get("severity", "informational").lower()
            sev_color = _SEV_COLORS.get(sev, _CLR_MUTED)
            check_id = r.get("check_id", "")

            if pdf.get_y() > pdf.h - 55:
                pdf.add_page()

            # Item number + ID + severity badge
            x0 = pdf.l_margin
            y0 = pdf.get_y()
            card_w = page_w - pdf.l_margin - pdf.r_margin

            pdf.set_fill_color(*sev_color)
            pdf.rect(x0, y0, 18, 8, "F")
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(10, 10, 10)
            pdf.set_xy(x0, y0 + 1)
            pdf.cell(18, 6, sev.upper(), align="C")

            pdf.set_text_color(*_CLR_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_xy(x0 + 21, y0 + 1)
            pdf.cell(card_w - 21, 6,
                     _safe(f"#{idx}  {check_id}  —  {r.get('title', '')}"), align="L")
            pdf.ln(9)

            # Remediation text
            pdf.set_x(x0 + 4)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*_CLR_WHITE)
            remediation = r.get("remediation", "")
            guidance = _CIS_GUIDANCE.get(check_id, "")
            full_text = remediation
            if guidance:
                full_text = guidance.replace("\n", " | ")
            pdf.multi_cell(card_w - 8, 4, _safe(full_text, 600))

            # Framework refs
            frameworks = _CIS_FRAMEWORKS.get(check_id, {})
            if frameworks:
                pdf.set_x(x0 + 4)
                pdf.set_font("Helvetica", "I", 6)
                pdf.set_text_color(*_CLR_MUTED)
                fw_str = "  |  ".join([
                    f"PCI-DSS: {frameworks.get('pci', 'N/A')}",
                    f"ISO 27001: {frameworks.get('iso', 'N/A')}",
                    f"NIST 800-53: {frameworks.get('nist', 'N/A')}",
                ])
                pdf.cell(card_w - 8, 4, _safe(fw_str, 200), new_x="LMARGIN", new_y="NEXT")

            pdf.ln(5)

    return bytes(pdf.output())



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECRET SCANNER – CSV
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_secret_csv(report: Dict) -> str:
    """Return a CSV string from a secret scanner report dict."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Metadata
    writer.writerow(["Clouds8 Secret Scanner Report"])
    writer.writerow(["Generated", _now_str()])
    writer.writerow(["Buckets Scanned", report.get("buckets_scanned", 0)])
    writer.writerow(["Objects Scanned", report.get("objects_scanned", 0)])
    writer.writerow(["Findings", report.get("findings_count", 0)])
    writer.writerow(["Scan Duration", report.get("scan_duration", "")])
    writer.writerow([])

    # Findings header
    writer.writerow([
        "File Name", "Bucket", "Compartment", "Finding Type",
        "Source", "File Size", "Object Name", "Time Created",
    ])

    for f in report.get("findings", []):
        writer.writerow([
            f.get("file_name", ""),
            f.get("bucket", ""),
            f.get("compartment", ""),
            f.get("finding_type", ""),
            f.get("source", ""),
            f.get("file_size", ""),
            f.get("object_name", ""),
            f.get("time_created", ""),
        ])

    return buf.getvalue()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECRET SCANNER – PDF
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_secret_pdf(report: Dict) -> bytes:
    """Return PDF bytes from a secret scanner report dict."""
    pdf = _LynxPDF("Secret Scanner Report")
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── Summary ────────────────────────────────────────────────────────
    pdf.section_title("Scan Summary")

    findings_count = report.get("findings_count", 0)
    count_clr = _CLR_FAIL if findings_count > 0 else _CLR_PASS

    pdf.summary_cell("Findings",         str(findings_count), count_clr)
    pdf.summary_cell("Buckets Scanned",  str(report.get("buckets_scanned", 0)), _CLR_INFO)
    pdf.summary_cell("Objects Scanned",  str(report.get("objects_scanned", 0)), _CLR_INFO)
    pdf.summary_cell("Scan Duration",    str(report.get("scan_duration", "—")), _CLR_MUTED, width=60)
    pdf.ln(22)

    findings = report.get("findings", [])
    if not findings:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_CLR_PASS)
        pdf.cell(0, 10, "No sensitive files detected. All clear!",
                 new_x="LMARGIN", new_y="NEXT")
        return bytes(pdf.output())

    # ── By-bucket breakdown ────────────────────────────────────────────
    pdf.section_title("Findings by Bucket")
    bucket_counts: Dict[str, int] = {}
    for f in findings:
        b = f.get("bucket", "unknown")
        bucket_counts[b] = bucket_counts.get(b, 0) + 1

    cols = [("Bucket", 120), ("Findings", 30)]
    pdf.table_header(cols)
    for bucket, count in sorted(bucket_counts.items(), key=lambda x: -x[1]):
        pdf.table_row([
            (bucket, 120, "L"),
            (str(count), 30, "C"),
        ], highlight=(count >= 3))
    pdf.ln(6)

    # ── By finding-type breakdown ──────────────────────────────────────
    pdf.section_title("Findings by Type")
    type_counts: Dict[str, int] = {}
    for f in findings:
        t = f.get("finding_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    cols = [("Finding Type", 120), ("Count", 30)]
    pdf.table_header(cols)
    for ftype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        pdf.table_row([
            (ftype, 120, "L"),
            (str(count), 30, "C"),
        ])
    pdf.ln(6)

    # ── Detailed findings table ────────────────────────────────────────
    pdf.section_title("All Findings")
    cols = [
        ("File Name", 70), ("Bucket", 50), ("Compartment", 40),
        ("Finding Type", 45), ("Source", 30), ("Size", 20), ("Created", 30),
    ]
    pdf.table_header(cols)

    for f in findings:
        pdf.table_row([
            (f.get("file_name", ""), 70, "L"),
            (f.get("bucket", ""), 50, "L"),
            (f.get("compartment", ""), 40, "L"),
            (f.get("finding_type", ""), 45, "L"),
            (f.get("source", ""), 30, "C"),
            (_format_file_size(f.get("file_size")), 20, "R"),
            (f.get("time_created", ""), 30, "C"),
        ])

    return bytes(pdf.output())
