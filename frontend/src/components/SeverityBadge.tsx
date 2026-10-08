import type { Severity } from "../api/types";

const SEVERITY_STYLE: Record<Severity, { bg: string; fg: string; label: string }> = {
  critical: { bg: "bg-lm-critical/15", fg: "text-lm-critical", label: "CRITICAL" },
  high: { bg: "bg-lm-high/15", fg: "text-lm-high", label: "HIGH" },
  medium: { bg: "bg-lm-medium/15", fg: "text-lm-medium", label: "MEDIUM" },
  low: { bg: "bg-lm-low/15", fg: "text-lm-low", label: "LOW" },
  info: { bg: "bg-lm-accent/15", fg: "text-lm-accent", label: "INFO" },
};

export function SeverityBadge({ severity }: { severity: Severity | string | null | undefined }) {
  const key = (severity ?? "").toLowerCase() as Severity;
  const style = SEVERITY_STYLE[key];
  if (!style) {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold tracking-wide bg-lm-clean/15 text-lm-clean">
        CLEAN
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold tracking-wide ${style.bg} ${style.fg}`}>
      {style.label}
    </span>
  );
}
