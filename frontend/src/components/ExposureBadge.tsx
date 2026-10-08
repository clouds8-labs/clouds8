import type { Exposure } from "../api/types";

export function ExposureBadge({ exposure }: { exposure: Exposure | string | null | undefined }) {
  if (exposure === "internet_facing") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-critical/15 text-lm-critical">
        Internet-facing
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-line text-lm-dim">
      Internal
    </span>
  );
}
