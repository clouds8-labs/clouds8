import type { Asset } from "../api/types";

interface ScanStatusBadgeProps {
  asset: Pick<Asset, "class" | "scan_status">;
  inProgressClasses: string[];
}

export function ScanStatusBadge({ asset, inProgressClasses }: ScanStatusBadgeProps) {
  if (asset.scan_status === "scanned") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-clean/15 text-lm-clean">
        Scanned
      </span>
    );
  }
  if (inProgressClasses.includes(asset.class)) {
    return (
      <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-accent/15 text-lm-accent">
        <span className="h-1.5 w-1.5 rounded-full bg-lm-accent animate-pulse" />
        In progress
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-line text-lm-dim">
      Not scanned
    </span>
  );
}
