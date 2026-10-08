import type { ReactNode } from "react";
import { SkeletonStatTile } from "./Skeleton";

interface StatTileProps {
  label: string;
  value: ReactNode;
  caption?: ReactNode;
  accent?: "default" | "critical" | "high" | "clean";
  loading?: boolean;
}

const ACCENT_CLASS: Record<NonNullable<StatTileProps["accent"]>, string> = {
  default: "text-lm-text",
  critical: "text-lm-critical",
  high: "text-lm-high",
  clean: "text-lm-clean",
};

export function StatTile({ label, value, caption, accent = "default", loading }: StatTileProps) {
  if (loading) return <SkeletonStatTile />;
  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel p-4">
      <div className="text-[11px] uppercase tracking-widest text-lm-dim font-ui mb-2">{label}</div>
      <div className={`font-display text-3xl font-semibold ${ACCENT_CLASS[accent]}`}>{value}</div>
      {caption && <div className="text-xs text-lm-dim mt-1">{caption}</div>}
    </div>
  );
}
