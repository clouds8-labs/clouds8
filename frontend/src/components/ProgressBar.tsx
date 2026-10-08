interface ProgressBarProps {
  percent: number;
  className?: string;
  // True while the underlying work is actually running. `percent` is often
  // stuck at 0 for single-scanner runs (see v1_runs.py's _aggregate_run -
  // it only tracks how many whole scanners finished, not resources scanned
  // within one), so a flat empty bar reads as stalled. When active, show a
  // pulsing minimum-width segment instead of a literal 0%-wide bar.
  active?: boolean;
}

export function ProgressBar({ percent, className = "", active = false }: ProgressBarProps) {
  const clamped = Math.max(0, Math.min(100, percent));
  const width = active ? Math.max(clamped, 8) : clamped;
  return (
    <div className={`h-1.5 w-full rounded-full bg-lm-line overflow-hidden ${className}`}>
      <div
        className={`h-full rounded-full bg-lm-accent transition-all ${active ? "animate-pulse" : ""}`}
        style={{ width: `${width}%` }}
      />
    </div>
  );
}
