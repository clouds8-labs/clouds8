import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { backendApi, dbApi } from "../api/client";
import type { Finding, Run } from "../api/types";

const POLL_INTERVAL_MS = 15000;

const RUN_STATE_STYLE: Record<Run["state"], { bg: string; fg: string; label: string }> = {
  running: { bg: "bg-lm-accent/15", fg: "text-lm-accent", label: "Running" },
  completed: { bg: "bg-lm-clean/15", fg: "text-lm-clean", label: "Completed" },
  partial: { bg: "bg-lm-medium/15", fg: "text-lm-medium", label: "Partial" },
  failed: { bg: "bg-lm-critical/15", fg: "text-lm-critical", label: "Failed" },
};

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [criticalFindings, setCriticalFindings] = useState<Finding[]>([]);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const poll = () => {
      backendApi.listRuns(5).then((r) => setRuns(r.items)).catch(() => {});
      dbApi
        .listFindings({ severity: "critical", state: "open", limit: 10 })
        .then((r) => setCriticalFindings(r.items.filter((f): f is Finding => "id" in f)))
        .catch(() => {});
    };
    poll();
    const id = window.setInterval(poll, POLL_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  const hasActiveRun = runs.some((r) => r.state === "running");
  const attentionCount = runs.filter((r) => r.state === "failed").length + criticalFindings.length;

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Notifications"
        className="relative flex items-center justify-center rounded-full p-2 text-lm-text hover:bg-lm-panel-2 transition-colors"
      >
        <span className="relative text-base opacity-80">
          🔔
          {hasActiveRun && (
            <span className="absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-lm-accent animate-pulse" />
          )}
        </span>
        {attentionCount > 0 && (
          <span className="absolute -top-1 -right-1 inline-flex items-center justify-center rounded-full bg-lm-critical/20 text-lm-critical text-[11px] font-semibold h-5 min-w-5 px-1">
            {attentionCount}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 bg-black/40 z-40" />
          <div
            ref={panelRef}
            className="fixed top-0 right-0 h-screen w-96 bg-lm-panel border-l border-lm-line z-50 flex flex-col shadow-xl"
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-lm-line">
              <span className="font-display font-semibold text-sm">Notifications</span>
              <button
                onClick={() => setOpen(false)}
                aria-label="Close"
                className="text-lm-dim hover:text-lm-text text-sm"
              >
                ✕
              </button>
            </div>

            <div className="overflow-y-auto flex-1">
              <div className="px-5 py-4">
                <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-3">Scan status</div>
                {runs.length === 0 ? (
                  <div className="text-xs text-lm-dim">No recent scans</div>
                ) : (
                  <div className="flex flex-col gap-2">
                    {runs.map((run) => {
                      const style = RUN_STATE_STYLE[run.state];
                      return (
                        <Link
                          key={run.id}
                          to="/scans"
                          onClick={() => setOpen(false)}
                          className="block rounded-md border border-lm-line px-3 py-2 hover:border-lm-dim transition-colors"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-lm-text truncate">{run.classes.join(", ")}</span>
                            <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold ${style.bg} ${style.fg}`}>
                              {style.label}
                            </span>
                          </div>
                          <div className="text-[11px] text-lm-dim">
                            {run.state === "running"
                              ? `${run.progress.succeeded + run.progress.failed}/${run.progress.total} collectors complete`
                              : run.finished_at
                                ? new Date(run.finished_at).toLocaleString()
                                : "—"}
                          </div>
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="px-5 py-4 border-t border-lm-line">
                <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-3">Critical alerts</div>
                {criticalFindings.length === 0 ? (
                  <div className="text-xs text-lm-dim">No open critical findings</div>
                ) : (
                  <div className="flex flex-col gap-2">
                    {criticalFindings.map((f) => (
                      <Link
                        key={f.id}
                        to={`/inventory/${encodeURIComponent(f.asset_id)}`}
                        onClick={() => setOpen(false)}
                        className="block rounded-md border border-lm-line px-3 py-2 hover:border-lm-dim transition-colors"
                      >
                        <div className="text-xs text-lm-text mb-1">{f.title}</div>
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] text-lm-dim truncate">{f.asset_name ?? f.asset_id}</span>
                          <span className="text-[11px] text-lm-critical font-semibold">CRITICAL</span>
                        </div>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
