import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { backendApi, dbApi } from "../api/client";
import type { Engagement, Run } from "../api/types";
import { AssetsByCompartmentChart } from "../components/AssetsByCompartmentChart";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";
import { SkeletonLines } from "../components/Skeleton";
import { StatTile } from "../components/StatTile";

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function Overview() {
  const [totalAssets, setTotalAssets] = useState<number | null>(null);
  const [openFindings, setOpenFindings] = useState<number | null>(null);
  const [severityCounts, setSeverityCounts] = useState<SeverityCounts | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState("");

  useEffect(() => {
    dbApi.listEngagements().then((r) => setEngagements(r.items));
  }, []);

  useEffect(() => {
    setTotalAssets(null);
    setOpenFindings(null);
    setSeverityCounts(null);
    setRuns(null);
    dbApi.listAssets({ limit: 1, engagement_id: engagementId }).then((r) => setTotalAssets(r.total));
    dbApi.listFindings({ state: "open", limit: 1, engagement_id: engagementId }).then((r) => setOpenFindings(r.total));
    Promise.all(
      (["critical", "high", "medium", "low"] as const).map((sev) =>
        dbApi.listFindings({ severity: sev, limit: 1, engagement_id: engagementId }).then((r) => r.total),
      ),
    ).then(([critical, high, medium, low]) => setSeverityCounts({ critical, high, medium, low }));
    backendApi.listRuns(5, { engagement_id: engagementId }).then((r) => setRuns(r.items));
  }, [engagementId]);

  const selectedEngagement = engagements.find((e) => e.id === engagementId) ?? null;

  const sevTotal = severityCounts
    ? severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low
    : 0;

  return (
    <div>
      <PageHeader
        title="Overview"
        subtitle={selectedEngagement ? `${selectedEngagement.name} · live` : "Attack surface · live"}
        actions={
          <select
            value={engagementId}
            onChange={(e) => setEngagementId(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            <option value="">All engagements</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
        }
      />

      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatTile label="Assets inventoried" value={totalAssets ?? "—"} loading={totalAssets === null} />
        <StatTile
          label="Open findings"
          value={openFindings ?? "—"}
          accent="critical"
          loading={openFindings === null}
        />
        <StatTile
          label="Attack paths"
          value="—"
          caption="pick an entry point to compute"
        />
        <StatTile
          label="Recent runs"
          value={runs?.length ?? "—"}
          loading={runs === null}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 rounded-lg border border-lm-line bg-lm-panel p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-base font-semibold">Highest-risk attack paths</h2>
            <Link to="/attack-paths" className="text-xs text-lm-accent hover:underline">
              Open graph
            </Link>
          </div>
          <div className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-xs text-lm-dim">
            Attack paths are computed from a chosen entry point (VM, user, group, or dynamic group),
            not shown as a dashboard aggregate. Open{" "}
            <Link to="/attack-paths" className="text-lm-accent hover:underline">Attack Paths</Link>{" "}
            and search for an asset to start.
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
            <h2 className="font-display text-base font-semibold mb-4">Findings by severity</h2>
            {severityCounts === null ? (
              <SkeletonLines />
            ) : (
              <>
                <div className="h-2 rounded-full overflow-hidden flex mb-4 bg-lm-line">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => {
                    const count = severityCounts[sev];
                    const pct = sevTotal ? (count / sevTotal) * 100 : 0;
                    const color = {
                      critical: "var(--lm-critical)", high: "var(--lm-high)",
                      medium: "var(--lm-medium)", low: "var(--lm-low)",
                    }[sev];
                    return pct > 0 ? (
                      <div key={sev} style={{ width: `${pct}%`, background: color }} />
                    ) : null;
                  })}
                </div>
                <div className="flex flex-col gap-2 text-sm">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => (
                    <div key={sev} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={sev} />
                      </div>
                      <span className="font-mono text-lm-dim">{severityCounts[sev]}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
            <h2 className="font-display text-base font-semibold mb-4">Recent runs</h2>
            {runs === null ? (
              <SkeletonLines />
            ) : runs.length === 0 ? (
              <div className="text-sm text-lm-dim">No scans run yet.</div>
            ) : (
              <div className="flex flex-col gap-3">
                {runs.map((r) => (
                  <div key={r.id} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                          r.state === "running" ? "bg-lm-accent" : r.state === "completed" ? "bg-lm-clean" : "bg-lm-critical"
                        }`}
                      />
                      <span className="truncate">{r.classes.join(", ")}</span>
                    </div>
                    <span className="text-lm-dim text-xs shrink-0 ml-2">{r.state}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4">
        <AssetsByCompartmentChart engagementId={engagementId} />
      </div>
    </div>
  );
}
