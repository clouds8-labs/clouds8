import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { dbApi } from "../api/client";
import type { Finding, FindingGroup, FindingState } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";
import { SkeletonLines } from "../components/Skeleton";

const STATE_OPTIONS: { value: FindingState; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "resolved", label: "Resolved" },
];

function GroupDetail({ group, severity, state }: { group: FindingGroup; severity: string; state: string }) {
  const [members, setMembers] = useState<Finding[] | null>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    setMembers(null);
    dbApi
      .listFindings({ rule_id: group.rule_id, severity: severity || undefined, state: state || undefined, limit: 50 })
      .then((r) => setMembers(r.items as Finding[]));
  }, [group.rule_id, severity, state]);

  const updateState = (findingId: number, newState: FindingState) => {
    dbApi.patchFindingState(findingId, newState).then((updated) => {
      setMembers((cur) => cur?.map((m) => (m.id === updated.id ? updated : m)) ?? null);
    });
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await dbApi.downloadRuleAssets(group.rule_id, { severity: severity || undefined, state: state || undefined });
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div>
      <div className="px-4 py-3 border-b border-lm-line flex flex-col gap-3">
        {group.description && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-1">Description</div>
            <div className="text-sm text-lm-text">{group.description}</div>
          </div>
        )}
        {group.remediation && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-1">Remediation</div>
            <div className="text-sm text-lm-text">{group.remediation}</div>
          </div>
        )}
        <div>
          <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-1">Affected assets</div>
          {members === null ? (
            <SkeletonLines widths={["40%"]} />
          ) : group.affected_assets > 10 ? (
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="text-sm text-lm-accent hover:underline disabled:text-lm-dim"
            >
              {downloading ? "Preparing…" : `Download list (${group.affected_assets} assets) .txt`}
            </button>
          ) : (
            <div className="text-sm text-lm-text">
              {members.map((m) => m.asset_name ?? m.asset_id).join(", ") || "—"}
            </div>
          )}
        </div>
        {members?.[0]?.proof_of_concept && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-1">
              Proof of concept <span className="normal-case text-lm-dim">(example against one affected asset)</span>
            </div>
            <pre className="text-xs font-mono bg-lm-panel-2 border border-lm-line rounded-md px-3 py-2 overflow-x-auto">
              {members[0].proof_of_concept}
            </pre>
          </div>
        )}
      </div>

      {members === null ? (
        <div className="px-4 py-3"><SkeletonLines widths={["60%", "40%"]} /></div>
      ) : (
        <div className="divide-y divide-lm-line">
          {members.map((m) => (
            <div key={m.id} className="flex items-center gap-4 px-4 py-2.5 text-sm">
              <Link to={`/inventory/${encodeURIComponent(m.asset_id)}`} className="min-w-0 flex-1 hover:text-lm-accent truncate">
                {m.asset_name ?? m.asset_id}
              </Link>
              <span className="text-xs text-lm-dim shrink-0">{m.account ?? "—"}</span>
              <select
                value={m.state}
                onChange={(e) => updateState(m.id, e.target.value as FindingState)}
                className="rounded border border-lm-line bg-lm-panel-2 text-xs px-2 py-1 shrink-0"
              >
                {STATE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function Findings() {
  const [groups, setGroups] = useState<FindingGroup[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [state, setState] = useState("open");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setGroups(null);
    dbApi
      .listFindings({ group_by: "rule", severity: severity || undefined, state: state || undefined, limit: 50 })
      .then((r) => setGroups(r.items as FindingGroup[]));
  }, [severity, state]);

  return (
    <div>
      <PageHeader title="Findings" subtitle={groups ? `${groups.length} rules with matching findings` : undefined} />

      <div className="flex flex-wrap items-center gap-3 mb-4">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={state}
          onChange={(e) => setState(e.target.value)}
          className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm"
        >
          <option value="">All states</option>
          {STATE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>

      {groups === null ? (
        <SkeletonLines widths={["100%", "100%", "100%", "80%"]} />
      ) : groups.length === 0 ? (
        <div className="text-sm text-lm-dim py-8 text-center rounded-lg border border-lm-line">
          No findings match the current filters.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {groups.map((g) => (
            <div key={g.group_key} className="rounded-lg border border-lm-line bg-lm-panel overflow-hidden">
              <button
                onClick={() => setExpanded(expanded === g.group_key ? null : g.group_key)}
                className="w-full flex items-center gap-4 px-4 py-3 text-left hover:bg-lm-panel-2"
              >
                <SeverityBadge severity={g.severity} />
                <span className="font-medium text-sm flex-1">{g.title}</span>
                <span className="text-xs text-lm-dim font-mono">{g.rule_id}</span>
                <span className="text-xs text-lm-dim shrink-0">{g.affected_assets} affected assets</span>
                <span className="text-lm-dim shrink-0">{expanded === g.group_key ? "▲" : "▼"}</span>
              </button>
              {expanded === g.group_key && (
                <GroupDetail group={g} severity={severity} state={state} />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
