import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { dbApi } from "../api/client";
import type { Asset, AttackPath } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";

// Entry points are limited to asset types that have real principal/
// membership data captured today - VM (via dynamic-group matching-rule
// evaluation), and the IAM entities a policy can directly grant to.
// Functions, OKE, buckets, and GCP assets have no attached-principal data
// in the DB yet, so they can't produce a real (non-fabricated) path.
const ENTRY_POINT_CLASSES = ["vm", "user", "group", "dynamic_group"];

export function AttackPaths() {
  const navigate = useNavigate();
  const [entryQuery, setEntryQuery] = useState("");
  const [entryMatches, setEntryMatches] = useState<Asset[]>([]);
  const [entry, setEntry] = useState<Asset | null>(null);
  const [paths, setPaths] = useState<AttackPath[] | null>(null);
  const [selected, setSelected] = useState<AttackPath | null>(null);

  useEffect(() => {
    if (entryQuery.trim().length < 2) {
      setEntryMatches([]);
      return;
    }
    const id = window.setTimeout(() => {
      dbApi.listAssets({ q: entryQuery, limit: 20 }).then((r) =>
        setEntryMatches(r.items.filter((a) => ENTRY_POINT_CLASSES.includes(a.class))),
      );
    }, 250);
    return () => window.clearTimeout(id);
  }, [entryQuery]);

  function pickEntry(asset: Asset) {
    setEntry(asset);
    setEntryQuery("");
    setEntryMatches([]);
    setPaths(null);
    setSelected(null);
    dbApi.getAttackPaths(asset.id).then((r) => {
      setPaths(r.items);
      setSelected(r.items[0] ?? null);
    });
  }

  return (
    <div>
      <PageHeader
        title="Attack paths"
        subtitle="Pick an entry point to compute real, data-backed reachability paths"
      />

      <div className="mb-5 rounded-md border border-lm-line bg-lm-panel-2 px-4 py-3 text-sm text-lm-dim">
        Supports VM, User, Group, and Dynamic Group entry points today — the only resource types
        with attached-principal data captured so far. Functions, OKE, buckets, and GCP assets
        aren't wired yet.
      </div>

      <div className="relative max-w-md mb-6">
        <input
          type="text"
          value={entryQuery}
          onChange={(e) => setEntryQuery(e.target.value)}
          placeholder="Search for an entry point by name or id…"
          className="w-full rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
        />
        {entryMatches.length > 0 && (
          <ul className="absolute z-10 mt-1 w-full rounded-md border border-lm-line bg-lm-panel shadow-lg max-h-56 overflow-y-auto">
            {entryMatches.map((a) => (
              <li key={a.id}>
                <button
                  onClick={() => pickEntry(a)}
                  className="w-full text-left px-3 py-2 text-sm hover:bg-lm-panel-2 flex items-center justify-between gap-2"
                >
                  <span className="truncate">{a.name}</span>
                  <span className="text-[11px] text-lm-dim uppercase shrink-0">{a.class}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {entry && (
        <div className="flex items-center gap-2 mb-4 text-sm text-lm-dim">
          <span>Entry point:</span>
          <span className="rounded-md border border-lm-accent/40 bg-lm-accent/10 px-2.5 py-1 text-xs text-lm-accent">
            {entry.name} ({entry.class})
          </span>
        </div>
      )}

      {!entry ? (
        <div className="text-sm text-lm-dim py-10 text-center">Search for and pick an entry point above.</div>
      ) : paths === null ? (
        <div className="text-sm text-lm-dim py-10 text-center">Computing paths…</div>
      ) : paths.length === 0 ? (
        <div className="text-sm text-lm-dim py-10 text-center">
          No reachable attack paths found from this entry point.
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          <div className="col-span-1 flex flex-col gap-2">
            {paths.map((p) => (
              <button
                key={p.id}
                onClick={() => setSelected(p)}
                className={`text-left rounded-lg border px-4 py-3 ${
                  selected?.id === p.id ? "border-lm-accent bg-lm-accent/10" : "border-lm-line bg-lm-panel hover:border-lm-dim"
                }`}
              >
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-display text-lg font-semibold text-lm-critical">{p.score}</span>
                  <SeverityBadge severity={p.severity} />
                </div>
                <div className="text-sm font-medium">{p.title}</div>
              </button>
            ))}
          </div>

          {selected && (
            <div className="col-span-2 rounded-lg border border-lm-line bg-lm-panel p-6">
              <div className="flex items-center gap-3 mb-1">
                <span className="font-display text-3xl font-semibold text-lm-critical">{selected.score}</span>
                <SeverityBadge severity={selected.severity} />
              </div>
              <h2 className="font-display text-lg font-semibold mt-2 mb-6">{selected.title}</h2>

              <div className="flex flex-col gap-2">
                {selected.hops.map((hop, i) => {
                  // A policy "hop" has no asset row (OCI policies aren't
                  // materialized as assets - see findings.py) - render it
                  // inline instead of as a dead link.
                  const clickable = hop.type !== "policy";
                  const Tag = clickable ? "button" : "div";
                  return (
                    <div key={i} className="flex items-start gap-2">
                      <Tag
                        onClick={clickable ? () => navigate(`/inventory/${encodeURIComponent(hop.asset_id)}`) : undefined}
                        className={`rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-left transition-colors shrink-0 w-56 ${clickable ? "hover:border-lm-accent" : ""}`}
                      >
                        <div className="text-xs text-lm-dim uppercase">{hop.type}</div>
                        <div className="text-sm font-mono truncate">{hop.name}</div>
                      </Tag>
                      <div className="text-xs text-lm-dim pt-2 flex-1">{hop.label}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
