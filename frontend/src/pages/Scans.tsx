import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { backendApi, dbApi } from "../api/client";
import { ASSET_CLASSES, ASSET_TYPE_SCANNERS, SCANNER_CLASSES, assetClassFilterForClasses, inventoryLinkForClasses } from "../api/types";
import type {
  Asset, CloudProvider, Engagement, ExportFormat, IntervalUnit, Profile, Run, RunState, ScanDepth, Schedule, ScheduleMode,
} from "../api/types";
import { Button } from "../components/Button";
import { type Column, DataTable } from "../components/DataTable";
import { ExportDialog } from "../components/ExportDialog";
import { PageHeader } from "../components/PageHeader";
import { ProgressBar } from "../components/ProgressBar";

const RECENT_SCANS_EXPORT_FORMATS: ExportFormat[] = ["csv", "html", "pdf"];

const DEPTH_LABEL: Record<ScanDepth, string> = {
  inventory: "Inventory only",
  rules: "Inventory + rules",
  full: "Full assessment",
};

const RUN_STATE_STYLE: Record<RunState, { bg: string; fg: string; pulse?: boolean }> = {
  running: { bg: "bg-lm-accent/15", fg: "text-lm-accent", pulse: true },
  completed: { bg: "bg-lm-clean/15", fg: "text-lm-clean" },
  partial: { bg: "bg-lm-high/15", fg: "text-lm-high" },
  failed: { bg: "bg-lm-critical/15", fg: "text-lm-critical" },
};

// RunCollector.status values, confirmed exact from
// services/backend-api/routers/v1_runs.py: sourced straight from the job
// row's own `status` column (pending/running/succeeded/failed).
const COLLECTOR_STATUS_STYLE: Record<string, { bg: string; fg: string; dot: string; label: string; pulse?: boolean }> = {
  succeeded: { bg: "bg-lm-clean/15", fg: "text-lm-clean", dot: "bg-lm-clean", label: "Succeeded" },
  failed: { bg: "bg-lm-critical/15", fg: "text-lm-critical", dot: "bg-lm-critical", label: "Failed" },
  running: { bg: "bg-lm-accent/15", fg: "text-lm-accent", dot: "bg-lm-accent", label: "Running", pulse: true },
  pending: { bg: "bg-lm-line", fg: "text-lm-dim", dot: "bg-lm-dim", label: "Queued" },
};

// A class belongs to exactly one provider's collector - gcp_-prefixed
// scanner_types are GCP's, everything else is OCI's today.
const classesForProvider = (classes: string[], provider: CloudProvider) =>
  classes.filter((c) => (provider === "gcp" ? c.startsWith("gcp_") : !c.startsWith("gcp_")));

const scannerProvider = (scanner: string): "oci" | "gcp" => (scanner.startsWith("gcp_") ? "gcp" : "oci");

const CSP_LABEL: Record<"oci" | "gcp", string> = { oci: "OCI", gcp: "GCP" };

export function Scans() {
  // ── Engagements (scope) ───────────────────────────────────────────────
  const [engagements, setEngagements] = useState<Engagement[] | null>(null);
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [engagementId, setEngagementId] = useState("");

  useEffect(() => {
    dbApi.listEngagements().then((r) => setEngagements(r.items));
    dbApi.listProfiles().then((r) => setProfiles(r.items));
  }, []);

  const selectedEngagement = engagements?.find((e) => e.id === engagementId) ?? null;

  // Engagement profiles eligible to actually run against - active AND
  // verified, so a scan never silently fires against a broken/disabled
  // credential just because it happens to be grouped into the engagement.
  const eligibleProfiles = (): Profile[] => {
    if (!selectedEngagement || !profiles) return [];
    const memberIds = new Set(selectedEngagement.profiles.map((p) => p.id));
    return profiles.filter((p) => memberIds.has(p.id) && p.is_active && p.verify_status === "ok");
  };

  // Scanners without a matching ASSET_CLASSES entry (cis/iam/secret/gcp_cis)
  // aren't expressible in an engagement's asset_classes scope, so they stay
  // visible regardless - the scope only narrows what it can narrow.
  const scopedScannerClasses = selectedEngagement?.asset_classes
    ? SCANNER_CLASSES.filter((c) => {
        const assetClass = ASSET_CLASSES.find((a) => a.scanner === c.scanner);
        return !assetClass || selectedEngagement.asset_classes!.includes(assetClass.id);
      })
    : SCANNER_CLASSES;

  // An engagement can hold profiles for more than one CSP - only offer
  // classes for a CSP the engagement actually has an active, verified
  // profile for, so checking a box never silently no-ops at scan time.
  const engagementProviders = selectedEngagement
    ? new Set(eligibleProfiles().map((p) => p.cloud_provider))
    : null;
  const visibleScannerClasses = engagementProviders
    ? scopedScannerClasses.filter((c) => engagementProviders.has(scannerProvider(c.scanner)))
    : scopedScannerClasses;

  // Grouped into one section per CSP when an engagement is selected (each
  // section only appears once that CSP has a configured profile above); a
  // single flat list otherwise, matching the provider-agnostic "active
  // profile for each provider" default.
  const classSections = selectedEngagement
    ? (["oci", "gcp"] as const)
        .map((provider) => ({ provider, classes: visibleScannerClasses.filter((c) => scannerProvider(c.scanner) === provider) }))
        .filter((s) => s.classes.length > 0)
    : [{ provider: null as "oci" | "gcp" | null, classes: visibleScannerClasses }];

  // ── Shared asset-class + depth selection (run-now and schedule both use these) ──
  const [selected, setSelected] = useState<string[]>(["bucket", "vm", "iam"]);
  const [depth, setDepth] = useState<ScanDepth>("full");

  const toggle = (scanner: string) =>
    setSelected((cur) => (cur.includes(scanner) ? cur.filter((s) => s !== scanner) : [...cur, scanner]));

  // Collapsed by default - searching for a specific asset below fills these
  // in automatically, so most users never need to open them manually.
  const [classesExpanded, setClassesExpanded] = useState(false);
  const [regionsExpanded, setRegionsExpanded] = useState(false);

  // ── Compartment/region/asset scope (optional, shared by run-now and schedule) ──
  const [compartments, setCompartments] = useState<{ compartment_id: string; name: string; scope_type: string }[]>([]);
  const [regionsAvailable, setRegionsAvailable] = useState<{ region: string }[]>([]);
  const [selectedCompartments, setSelectedCompartments] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);

  useEffect(() => {
    dbApi.listCompartments().then(setCompartments);
    dbApi.listRegions().then(setRegionsAvailable);
  }, []);

  // scope_type is "compartment" for OCI or "project" for GCP (a GCP project
  // stands in for an OCI compartment - see store.py's get_compartments_list).
  // Grouped the same way classSections groups asset classes, so GCP gets
  // its own visible section (and its own "nothing here yet" message)
  // instead of being invisible inside one OCI-dominated list.
  const compartmentSections = (["oci", "gcp"] as const).map((provider) => ({
    provider,
    items: compartments.filter((c) => (provider === "gcp" ? c.scope_type === "project" : c.scope_type !== "project")),
  }));

  const toggleCompartment = (id: string) =>
    setSelectedCompartments((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
  const toggleRegion = (r: string) =>
    setSelectedRegions((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]));

  // Search-and-select a specific asset to scan directly, reusing Inventory's
  // own search mechanism (GET /v1/assets?q=) - a no-hit query isn't an
  // error, it just means "not in inventory yet" and the raw typed id still
  // flows through as a filter (0 matches if it's not real).
  const [assetQuery, setAssetQuery] = useState("");
  const [assetMatches, setAssetMatches] = useState<Asset[]>([]);
  const [selectedAssets, setSelectedAssets] = useState<{ id: string; name: string; inInventory: boolean }[]>([]);

  useEffect(() => {
    if (assetQuery.trim().length < 2) {
      setAssetMatches([]);
      return;
    }
    const id = window.setTimeout(() => {
      dbApi.listAssets({ q: assetQuery, limit: 10 }).then((r) => setAssetMatches(r.items));
    }, 250);
    return () => window.clearTimeout(id);
  }, [assetQuery]);

  const selectAsset = (asset: Asset) => {
    // Picking a specific resource means "scan just this" - the first pick
    // replaces the generic bucket/vm/iam starting defaults rather than
    // piling on top of them; a second/third pick then adds to that (so
    // scanning a handful of specific resources together still works).
    const isFirstPick = selectedAssets.length === 0;
    setSelectedAssets((cur) => (cur.some((a) => a.id === asset.id) ? cur : [...cur, { id: asset.id, name: asset.name, inInventory: true }]));

    // Jump straight to this asset's own compartment/region instead of
    // sweeping everything and filtering at the end. asset.compartment is a
    // *name* for OCI (findings.py stores compartment_name, not the OCID)
    // but the picker/filter work off compartment_id - resolve the name
    // back to its id via the already-loaded compartment list (GCP's
    // asset.compartment is already a project id, which matches
    // compartment_id directly, so this resolves to itself there).
    const compartmentId = asset.compartment
      ? compartments.find((c) => c.compartment_id === asset.compartment || c.name === asset.compartment)?.compartment_id
      : undefined;
    if (compartmentId) {
      setSelectedCompartments((cur) => (isFirstPick ? [compartmentId] : cur.includes(compartmentId) ? cur : [...cur, compartmentId]));
    }
    if (asset.region) {
      setSelectedRegions((cur) => (isFirstPick ? [asset.region!] : cur.includes(asset.region!) ? cur : [...cur, asset.region!]));
      setRegionsExpanded(true);
    }
    // The DB already knows which scanner(s) produced this asset - select
    // those automatically instead of making the user re-derive it.
    const scanners = ASSET_TYPE_SCANNERS[asset.class] ?? [];
    if (scanners.length > 0) {
      setSelected((cur) => (isFirstPick ? scanners : [...cur, ...scanners.filter((s) => !cur.includes(s))]));
      setClassesExpanded(true);
    }
    setAssetQuery("");
    setAssetMatches([]);
  };

  const addFreeTextAsset = () => {
    const q = assetQuery.trim();
    if (!q || selectedAssets.some((a) => a.id === q)) return;
    setSelectedAssets((cur) => [...cur, { id: q, name: q, inInventory: false }]);
    setAssetQuery("");
    setAssetMatches([]);
  };

  const removeSelectedAsset = (id: string) =>
    setSelectedAssets((cur) => cur.filter((a) => a.id !== id));

  // Drop any selected class that just fell out of scope when the engagement
  // (or its scope) changed.
  useEffect(() => {
    const visible = new Set<string>(visibleScannerClasses.map((c) => c.scanner));
    setSelected((cur) => cur.filter((c) => visible.has(c)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engagementId]);

  // ── Ad-hoc runs (one per fired profile when an engagement is selected) ──
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const pollRefs = useRef<Record<string, number>>({});

  // Friendly names for a run's asset_ids, keyed by run id - only known for
  // runs fired this session (the backend only persists the raw ids, not
  // names). Recent Scans falls back to showing the bare id for anything
  // loaded from history instead of this map.
  const [runAssetNames, setRunAssetNames] = useState<Record<string, { id: string; name: string }[]>>({});
  const resourceNameFor = (runId: string, assetId: string): string =>
    runAssetNames[runId]?.find((a) => a.id === assetId)?.name ?? assetId;

  const watchRun = (runId: string) => {
    if (pollRefs.current[runId]) window.clearInterval(pollRefs.current[runId]);
    pollRefs.current[runId] = window.setInterval(async () => {
      const updated = await backendApi.getRun(runId);
      setRuns((prev) => ({ ...prev, [runId]: updated }));
      if (updated.state !== "running") {
        window.clearInterval(pollRefs.current[runId]);
        delete pollRefs.current[runId];
        fetchRecentRuns();
      }
    }, 2500);
  };

  // Resume watching any already-running scans on mount - without this,
  // `runs` starts out empty on every page load/refresh and the in-progress
  // panel just vanishes even though the scan is still going server-side.
  useEffect(() => {
    backendApi.listRuns(10).then((r) => {
      const running = r.items.filter((candidate) => candidate.state === "running");
      if (running.length === 0) return;
      setRuns((prev) => {
        const next = { ...prev };
        for (const run of running) next[run.id] = run;
        return next;
      });
      running.forEach((run) => watchRun(run.id));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      for (const id of Object.values(pollRefs.current)) window.clearInterval(id);
    };
  }, []);

  // Last 5 scans (ad-hoc and schedule-fired alike - /v1/runs doesn't
  // distinguish), independent of the in-progress `runs` above so history
  // stays visible once scans finish. Refetch on the same 30s cadence as the
  // schedule list, plus whenever a watched run stops (see watchRun above).
  const [recentRuns, setRecentRuns] = useState<Run[] | null>(null);
  const fetchRecentRuns = () => backendApi.listRuns(5).then((r) => setRecentRuns(r.items));

  useEffect(() => {
    fetchRecentRuns();
    const id = window.setInterval(fetchRecentRuns, 30000);
    return () => window.clearInterval(id);
  }, []);

  const isRunning = Object.values(runs).some((r) => r.state === "running");

  // ── Scheduling (shares `selected`/`depth` with the run-now flow above) ──
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [scheduleMode, setScheduleMode] = useState<ScheduleMode>("interval");
  const [intervalValue, setIntervalValue] = useState(24);
  const [intervalUnit, setIntervalUnit] = useState<IntervalUnit>("hours");
  const [runAt, setRunAt] = useState("");
  const [creatingSchedule, setCreatingSchedule] = useState(false);

  const fetchSchedules = () => backendApi.listSchedules().then((r) => setSchedules(r.items));

  useEffect(() => {
    fetchSchedules();
    const id = window.setInterval(fetchSchedules, 30000);
    return () => window.clearInterval(id);
  }, []);

  // Per-schedule run status, keyed by run id - lets each schedule row show
  // its last fire's live progress and a link to the results, the same way
  // the ad-hoc "Run in progress" panel above does for a manually-started run.
  const [scheduleRuns, setScheduleRuns] = useState<Record<string, Run>>({});

  useEffect(() => {
    const ids = schedules.map((s) => s.last_run_id).filter((id): id is string => !!id);
    if (ids.length === 0) return;
    Promise.all(ids.map((id) => backendApi.getRun(id).catch(() => null))).then((runList) => {
      setScheduleRuns((prev) => {
        const next = { ...prev };
        for (const r of runList) if (r) next[r.id] = r;
        return next;
      });
    });
  }, [schedules]);

  // Keep polling only the runs that are still active, same 2.5s cadence as
  // the ad-hoc run above - stops itself once nothing is running anymore.
  useEffect(() => {
    const activeIds = Object.values(scheduleRuns).filter((r) => r.state === "running").map((r) => r.id);
    if (activeIds.length === 0) return;
    const id = window.setInterval(() => {
      Promise.all(activeIds.map((rid) => backendApi.getRun(rid).catch(() => null))).then((runList) => {
        setScheduleRuns((prev) => {
          const next = { ...prev };
          for (const r of runList) if (r) next[r.id] = r;
          return next;
        });
      });
    }, 2500);
    return () => window.clearInterval(id);
  }, [scheduleRuns]);

  const canCreateSchedule =
    selected.length > 0 &&
    (!selectedEngagement || eligibleProfiles().length > 0) &&
    (scheduleMode === "interval" ? intervalValue >= 1 : runAt !== "");

  const scheduleTiming = () =>
    scheduleMode === "interval"
      ? { interval_value: intervalValue, interval_unit: intervalUnit }
      // datetime-local is a naive wall-clock string in the browser's own
      // timezone; convert to a UTC instant since backend-api's container
      // clock may run in a different timezone (see v1_schedules.py's docstring).
      : { run_at: new Date(runAt).toISOString() };

  const createSchedule = async () => {
    setCreatingSchedule(true);
    try {
      const scope = {
        compartment_ids: selectedCompartments.length ? selectedCompartments : undefined,
        regions: selectedRegions.length ? selectedRegions : undefined,
        asset_ids: selectedAssets.length ? selectedAssets.map((a) => a.id) : undefined,
      };
      if (selectedEngagement) {
        for (const profile of eligibleProfiles()) {
          const classesForProfile = classesForProvider(selected, profile.cloud_provider);
          if (classesForProfile.length === 0) continue;
          await backendApi.createSchedule({
            classes: classesForProfile, mode: scheduleMode, scan_depth: depth,
            provider: profile.cloud_provider, profile_id: profile.id, ...scope, ...scheduleTiming(),
          });
        }
      } else {
        // Mirror the engagement branch above: a selection can mix OCI and
        // GCP classes (they're shown in one flat list when no engagement
        // scopes them by provider), so fire one schedule per provider that
        // actually has classes selected - resolving the whole selection to
        // a single inferred provider silently dropped every class for the
        // other one whenever the selection wasn't 100% single-provider.
        for (const provider of ["oci", "gcp"] as const) {
          const classesForThisProvider = classesForProvider(selected, provider);
          if (classesForThisProvider.length === 0) continue;
          await backendApi.createSchedule({
            classes: classesForThisProvider, mode: scheduleMode, scan_depth: depth, provider, ...scope, ...scheduleTiming(),
          });
        }
      }
      setRunAt("");
      await fetchSchedules();
    } finally {
      setCreatingSchedule(false);
    }
  };

  const toggleScheduleStatus = (s: Schedule) =>
    backendApi.setScheduleStatus(s.id, s.status === "active" ? "disabled" : "active").then(fetchSchedules);

  const removeSchedule = (id: string) => backendApi.deleteSchedule(id).then(fetchSchedules);

  const formatScheduleMode = (s: Schedule) =>
    s.mode === "interval"
      ? `Every ${s.interval_value} ${s.interval_unit}`
      : `Once at ${s.run_at ? new Date(s.run_at).toLocaleString() : "—"}`;

  const start = async () => {
    const compartmentIds = selectedCompartments.length ? selectedCompartments : undefined;
    const regions = selectedRegions.length ? selectedRegions : undefined;
    const assetIds = selectedAssets.length ? selectedAssets.map((a) => a.id) : undefined;
    const rememberAssetNames = (runId: string) => {
      if (selectedAssets.length) setRunAssetNames((prev) => ({ ...prev, [runId]: selectedAssets }));
    };
    if (selectedEngagement) {
      for (const profile of eligibleProfiles()) {
        const classesForProfile = classesForProvider(selected, profile.cloud_provider);
        if (classesForProfile.length === 0) continue;
        const started = await backendApi.startRun(
          classesForProfile, depth, compartmentIds, profile.cloud_provider, profile.id, regions, assetIds,
        );
        setRuns((prev) => ({ ...prev, [started.id]: started }));
        rememberAssetNames(started.id);
        watchRun(started.id);
      }
    } else {
      // One run per provider that has classes selected - a mixed OCI+GCP
      // selection (the flat, ungrouped list shown when no engagement scopes
      // it by provider) previously resolved to a single inferred provider,
      // silently never starting the other provider's scanners at all.
      for (const provider of ["oci", "gcp"] as const) {
        const classesForThisProvider = classesForProvider(selected, provider);
        if (classesForThisProvider.length === 0) continue;
        const started = await backendApi.startRun(classesForThisProvider, depth, compartmentIds, provider, undefined, regions, assetIds);
        setRuns((prev) => ({ ...prev, [started.id]: started }));
        rememberAssetNames(started.id);
        watchRun(started.id);
      }
    }
  };

  const startDisabled =
    selected.length === 0 || isRunning || (!!selectedEngagement && eligibleProfiles().length === 0);

  const [exportingRun, setExportingRun] = useState<Run | null>(null);

  const recentScanColumns: Column<Run>[] = [
    { key: "classes", label: "Classes", render: (r) => <span className="truncate">{r.classes.join(", ")}</span> },
    {
      key: "resource",
      label: "Resource",
      render: (r) =>
        r.asset_ids && r.asset_ids.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {r.asset_ids.map((id) => (
              <Link
                key={id}
                to={`/inventory?q=${encodeURIComponent(resourceNameFor(r.id, id))}`}
                className="text-xs text-lm-accent hover:underline truncate max-w-[140px]"
                title={id}
              >
                {resourceNameFor(r.id, id)}
              </Link>
            ))}
          </div>
        ) : (
          <span className="text-xs text-lm-dim">All</span>
        ),
    },
    { key: "depth", label: "Depth", render: (r) => DEPTH_LABEL[r.scan_depth] },
    {
      key: "started",
      label: "Started",
      render: (r) => (
        <span className="text-xs text-lm-dim">
          {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
        </span>
      ),
    },
    {
      key: "state",
      label: "State",
      render: (r) => {
        const style = RUN_STATE_STYLE[r.state];
        return (
          <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold ${style.bg} ${style.fg}`}>
            {style.pulse && <span className="h-1.5 w-1.5 rounded-full bg-lm-accent animate-pulse" />}
            {r.state.toUpperCase()}
          </span>
        );
      },
    },
    {
      key: "inventory",
      label: "",
      render: (r) => (
        <Link to={inventoryLinkForClasses(r.classes, r.state === "running")} className="text-xs text-lm-accent hover:underline">
          View in Inventory
        </Link>
      ),
    },
    {
      key: "report",
      label: "",
      render: (r) => (
        <button onClick={() => setExportingRun(r)} className="text-xs text-lm-accent hover:underline">
          Download report
        </button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader title="New scan" subtitle="Every asset class runs against your live OCI tenancy or GCP project(s)." />

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Engagement</div>
          <select
            value={engagementId}
            onChange={(e) => setEngagementId(e.target.value)}
            className="w-full max-w-md rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm mb-6 focus:outline-none focus:border-lm-accent"
          >
            <option value="">None — use the active profile for each provider</option>
            {(engagements ?? []).map((e) => (
              <option key={e.id} value={e.id}>{e.name} ({e.profiles.length} profile{e.profiles.length === 1 ? "" : "s"})</option>
            ))}
          </select>

          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">
            Scan a specific resource (optional — selects its asset class, compartment and region automatically)
          </div>
          <div className="relative max-w-md mb-2">
            <input
              type="text"
              value={assetQuery}
              onChange={(e) => setAssetQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && assetMatches.length === 0) addFreeTextAsset();
              }}
              placeholder="Search inventory by name or id…"
              className="w-full rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
            />
            {assetMatches.length > 0 && (
              <ul className="absolute z-10 mt-1 w-full rounded-md border border-lm-line bg-lm-panel shadow-lg max-h-56 overflow-y-auto">
                {assetMatches.map((a) => (
                  <li key={a.id}>
                    <button
                      onClick={() => selectAsset(a)}
                      className="w-full text-left px-3 py-2 text-sm hover:bg-lm-panel-2 flex items-center justify-between gap-2"
                    >
                      <span className="truncate">{a.name}</span>
                      <span className="text-[11px] text-lm-clean shrink-0">found in inventory</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {selectedAssets.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-6">
              {selectedAssets.map((a) => (
                <span
                  key={a.id}
                  className="inline-flex items-center gap-2 rounded-md border border-lm-line bg-lm-panel-2 px-3 py-1.5 text-xs"
                >
                  <span className="truncate max-w-[200px]">{a.name}</span>
                  <span className={a.inInventory ? "text-lm-clean" : "text-lm-dim"}>
                    {a.inInventory ? "in inventory" : "not in inventory"}
                  </span>
                  <button onClick={() => removeSelectedAsset(a.id)} className="text-lm-dim hover:text-lm-critical">×</button>
                </span>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={() => setClassesExpanded((v) => !v)}
            className="w-full flex items-center justify-between text-[11px] uppercase tracking-widest text-lm-dim mb-2"
          >
            <span>Asset classes ({selected.length} selected)</span>
            <span>{classesExpanded ? "▾" : "▸"}</span>
          </button>
          {classesExpanded && (selectedEngagement && classSections.length === 0 ? (
            <div className="text-sm text-lm-dim mb-4">
              No active, verified profiles in this engagement — add one on the Engagements page first.
            </div>
          ) : (
            classSections.map((section) => (
              <div key={section.provider ?? "all"} className="mb-4">
                {section.provider && (
                  <div className="text-xs font-semibold text-lm-dim mb-2">{CSP_LABEL[section.provider]}</div>
                )}
                <div className="grid grid-cols-2 gap-2">
                  {section.classes.map((c) => (
                    <label
                      key={c.scanner}
                      className={`flex items-center gap-3 rounded-md border px-4 py-3 cursor-pointer ${
                        selected.includes(c.scanner) ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selected.includes(c.scanner)}
                        onChange={() => toggle(c.scanner)}
                        className="accent-lm-accent"
                      />
                      <span className="text-sm font-medium">{c.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            ))
          ))}
          {selectedEngagement?.asset_classes && (
            <div className="text-xs text-lm-dim mb-4">Narrowed to this engagement's scope.</div>
          )}

          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2 mt-4">
            Compartments / projects ({selectedCompartments.length ? `${selectedCompartments.length} selected` : "all if none selected"})
          </div>
          {compartmentSections.map((section) => (
            <div key={section.provider} className="mb-4">
              <div className="text-xs font-semibold text-lm-dim mb-2">{CSP_LABEL[section.provider]}</div>
              {section.items.length === 0 ? (
                <div className="text-xs text-lm-dim">
                  No {section.provider === "gcp" ? "GCP projects" : "OCI compartments"} discovered yet — run a{" "}
                  {section.provider === "gcp" ? "GCP" : "OCI"} inventory scan first.
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                  {section.items.map((c) => (
                    <label
                      key={c.compartment_id}
                      className={`flex items-center gap-3 rounded-md border px-4 py-3 cursor-pointer ${
                        selectedCompartments.includes(c.compartment_id) ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedCompartments.includes(c.compartment_id)}
                        onChange={() => toggleCompartment(c.compartment_id)}
                        className="accent-lm-accent"
                      />
                      <span className="text-sm font-medium truncate">{c.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          ))}

          <button
            type="button"
            onClick={() => setRegionsExpanded((v) => !v)}
            className="w-full flex items-center justify-between text-[11px] uppercase tracking-widest text-lm-dim mb-2 mt-4"
          >
            <span>Regions ({selectedRegions.length ? selectedRegions.length : "all"})</span>
            <span>{regionsExpanded ? "▾" : "▸"}</span>
          </button>
          {regionsExpanded && (regionsAvailable.length === 0 ? (
            <div className="text-xs text-lm-dim mb-4">No regions discovered yet — run an inventory scan first.</div>
          ) : (
            <div className="grid grid-cols-2 gap-2 mb-6 max-h-48 overflow-y-auto">
              {regionsAvailable.map((r) => (
                <label
                  key={r.region}
                  className={`flex items-center gap-3 rounded-md border px-4 py-3 cursor-pointer ${
                    selectedRegions.includes(r.region) ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedRegions.includes(r.region)}
                    onChange={() => toggleRegion(r.region)}
                    className="accent-lm-accent"
                  />
                  <span className="text-sm font-medium">{r.region}</span>
                </label>
              ))}
            </div>
          ))}

          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2 mt-4">Depth</div>
          <div className="grid grid-cols-3 gap-2 mb-6">
            {([
              ["inventory", "Inventory only", "Collects assets. Runs no security or compliance checks."],
              ["rules", "Inventory + rules", "Collects assets and runs every check available today."],
              ["full", "Full assessment", "Runs every check available today; attack graph analysis is coming in a future release."],
            ] as [ScanDepth, string, string][]).map(([id, label, desc]) => (
              <button
                key={id}
                onClick={() => setDepth(id)}
                className={`text-left rounded-md border px-4 py-3 ${
                  depth === id ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                }`}
              >
                <div className="text-sm font-medium">{label}</div>
                <div className="text-xs text-lm-dim mt-1">{desc}</div>
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
            <h2 className="font-display text-sm font-semibold mb-4">Run summary</h2>
            <dl className="text-sm flex flex-col gap-2 mb-5">
              <div className="flex justify-between"><dt className="text-lm-dim">Classes selected</dt><dd>{selected.length}</dd></div>
              <div className="flex justify-between"><dt className="text-lm-dim">Engagement</dt><dd className="text-right">{selectedEngagement?.name ?? "None"}</dd></div>
              <div className="flex justify-between">
                <dt className="text-lm-dim">Profiles</dt>
                <dd>{selectedEngagement ? `${eligibleProfiles().length} active, verified` : "Active profile"}</dd>
              </div>
            </dl>
            {selectedEngagement && eligibleProfiles().length === 0 && (
              <div className="text-xs text-lm-critical mb-4">
                No active, verified profiles in this engagement — verify or activate one on the Engagements page first.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Run &amp; schedule</div>
          <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
            <Button variant="primary" disabled={startDisabled} onClick={start} className="mb-5">
              {isRunning ? "Scanning…" : "Start scan"}
            </Button>

            {Object.keys(runs).length > 0 && (
              <div className="flex flex-col gap-3 mb-5">
                {Object.values(runs).map((run) => (
                  <div key={run.id} className="rounded-md border border-lm-line p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-display text-sm font-semibold">
                        Run {run.state === "running" ? "in progress" : run.state}
                      </h3>
                      <Link to={inventoryLinkForClasses(run.classes, run.state === "running")} className="text-xs text-lm-accent hover:underline">View in Inventory</Link>
                    </div>
                    <ProgressBar percent={run.progress.percent} active={run.state === "running"} className="mb-4" />
                    <div className="flex flex-col gap-2">
                      {run.collectors.map((c) => {
                        const style = COLLECTOR_STATUS_STYLE[c.status] ?? COLLECTOR_STATUS_STYLE.pending;
                        return (
                          <div key={c.job_id} className="flex items-center justify-between gap-3 rounded-md border border-lm-line px-3 py-2">
                            <span className="font-mono text-xs shrink-0">{c.scanner_type}</span>
                            <span className="text-xs text-lm-dim truncate flex-1 text-right mr-2">
                              {c.progress_message ?? style.label}
                            </span>
                            <span className={`shrink-0 inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold ${style.bg} ${style.fg}`}>
                              {style.pulse && <span className={`h-1.5 w-1.5 rounded-full ${style.dot} animate-pulse`} />}
                              {style.label}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="border-t border-lm-line pt-5">
              <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-3">Schedule this selection</div>

              <div className="flex items-center gap-2 mb-4">
                {(["interval", "once"] as ScheduleMode[]).map((m) => (
                  <button
                    key={m}
                    onClick={() => setScheduleMode(m)}
                    className={`rounded-md border px-4 py-2 text-sm font-medium ${
                      scheduleMode === m ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                    }`}
                  >
                    {m === "interval" ? "Recurring" : "One-time"}
                  </button>
                ))}
              </div>

              {scheduleMode === "interval" ? (
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm text-lm-dim">Every</span>
                  <input
                    type="number"
                    min={1}
                    value={intervalValue}
                    onChange={(e) => setIntervalValue(Number(e.target.value))}
                    className="w-20 rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
                  />
                  <select
                    value={intervalUnit}
                    onChange={(e) => setIntervalUnit(e.target.value as IntervalUnit)}
                    className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
                  >
                    <option value="hours">hours</option>
                    <option value="days">days</option>
                  </select>
                </div>
              ) : (
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm text-lm-dim">Run at</span>
                  <input
                    type="datetime-local"
                    value={runAt}
                    min={new Date().toISOString().slice(0, 16)}
                    onChange={(e) => setRunAt(e.target.value)}
                    className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
                  />
                </div>
              )}

              <Button variant="primary" disabled={!canCreateSchedule || creatingSchedule} onClick={createSchedule}>
                {creatingSchedule ? "Creating…" : "Add schedule"}
              </Button>

              <div className="mt-5">
                {schedules.length === 0 ? (
                  <div className="text-sm text-lm-dim">No scheduled scans yet.</div>
                ) : (
                  <div className="flex flex-col gap-3">
                    {schedules.map((s) => {
                      const lastRun = s.last_run_id ? scheduleRuns[s.last_run_id] : undefined;
                      const scheduleIsRunning = lastRun?.state === "running";
                      return (
                        <div key={s.id} className="flex items-center justify-between gap-4 rounded-md border border-lm-line px-4 py-3">
                          <div className="min-w-0">
                            <div className="text-sm font-medium truncate">{s.classes.join(", ")}</div>
                            <div className="text-xs text-lm-dim mt-0.5">{formatScheduleMode(s)}</div>
                          </div>
                          <div className="text-xs text-lm-dim shrink-0">
                            Next: {s.status !== "completed" && s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"}
                          </div>
                          {lastRun && (
                            <div className="flex items-center gap-2 shrink-0 text-xs">
                              {scheduleIsRunning ? (
                                <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 font-semibold bg-lm-accent/15 text-lm-accent">
                                  <span className="h-1.5 w-1.5 rounded-full bg-lm-accent animate-pulse" />
                                  Running {lastRun.progress.percent}%
                                </span>
                              ) : (
                                <span className="text-lm-dim">Last run: {lastRun.state}</span>
                              )}
                              <Link to={inventoryLinkForClasses(s.classes, scheduleIsRunning)} className="text-lm-accent hover:underline">
                                View in Inventory
                              </Link>
                            </div>
                          )}
                          <span
                            className={`shrink-0 inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold tracking-wide ${
                              s.status === "active" ? "bg-lm-clean/15 text-lm-clean" :
                              s.status === "disabled" ? "bg-lm-line text-lm-dim" : "bg-lm-accent/15 text-lm-accent"
                            }`}
                          >
                            {s.status.toUpperCase()}
                          </span>
                          <div className="flex items-center gap-2 shrink-0">
                            {s.status !== "completed" && (
                              <Button variant="secondary" onClick={() => toggleScheduleStatus(s)}>
                                {s.status === "active" ? "Disable" : "Enable"}
                              </Button>
                            )}
                            <Button variant="destructive" onClick={() => removeSchedule(s.id)}>Delete</Button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Recent scans</div>
          <DataTable
            columns={recentScanColumns}
            rows={recentRuns ?? []}
            keyField={(r) => r.id}
            loading={recentRuns === null}
            emptyLabel="No scans run yet."
          />
        </div>
      </div>

      <ExportDialog
        open={exportingRun !== null}
        onClose={() => setExportingRun(null)}
        filter={exportingRun ? { asset_class: assetClassFilterForClasses(exportingRun.classes) } : {}}
        scopeLabel={exportingRun ? exportingRun.classes.join(", ") : ""}
        formats={RECENT_SCANS_EXPORT_FORMATS}
      />
    </div>
  );
}
