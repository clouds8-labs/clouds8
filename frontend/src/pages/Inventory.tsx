import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { backendApi, dbApi } from "../api/client";
import type { AssetFilter } from "../api/client";
import { ASSET_TYPE_SCANNERS, SCAN_STATUS_UNTRACKED_CLASSES } from "../api/types";
import type { Asset, Engagement, Profile, Run } from "../api/types";
import { Button } from "../components/Button";
import { type Column, DataTable } from "../components/DataTable";
import { ExportDialog } from "../components/ExportDialog";
import { ExposureBadge } from "../components/ExposureBadge";
import { PageHeader } from "../components/PageHeader";
import { ProgressBar } from "../components/ProgressBar";
import { ScanStatusBadge } from "../components/ScanStatusBadge";

const PAGE_SIZE = 25;

const ASSET_CLASS_OPTIONS = [
  { value: "", label: "All classes" },
  { value: "vm", label: "Virtual Machines" },
  { value: "bucket", label: "Storage Buckets" },
  { value: "adb", label: "Autonomous Databases" },
  { value: "vault", label: "Vaults" },
  { value: "volume", label: "Block Volumes" },
  { value: "image", label: "Custom Images" },
  { value: "policy", label: "IAM Policies" },
  { value: "user", label: "IAM Users" },
  { value: "group", label: "IAM Groups" },
  { value: "dynamic_group", label: "Dynamic Groups" },
  { value: "oke_cluster", label: "OKE Clusters" },
  { value: "function_app", label: "Functions Apps" },
  { value: "gcp_service_account", label: "GCP Service Accounts" },
];

type ScanStatusBucket = "" | "scanned" | "not_scanned" | "in_progress";

const SCAN_STATUS_OPTIONS: { value: ScanStatusBucket; label: string }[] = [
  { value: "", label: "All statuses" },
  { value: "scanned", label: "Scanned" },
  { value: "in_progress", label: "In progress" },
  { value: "not_scanned", label: "Not scanned" },
];

// An asset class is "in progress" if it still has not_scanned rows and its
// scanner is part of the currently-active Run. scan_status has no real
// "in progress" value in the DB (see ASSET_TYPE_SCANNERS's doc comment) -
// this is purely a frontend derivation from the live Run.
function computeInProgressClasses(run: Run | null): string[] {
  if (!run) return [];
  return Object.entries(ASSET_TYPE_SCANNERS)
    .filter(([, scanners]) => scanners.some((s) => run.classes.includes(s)))
    .map(([assetType]) => assetType);
}

type SortKey = "" | "name" | "findings" | "last_scanned";

function buildBaseFilter(
  q: string, assetClass: string, account: string, exposure: string, scanStatus: ScanStatusBucket,
  severity: string, sortBy: SortKey, sortDir: "asc" | "desc", profileId: string, engagementId: string,
) {
  return {
    q: q || undefined,
    asset_class: assetClass || undefined,
    account: account || undefined,
    exposure: exposure || undefined,
    scan_status: scanStatus === "scanned" || scanStatus === "not_scanned" ? scanStatus : undefined,
    severity: severity || undefined,
    sort: sortBy || undefined,
    order: sortBy ? sortDir : undefined,
    profile_id: profileId || undefined,
    engagement_id: engagementId || undefined,
  };
}

export function Inventory() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [total, setTotal] = useState(0);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([]);

  const [q, setQ] = useState("");
  const [assetClass, setAssetClass] = useState(() => searchParams.get("assetClass") ?? "");
  const [account, setAccount] = useState(() => searchParams.get("account") ?? "");
  const [exposure, setExposure] = useState("");
  const [scanStatus, setScanStatus] = useState<ScanStatusBucket>(() => {
    const fromUrl = searchParams.get("scanStatus");
    return fromUrl === "scanned" || fromUrl === "not_scanned" || fromUrl === "in_progress" ? fromUrl : "";
  });
  const [severity, setSeverity] = useState("");
  const [sortBy, setSortBy] = useState<SortKey>("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [exportOpen, setExportOpen] = useState(false);
  const [profileId, setProfileId] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [engagementId, setEngagementId] = useState(() => searchParams.get("engagementId") ?? "");
  const [engagements, setEngagements] = useState<Engagement[]>([]);

  useEffect(() => {
    dbApi.listProfiles().then((r) => setProfiles(r.items));
    dbApi.listEngagements().then((r) => setEngagements(r.items));
  }, []);

  // Default direction on first click of a column: name reads better
  // ascending (A->Z), findings/last_scanned are more useful descending
  // (most findings / most recent first). Clicking the already-active
  // column just flips direction.
  const handleSort = (key: string) => {
    const k = key as SortKey;
    if (sortBy === k) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(k);
      setSortDir(k === "name" ? "asc" : "desc");
    }
  };

  const [activeRun, setActiveRun] = useState<Run | null>(null);
  const pollRef = useRef<number | null>(null);

  // Refs so the long-lived run-polling effect (subscribed once, empty dep
  // array) always sees fresh values without resubscribing its interval.
  const activeRunRef = useRef(activeRun);
  useEffect(() => { activeRunRef.current = activeRun; }, [activeRun]);
  const scanStatusRef = useRef(scanStatus);
  useEffect(() => { scanStatusRef.current = scanStatus; }, [scanStatus]);
  const cursorRef = useRef(cursor);
  useEffect(() => { cursorRef.current = cursor; }, [cursor]);

  const inProgressClasses = useMemo(() => computeInProgressClasses(activeRun), [activeRun]);

  const currentFilter = buildBaseFilter(q, assetClass, account, exposure, scanStatus, severity, sortBy, sortDir, profileId, engagementId);

  const inProgressTargetClasses = scanStatus === "in_progress"
    ? (assetClass ? [assetClass] : inProgressClasses)
    : [];
  const isMergedQuery = scanStatus === "in_progress" && inProgressTargetClasses.length > 1;

  // cursorStack holds one entry per page already visited backward from the
  // current one, so its length is exactly "pages back from here" - current
  // page number falls out directly without tracking it separately.
  const currentPage = cursorStack.length + 1;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  // Empty-state copy for the cases where we deliberately skip the fetch
  // (there's nothing meaningful to ask the server for).
  let emptyMessage = "No assets match the current filters.";
  if ((scanStatus === "scanned" || scanStatus === "in_progress") && assetClass && SCAN_STATUS_UNTRACKED_CLASSES.includes(assetClass)) {
    emptyMessage = "Scan status isn't tracked for this asset class yet.";
  } else if (scanStatus === "in_progress") {
    if (!activeRun) {
      emptyMessage = "No scan is currently running. Start one from the Scans page.";
    } else if (assetClass && !inProgressClasses.includes(assetClass)) {
      emptyMessage = "The current scan does not include this asset class.";
    } else if (inProgressTargetClasses.length === 0) {
      emptyMessage = "No scan is currently running. Start one from the Scans page.";
    }
  }

  // The single-query filter Next/Previous (and the "" / scanned / not_scanned
  // buckets) use — covers every case except the merged multi-class query,
  // which has no single meaningful cursor and disables paging instead.
  const queryFilter: AssetFilter = scanStatus === "in_progress" && inProgressTargetClasses.length === 1
    ? { ...currentFilter, asset_class: inProgressTargetClasses[0], scan_status: "not_scanned" }
    : currentFilter;

  function clearAccountFilter() {
    setAccount("");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("account");
      return next;
    });
  }

  // `silent`: the 3s active-run poll re-calls load() on every tick while
  // watching an in-progress scan so the table reflects rows as they get
  // marked scanned - without this flag that was clearing `assets` to null
  // (the DataTable's loading/skeleton state) every single tick, producing
  // a full flash-to-skeleton-and-back every 3 seconds even when nothing
  // had actually changed. A real filter change still gets the loading
  // skeleton (silent defaults to false) since that's a user-initiated,
  // one-shot fetch where a brief loading state is expected, not a
  // recurring background refresh.
  const load = useCallback((c: string | undefined, silent = false) => {
    const run = activeRunRef.current;
    const ipClasses = computeInProgressClasses(run);
    const base = buildBaseFilter(q, assetClass, account, exposure, scanStatus, severity, sortBy, sortDir, profileId, engagementId);

    if ((scanStatus === "scanned" || scanStatus === "in_progress") && assetClass && SCAN_STATUS_UNTRACKED_CLASSES.includes(assetClass)) {
      setAssets([]);
      setTotal(0);
      return;
    }

    if (scanStatus === "in_progress") {
      if (!run) {
        setAssets([]);
        setTotal(0);
        return;
      }
      if (assetClass && !ipClasses.includes(assetClass)) {
        setAssets([]);
        setTotal(0);
        return;
      }
      const targets = assetClass ? [assetClass] : ipClasses;
      if (targets.length === 0) {
        setAssets([]);
        setTotal(0);
        return;
      }

      if (!silent) setAssets(null);
      if (targets.length === 1) {
        dbApi
          .listAssets({ ...base, asset_class: targets[0], scan_status: "not_scanned", cursor: c, limit: PAGE_SIZE })
          .then((r) => {
            setAssets(r.items);
            setTotal(r.total);
          });
      } else {
        Promise.all(
          targets.map((cls) =>
            dbApi.listAssets({ ...base, asset_class: cls, scan_status: "not_scanned", limit: 100 }),
          ),
        ).then((results) => {
          setAssets(results.flatMap((r) => r.items));
          setTotal(results.reduce((sum, r) => sum + r.total, 0));
        });
      }
      return;
    }

    if (!silent) setAssets(null);
    dbApi
      .listAssets({ ...base, cursor: c, limit: PAGE_SIZE })
      .then((r) => {
        setAssets(r.items);
        setTotal(r.total);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, assetClass, account, exposure, scanStatus, severity, sortBy, sortDir, profileId, engagementId]);

  const loadRef = useRef(load);
  useEffect(() => { loadRef.current = load; }, [load]);

  useEffect(() => {
    setCursor(undefined);
    setCursorStack([]);
    load(undefined);
  }, [load]);

  // Poll for an active run so the banner + eventual refresh reflect a scan
  // in progress. No SSE - this is the same polling model the rest of the
  // app uses. Reads load/cursor/scanStatus via refs (not deps) so this
  // interval is never resubscribed - it just always calls the freshest
  // versions of each.
  useEffect(() => {
    const checkRuns = () => {
      backendApi.listRuns(1).then((r) => {
        const running = r.items.find((run) => run.state === "running") ?? null;
        setActiveRun((prev) => {
          if (running) {
            // Keep the "In progress" view live as rows get marked scanned.
            if (scanStatusRef.current === "in_progress") loadRef.current(cursorRef.current, true);
            return running;
          }
          if (prev) loadRef.current(cursorRef.current, true); // a run just finished - refresh the table
          return null;
        });
      });
    };
    checkRuns();
    pollRef.current = window.setInterval(checkRuns, 3000);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const columns: Column<Asset>[] = [
    {
      key: "name", label: "Asset", sortKey: "name",
      render: (a) => (
        <div>
          <div className="font-medium text-lm-text">{a.name}</div>
          <div className="text-xs text-lm-dim font-mono truncate max-w-[260px]">{a.id}</div>
        </div>
      ),
    },
    { key: "class", label: "Type", render: (a) => <span className="uppercase text-xs text-lm-dim">{a.class}</span> },
    { key: "profile", label: "Profile", render: (a) => a.profile_name ?? "—" },
    { key: "account", label: "Compartment", render: (a) => a.compartment ?? "—" },
    { key: "region", label: "Region", render: (a) => a.region ?? "—" },
    { key: "exposure", label: "Exposure", render: (a) => <ExposureBadge exposure={a.exposure} /> },
    {
      key: "scan_status", label: "Scan status",
      render: (a) => <ScanStatusBadge asset={a} inProgressClasses={inProgressClasses} />,
    },
    {
      key: "last_scanned_at", label: "Last scanned", sortKey: "last_scanned",
      render: (a) => (
        <span className="text-xs text-lm-dim">
          {a.last_scanned_at ? new Date(a.last_scanned_at).toLocaleString() : "—"}
        </span>
      ),
    },
    {
      key: "findings", label: "Findings", sortKey: "findings",
      render: (a) => (
        <span className={a.finding_counts.total > 0 ? "text-lm-critical font-medium" : "text-lm-dim"}>
          {a.finding_counts.total}
        </span>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Inventory"
        subtitle={`${total.toLocaleString()} assets`}
        actions={<Button variant="primary" onClick={() => setExportOpen(true)}>Export</Button>}
      />

      {activeRun && (
        <div className="mb-4 rounded-lg border border-lm-accent/40 bg-lm-accent/10 p-4">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-sm font-medium text-lm-accent">
              <span className="h-2 w-2 rounded-full bg-lm-accent animate-pulse" />
              Scan in progress
            </div>
            <div className="text-xs text-lm-dim">
              {activeRun.progress.succeeded + activeRun.progress.failed}/{activeRun.progress.total} collectors complete
            </div>
          </div>
          <ProgressBar percent={activeRun.progress.percent} active className="mb-3" />
          <div className="flex flex-wrap gap-1.5">
            {activeRun.classes.map((cls) => (
              <span
                key={cls}
                className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-mono bg-lm-panel-2 text-lm-dim border border-lm-line"
              >
                {cls}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-4 mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search name or OCID…"
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm w-64 focus:outline-none focus:border-lm-accent"
          />
          <select
            value={assetClass}
            onChange={(e) => setAssetClass(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            {ASSET_CLASS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
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
          <select
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            <option value="">All profiles</option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>

        <div className="h-6 w-px bg-lm-line" />

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={exposure}
            onChange={(e) => setExposure(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            <option value="">All exposures</option>
            <option value="internet_facing">Internet-facing</option>
            <option value="internal">Internal</option>
          </select>
          <select
            value={scanStatus}
            onChange={(e) => setScanStatus(e.target.value as ScanStatusBucket)}
            className="rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            {SCAN_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>

        {account && (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-lm-accent/40 bg-lm-accent/10 px-2.5 py-1.5 text-xs text-lm-accent">
            Compartment: {account}
            <button
              onClick={clearAccountFilter}
              aria-label="Clear compartment filter"
              className="hover:text-lm-text"
            >
              ×
            </button>
          </span>
        )}
      </div>

      <DataTable
        columns={columns}
        rows={assets ?? []}
        keyField={(a) => a.id}
        loading={assets === null}
        onRowClick={(a) => navigate(`/inventory/${encodeURIComponent(a.id)}`)}
        emptyLabel={emptyMessage}
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
      />

      <div className="flex items-center justify-end gap-2 mt-4">
        <Button
          variant="secondary"
          disabled={isMergedQuery || cursorStack.length === 0}
          onClick={() => {
            const prevStack = [...cursorStack];
            const prevCursor = prevStack.pop();
            setCursorStack(prevStack);
            setCursor(prevCursor);
            load(prevCursor);
          }}
        >
          Previous
        </Button>
        {!isMergedQuery && totalPages > 0 && (
          <span className="text-xs text-lm-dim">
            Page {currentPage} of {totalPages}
          </span>
        )}
        <Button
          variant="secondary"
          disabled={isMergedQuery || assets === null || assets.length === 0}
          onClick={() => {
            dbApi.listAssets({ ...queryFilter, cursor, limit: PAGE_SIZE }).then((r) => {
              if (r.next_cursor) {
                setCursorStack((s) => [...s, cursor]);
                setCursor(r.next_cursor);
                load(r.next_cursor);
              }
            });
          }}
        >
          Next
        </Button>
      </div>

      <ExportDialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        filter={currentFilter}
        scopeLabel="Current filtered view"
      />
    </div>
  );
}
