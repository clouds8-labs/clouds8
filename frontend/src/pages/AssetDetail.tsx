import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { dbApi } from "../api/client";
import type { Asset, Finding } from "../api/types";
import { ExposureBadge } from "../components/ExposureBadge";
import { type PropertyField, PropertyList } from "../components/PropertyList";
import { SeverityBadge } from "../components/SeverityBadge";
import { SkeletonLines } from "../components/Skeleton";

type Tab = "findings" | "relationships" | "raw";

// Structured field specs for the Raw configuration tab - classes absent here
// fall back to the bare JSON dump. Scoped to vm/bucket for now; the legacy
// Dash UI's raw cloud-init/user-metadata/extended-metadata content is
// deliberately not reintroduced here (that's exactly what the secret-scanner
// targets - findings for it already surface via the Findings tab). A
// function (not a plain object) so the "Has Cloud-Init" row can link into
// the Findings tab via the caller's setTab.
function buildFieldSpecs(onViewFindings: () => void): Record<string, PropertyField[]> {
  return {
  vm: [
    { key: "public_ips", label: "Public IPs", format: "stringArray" },
    { key: "private_ips", label: "Private IPs", format: "stringArray" },
    { key: "vnic_names", label: "VNIC Names", format: "stringArray" },
    { key: "subnet_ids", label: "Subnet IDs", format: "stringArray" },
    { key: "agent_monitoring", label: "Agent Monitoring", format: "boolean" },
    { key: "legacy_imds_disabled", label: "Legacy IMDS Disabled", format: "boolean" },
    {
      key: "has_cloud_init", label: "Has Cloud-Init", format: "boolean",
      labelExtra: (
        <button onClick={onViewFindings} className="ml-1.5 text-[11px] text-lm-accent hover:underline">
          (any secrets found? see Findings)
        </button>
      ),
    },
    { key: "shape", label: "Shape" },
    { key: "lifecycle_state", label: "Lifecycle State" },
    { key: "availability_domain", label: "Availability Domain" },
    { key: "freeform_tags", label: "Tags", format: "tags" },
    {
      key: "cloud_init_data", label: "Cloud-Init Data", format: "multilineText",
      labelExtra: <span className="ml-1.5 text-[11px] text-lm-dim">(secrets redacted)</span>,
    },
    {
      key: "user_metadata", label: "User Metadata", format: "keyValueBlock",
      labelExtra: <span className="ml-1.5 text-[11px] text-lm-dim">(secrets redacted)</span>,
    },
    {
      key: "extended_metadata", label: "Extended Metadata", format: "keyValueBlock",
      labelExtra: <span className="ml-1.5 text-[11px] text-lm-dim">(secrets redacted)</span>,
    },
  ],
  bucket: [
    { key: "public_access_type", label: "Public Access Type" },
    { key: "storage_tier", label: "Storage Tier" },
    { key: "versioning", label: "Versioning" },
    { key: "kms_key_id", label: "Encryption", format: "kmsKey" },
    { key: "approximate_count", label: "Approximate Object Count" },
    { key: "approximate_size", label: "Approximate Size", format: "bytes" },
    { key: "replication_enabled", label: "Replication Enabled", format: "boolean" },
    { key: "namespace", label: "Namespace" },
    { key: "freeform_tags", label: "Tags", format: "tags" },
  ],
  };
}

function RiskBar({ label, value }: { label: string; value: number }) {
  const pct = Math.min(100, (value / 10) * 100);
  const color = value >= 8 ? "var(--lm-critical)" : value >= 5 ? "var(--lm-high)" : "var(--lm-low)";
  return (
    <div className="mb-2">
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-lm-dim">{label}</span>
        <span className="font-mono text-lm-text">{value.toFixed(1)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-lm-line overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

export function AssetDetail() {
  const { assetId = "" } = useParams();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    setAsset(null);
    setFindings(null);
    setNotFound(false);
    dbApi.getAsset(assetId).then(setAsset).catch(() => setNotFound(true));
    dbApi.getAssetFindings(assetId).then(setFindings).catch(() => setFindings([]));
  }, [assetId]);

  if (notFound) {
    return (
      <div>
        <div className="text-xs text-lm-dim mb-4">
          <Link to="/inventory" className="hover:text-lm-text">Inventory</Link> / …
        </div>
        <div className="rounded-md border border-dashed border-lm-line px-4 py-8 text-center text-sm text-lm-dim">
          Asset not found — it may not be collected into inventory yet, or the ID is stale.
        </div>
      </div>
    );
  }

  if (!asset) {
    return (
      <div>
        <div className="text-xs text-lm-dim mb-4">
          <Link to="/inventory" className="hover:text-lm-text">Inventory</Link> / …
        </div>
        <SkeletonLines widths={["40%", "60%", "30%"]} />
      </div>
    );
  }

  const fc = asset.finding_counts;
  const fieldSpec = buildFieldSpecs(() => setTab("findings"))[asset.class];

  return (
    <div>
      <div className="text-xs text-lm-dim mb-2">
        <Link to="/inventory" className="hover:text-lm-text">Inventory</Link>
        {" / "}
        <Link to={`/inventory?assetClass=${encodeURIComponent(asset.class)}`} className="uppercase hover:text-lm-text">
          {asset.class}
        </Link>
        {" / "}
        <span className="text-lm-text">{asset.name}</span>
      </div>
      <div className="flex items-center gap-3 mb-6">
        <h1 className="font-display text-2xl font-semibold">{asset.name}</h1>
        <ExposureBadge exposure={asset.exposure} />
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
          <h2 className="font-display text-sm font-semibold mb-3">Identity</h2>
          <dl className="text-sm flex flex-col gap-2">
            <div className="flex justify-between gap-4">
              <dt className="text-lm-dim">ID</dt>
              <dd className="font-mono text-xs text-right break-all">{asset.id}</dd>
            </div>
            <div className="flex justify-between"><dt className="text-lm-dim">Compartment</dt><dd>{asset.compartment ?? "—"}</dd></div>
            <div className="flex justify-between"><dt className="text-lm-dim">Region</dt><dd>{asset.region ?? "—"}</dd></div>
            <div className="flex justify-between"><dt className="text-lm-dim">Scan status</dt><dd>{asset.scan_status ?? "—"}</dd></div>
            <div className="flex justify-between"><dt className="text-lm-dim">Last scanned</dt><dd className="text-xs">{asset.last_scanned_at ?? "—"}</dd></div>
          </dl>
        </div>

        <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
          <h2 className="font-display text-sm font-semibold mb-1">Risk profile</h2>
          <div className="font-display text-3xl font-semibold mb-3" style={{ color: asset.risk >= 8 ? "var(--lm-critical)" : asset.risk >= 5 ? "var(--lm-high)" : "var(--lm-clean)" }}>
            {asset.risk.toFixed(1)}
          </div>
          <RiskBar label="Critical findings" value={Math.min(10, fc.critical * 2)} />
          <RiskBar label="High findings" value={Math.min(10, fc.high * 2)} />
          <RiskBar label="Exposure" value={asset.exposure === "internet_facing" ? 10 : 2} />
        </div>

        <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
          <h2 className="font-display text-sm font-semibold mb-3">Findings summary</h2>
          <div className="flex flex-col gap-2 text-sm">
            <div className="flex items-center justify-between"><SeverityBadge severity="critical" /><span className="font-mono">{fc.critical}</span></div>
            <div className="flex items-center justify-between"><SeverityBadge severity="high" /><span className="font-mono">{fc.high}</span></div>
            <div className="flex items-center justify-between"><SeverityBadge severity="medium" /><span className="font-mono">{fc.medium}</span></div>
            <div className="flex items-center justify-between"><SeverityBadge severity="low" /><span className="font-mono">{fc.low}</span></div>
            {fc.info > 0 && (
              <div className="flex items-center justify-between"><SeverityBadge severity="info" /><span className="font-mono">{fc.info}</span></div>
            )}
          </div>
        </div>
      </div>

      <div className="border-b border-lm-line mb-4 flex gap-6 text-sm">
        {([
          ["findings", `Findings (${findings?.length ?? "…"})`],
          ["relationships", "Relationships"],
          ["raw", "Raw configuration"],
        ] as [Tab, string][]).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`pb-3 -mb-px border-b-2 font-medium ${
              tab === id ? "border-lm-accent text-lm-accent" : "border-transparent text-lm-dim hover:text-lm-text"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        findings === null ? (
          <SkeletonLines />
        ) : findings.length === 0 ? (
          <div className="text-sm text-lm-dim py-6">No findings — this asset passed all checks.</div>
        ) : (
          <div className="flex flex-col gap-2">
            {findings.map((f) => (
              <div key={f.id} className="rounded-md border border-lm-line px-4 py-3">
                <div className="flex items-center gap-3 mb-1">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-medium text-sm">{f.title}</span>
                  <span className="text-xs text-lm-dim font-mono ml-auto">{f.rule_id}</span>
                </div>
                <div className="text-xs text-lm-dim">{f.description}</div>
                {f.remediation && (
                  <div className="text-xs text-lm-accent mt-1">→ {f.remediation}</div>
                )}
                {f.proof_of_concept && (
                  <div className="mt-2">
                    <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-1">Proof of concept</div>
                    <pre className="text-xs font-mono bg-lm-panel-2 border border-lm-line rounded-md px-3 py-2 overflow-x-auto">
                      {f.proof_of_concept}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        )
      )}

      {tab === "relationships" && (
        <div className="rounded-md border border-dashed border-lm-line px-4 py-8 text-center text-sm text-lm-dim">
          Not available — Clouds8 does not yet build an asset relationship graph.
        </div>
      )}

      {tab === "raw" && (
        fieldSpec ? (
          <div className="flex flex-col gap-4">
            <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
              <PropertyList properties={asset.properties} fields={fieldSpec} />
            </div>
            <details>
              <summary className="text-xs text-lm-dim cursor-pointer hover:text-lm-text">View raw JSON</summary>
              <pre className="mt-2 rounded-md border border-lm-line bg-lm-panel-2 p-4 text-xs font-mono overflow-x-auto max-h-[500px] overflow-y-auto">
                {JSON.stringify(asset.properties, null, 2)}
              </pre>
            </details>
          </div>
        ) : (
          <pre className="rounded-md border border-lm-line bg-lm-panel-2 p-4 text-xs font-mono overflow-x-auto max-h-[500px] overflow-y-auto">
            {JSON.stringify(asset.properties, null, 2)}
          </pre>
        )
      )}
    </div>
  );
}
