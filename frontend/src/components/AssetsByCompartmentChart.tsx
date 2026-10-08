import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip,
} from "recharts";
import { dbApi } from "../api/client";
import { SkeletonLines } from "./Skeleton";

// Fixed-order categorical slots, validated against the --lm-panel dark
// surface (#171c22) via the dataviz skill's validate_palette.js — do not
// reorder or cycle these; a 9th+ slice folds into "Other" instead.
const SLOT_COLORS = [
  "#3987e5", "#199e70", "#c98500", "#008300",
  "#9085e9", "#e66767", "#d55181", "#d95926",
];
const OTHER_COLOR = "#5a6472";

const TOP_N = 8;

const ASSET_TYPE_LABELS: Record<string, string> = {
  vm: "Virtual Machines",
  bucket: "Storage Buckets",
  adb: "Autonomous Databases",
  vault: "Vaults",
  volume: "Block Volumes",
  image: "Custom Images",
  policy: "IAM Policies",
  vnic: "VNICs",
  lb: "Load Balancers",
  secret: "Secrets",
  oke_cluster: "OKE Clusters",
  function_app: "Functions Apps",
};

interface Slice {
  name: string;
  value: number;
  color: string;
  clickable: boolean;
}

function formatAssetType(type: string): string {
  return ASSET_TYPE_LABELS[type] ?? type.toUpperCase();
}

export function AssetsByCompartmentChart({ engagementId }: { engagementId?: string } = {}) {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [typeCounts, setTypeCounts] = useState<Record<string, number> | null>(null);

  useEffect(() => {
    setSelected(null);
    setTypeCounts(null);
    setSummary(null);
    dbApi.getCompartmentSummary({ engagement_id: engagementId }).then(setSummary);
  }, [engagementId]);

  const { slices, total } = useMemo(() => {
    if (!summary) return { slices: [] as Slice[], total: 0 };
    const entries = Object.entries(summary); // already sorted DESC by the backend
    const top = entries.slice(0, TOP_N);
    const rest = entries.slice(TOP_N);
    const restTotal = rest.reduce((sum, [, count]) => sum + count, 0);
    const result: Slice[] = top.map(([name, value], i) => ({
      name, value, color: SLOT_COLORS[i], clickable: true,
    }));
    if (rest.length > 0) {
      result.push({
        name: `Other (${rest.length} compartments)`,
        value: restTotal,
        color: OTHER_COLOR,
        clickable: false,
      });
    }
    const grandTotal = entries.reduce((sum, [, count]) => sum + count, 0);
    return { slices: result, total: grandTotal };
  }, [summary]);

  function handleSliceClick(slice: Slice) {
    if (!slice.clickable) return;
    setSelected(slice.name);
    setTypeCounts(null);
    dbApi.getAssetCountsByCompartment(slice.name, { engagement_id: engagementId }).then(setTypeCounts);
  }

  const selectedTotal = typeCounts ? Object.values(typeCounts).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel p-5">
      <h2 className="font-display text-base font-semibold mb-4">Assets by compartment</h2>

      {summary === null ? (
        <SkeletonLines />
      ) : slices.length === 0 ? (
        <div className="text-sm text-lm-dim">No compartment data yet.</div>
      ) : (
        <div className="grid grid-cols-2 gap-4 items-start">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={slices}
                  dataKey="value"
                  nameKey="name"
                  innerRadius="55%"
                  outerRadius="90%"
                  paddingAngle={2}
                  cursor="pointer"
                  onClick={(_, index) => handleSliceClick(slices[index])}
                >
                  {slices.map((s) => (
                    <Cell
                      key={s.name}
                      fill={s.color}
                      stroke="var(--lm-panel)"
                      strokeWidth={2}
                      opacity={selected && selected !== s.name && s.clickable ? 0.45 : 1}
                    />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value, name) => {
                    const n = Number(value);
                    return [`${n.toLocaleString()} assets (${((n / total) * 100).toFixed(1)}%)`, name];
                  }}
                  contentStyle={{
                    background: "var(--lm-panel-2)",
                    border: "1px solid var(--lm-line)",
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  itemStyle={{ color: "var(--lm-text)" }}
                />
                <Legend
                  layout="vertical"
                  align="right"
                  verticalAlign="middle"
                  wrapperStyle={{ fontSize: 11, color: "var(--lm-dim)", maxWidth: "45%" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="min-h-64 border-l border-lm-line pl-4">
            {selected === null ? (
              <div className="text-xs text-lm-dim py-6 text-center">
                Click a compartment slice to see its asset breakdown.
              </div>
            ) : (
              <>
                <div className="font-medium text-sm text-lm-text truncate mb-1">{selected}</div>
                {typeCounts === null ? (
                  <SkeletonLines widths={["60%", "80%", "50%"]} />
                ) : (
                  <>
                    <div className="flex items-center gap-2 mb-3">
                      <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-accent/15 text-lm-accent">
                        {selectedTotal.toLocaleString()} assets
                      </span>
                      <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-line text-lm-dim">
                        {Object.keys(typeCounts).length} types
                      </span>
                    </div>
                    {Object.keys(typeCounts).length === 0 ? (
                      <div className="text-xs text-lm-dim">No assets in this compartment.</div>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(typeCounts).map(([type, count]) => (
                          <button
                            key={type}
                            onClick={() =>
                              navigate(
                                `/inventory?account=${encodeURIComponent(selected)}&assetClass=${encodeURIComponent(type)}`,
                              )
                            }
                            className="rounded-md border border-lm-line px-2.5 py-1.5 text-xs text-lm-text hover:border-lm-accent hover:text-lm-accent transition-colors"
                          >
                            {count.toLocaleString()} {formatAssetType(type)}
                          </button>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
