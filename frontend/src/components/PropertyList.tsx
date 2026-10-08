import type { ReactNode } from "react";

export type PropertyFormat =
  | "text" | "boolean" | "stringArray" | "bytes" | "tags" | "kmsKey"
  | "multilineText" | "keyValueBlock";

// Formats whose content doesn't fit the standard inline label/value row -
// these render full-width, stacked below the label instead.
const BLOCK_FORMATS = new Set<PropertyFormat>(["multilineText", "keyValueBlock"]);

export interface PropertyField {
  key: string;
  label: string;
  format?: PropertyFormat;
  /** Extra content appended after the label, e.g. a link to another tab for more detail. */
  labelExtra?: ReactNode;
}

function formatBytes(value: number): string {
  if (value === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function Badge({ children, dim = false }: { children: ReactNode; dim?: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold ${
        dim ? "bg-lm-line text-lm-dim" : "bg-lm-clean/15 text-lm-clean"
      }`}
    >
      {children}
    </span>
  );
}

function renderValue(value: unknown, format: PropertyFormat): ReactNode {
  if (value === undefined) return <span className="text-lm-dim">—</span>;

  switch (format) {
    case "boolean":
      if (value === null) return <span className="text-lm-dim">—</span>;
      return value ? <Badge>Yes</Badge> : <Badge dim>No</Badge>;

    case "stringArray": {
      const arr = Array.isArray(value) ? value.filter((v) => typeof v === "string") : [];
      if (arr.length === 0) return <span className="text-lm-dim">None</span>;
      if (arr.length <= 3) return <span className="text-right break-all">{arr.join(", ")}</span>;
      return (
        <ul className="list-disc list-inside text-right">
          {arr.map((v) => (
            <li key={v} className="break-all">{v}</li>
          ))}
        </ul>
      );
    }

    case "bytes": {
      const n = typeof value === "number" ? value : Number(value);
      return Number.isFinite(n) ? <span>{formatBytes(n)}</span> : <span className="text-lm-dim">—</span>;
    }

    case "tags": {
      const tags = value && typeof value === "object" ? (value as Record<string, string>) : {};
      const entries = Object.entries(tags);
      if (entries.length === 0) return <span className="text-lm-dim">None</span>;
      return (
        <div className="flex flex-wrap gap-1.5 justify-end">
          {entries.map(([k, v]) => (
            <Badge key={k} dim>{k}: {v}</Badge>
          ))}
        </div>
      );
    }

    case "kmsKey":
      if (!value || typeof value !== "string") return <Badge dim>Oracle-managed (default)</Badge>;
      return (
        <div className="flex items-center gap-2 justify-end">
          <Badge>Customer-managed</Badge>
          <span className="font-mono text-xs text-lm-dim truncate max-w-[160px]" title={value}>
            {value}
          </span>
        </div>
      );

    case "multilineText":
      if (value === null || value === "") return <span className="text-lm-dim">—</span>;
      return (
        <pre className="rounded-md border border-lm-line bg-lm-panel-2 p-3 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
          {String(value)}
        </pre>
      );

    case "keyValueBlock": {
      const obj = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
      const entries = Object.entries(obj);
      if (entries.length === 0) return <span className="text-lm-dim">None</span>;
      return (
        <div className="rounded-md border border-lm-line divide-y divide-lm-line">
          {entries.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-4 px-3 py-1.5 text-xs">
              <span className="font-mono text-lm-dim shrink-0">{k}</span>
              <span className="font-mono text-right break-all">{String(v)}</span>
            </div>
          ))}
        </div>
      );
    }

    case "text":
    default:
      if (value === null || value === "") return <span className="text-lm-dim">—</span>;
      return <span className="text-right break-all">{typeof value === "number" ? value.toLocaleString() : String(value)}</span>;
  }
}

export function PropertyList({
  properties, fields,
}: {
  properties: Record<string, unknown>;
  fields: PropertyField[];
}) {
  return (
    <dl className="text-sm flex flex-col gap-3">
      {fields.map((f) => {
        const format = f.format ?? "text";
        const value = renderValue(properties[f.key], format);
        return BLOCK_FORMATS.has(format) ? (
          <div key={f.key} className="flex flex-col gap-1.5">
            <dt className="text-lm-dim">
              {f.label}
              {f.labelExtra}
            </dt>
            <dd>{value}</dd>
          </div>
        ) : (
          <div key={f.key} className="flex justify-between gap-4">
            <dt className="text-lm-dim shrink-0">
              {f.label}
              {f.labelExtra}
            </dt>
            <dd>{value}</dd>
          </div>
        );
      })}
    </dl>
  );
}
