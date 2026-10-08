import type { ReactNode } from "react";
import { SkeletonAssetRow } from "./Skeleton";

export interface Column<T> {
  key: string;
  label: string;
  render: (row: T) => ReactNode;
  width?: string;
  /** Opaque sort key passed to onSort - omit to make the column unsortable. */
  sortKey?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  keyField: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  loading?: boolean;
  skeletonRows?: number;
  emptyLabel?: string;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  onSort?: (sortKey: string) => void;
}

export function DataTable<T>({
  columns, rows, keyField, onRowClick, loading, skeletonRows = 6, emptyLabel = "No results.",
  sortBy, sortDir, onSort,
}: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto rounded-lg border border-lm-line">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-lm-panel-2 text-left text-[11px] uppercase tracking-wider text-lm-dim">
            <th className="w-8" />
            {columns.map((col) => {
              const active = !!col.sortKey && sortBy === col.sortKey;
              return (
                <th key={col.key} className="px-4 py-3 font-medium" style={{ width: col.width }}>
                  {col.sortKey && onSort ? (
                    <button
                      onClick={() => onSort(col.sortKey!)}
                      className={`inline-flex items-center gap-1 uppercase tracking-wider hover:text-lm-text ${active ? "text-lm-text" : ""}`}
                    >
                      {col.label}
                      <span className="text-[9px] w-2.5 inline-block">
                        {active ? (sortDir === "asc" ? "▲" : "▼") : ""}
                      </span>
                    </button>
                  ) : (
                    col.label
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading &&
            Array.from({ length: skeletonRows }).map((_, i) => (
              <SkeletonAssetRow key={`sk-${i}`} columns={columns.length} />
            ))}
          {!loading && rows.length === 0 && (
            <tr>
              <td colSpan={columns.length + 1} className="px-4 py-10 text-center text-lm-dim text-sm">
                {emptyLabel}
              </td>
            </tr>
          )}
          {!loading &&
            rows.map((row) => (
              <tr
                key={keyField(row)}
                onClick={() => onRowClick?.(row)}
                className={`border-b border-lm-line last:border-b-0 ${
                  onRowClick ? "cursor-pointer hover:bg-lm-panel-2" : ""
                }`}
                style={{ height: 58 }}
              >
                <td />
                {columns.map((col) => (
                  <td key={col.key} className="px-4 text-lm-text">
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
