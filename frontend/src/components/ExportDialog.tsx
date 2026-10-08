import { useState } from "react";
import { backendApi } from "../api/client";
import type { ExportFormat } from "../api/types";
import { Button } from "./Button";

interface ExportDialogProps {
  open: boolean;
  onClose: () => void;
  filter: Record<string, unknown>;
  scopeLabel: string;
  formats?: ExportFormat[];
}

const SECTIONS: { id: string; label: string }[] = [
  { id: "assets", label: "Asset inventory" },
  { id: "findings", label: "Findings detail" },
];

const DEFAULT_FORMATS: ExportFormat[] = ["csv", "json", "pdf"];

export function ExportDialog({ open, onClose, filter, scopeLabel, formats = DEFAULT_FORMATS }: ExportDialogProps) {
  const [format, setFormat] = useState<ExportFormat>(formats[0] ?? "csv");
  const [sections, setSections] = useState<string[]>(["assets", "findings"]);
  const [state, setState] = useState<"idle" | "generating" | "error">("idle");

  if (!open) return null;

  const toggleSection = (id: string) =>
    setSections((cur) => (cur.includes(id) ? cur.filter((s) => s !== id) : [...cur, id]));

  const handleExport = async () => {
    setState("generating");
    try {
      const meta = await backendApi.createExport(format, sections, filter);
      await backendApi.downloadExportFile(meta.id, meta.filename);
      setState("idle");
      onClose();
    } catch {
      setState("error");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-lg border border-lm-line bg-lm-panel p-6">
        <div className="flex items-start justify-between mb-1">
          <h2 className="font-display text-xl font-semibold">Export results</h2>
          <button onClick={onClose} className="text-lm-dim hover:text-lm-text text-lg leading-none">✕</button>
        </div>
        <p className="text-sm text-lm-dim mb-5">Scope: {scopeLabel}</p>

        <div className="mb-5">
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Format</div>
          <div className="flex gap-2">
            {formats.map((f) => (
              <button
                key={f}
                onClick={() => setFormat(f)}
                className={`rounded-md px-3 py-1.5 text-sm font-medium border ${
                  format === f
                    ? "bg-lm-accent text-lm-bg border-lm-accent"
                    : "border-lm-line text-lm-text hover:border-lm-dim"
                }`}
              >
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="mb-6">
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Sections to include</div>
          <div className="flex flex-col gap-2">
            {SECTIONS.map((s) => (
              <label key={s.id} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={sections.includes(s.id)}
                  onChange={() => toggleSection(s.id)}
                  className="accent-lm-accent"
                />
                {s.label}
              </label>
            ))}
          </div>
        </div>

        {state === "error" && (
          <div className="text-sm text-lm-critical mb-4">Export failed — please try again.</div>
        )}

        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            onClick={handleExport}
            disabled={sections.length === 0 || state === "generating"}
          >
            {state === "generating" ? "Generating…" : `Export ${format.toUpperCase()}`}
          </Button>
        </div>
      </div>
    </div>
  );
}
