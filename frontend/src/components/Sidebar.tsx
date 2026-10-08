import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { backendApi } from "../api/client";
import type { Connection } from "../api/types";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: "▦" },
  { to: "/inventory", label: "Inventory", icon: "◈" },
  { to: "/scans", label: "Scans", icon: "⌕" },
  { to: "/attack-paths", label: "Attack paths", icon: "⇢" },
  { to: "/findings", label: "Findings", icon: "◉" },
  { to: "/engagements", label: "Engagements", icon: "⚑" },
];

export function Sidebar() {
  const [connections, setConnections] = useState<Connection[] | null>(null);

  useEffect(() => {
    backendApi.listConnections().then((r) => setConnections(r.items)).catch(() => setConnections([]));
  }, []);

  return (
    <aside className="w-60 shrink-0 border-r border-lm-line bg-lm-panel h-full flex flex-col">
      <div className="px-5 py-5 flex items-center gap-2">
        <span className="text-xl">🐱</span>
        <span className="font-display font-semibold text-lg tracking-tight">clouds8</span>
      </div>

      <div className="px-3 mt-2">
        <div className="text-[10px] uppercase tracking-widest text-lm-dim px-2 mb-2">Navigation</div>
        <nav className="flex flex-col gap-0.5">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? "bg-lm-accent/15 text-lm-accent" : "text-lm-text hover:bg-lm-panel-2"
                }`
              }
            >
              <span className="w-4 text-center opacity-80">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="mt-auto px-5 py-5">
        <div className="text-[10px] uppercase tracking-widest text-lm-dim mb-2">Connected</div>
        {connections === null ? (
          <div className="text-xs text-lm-dim">Checking…</div>
        ) : connections.length === 0 ? (
          <div className="text-xs text-lm-dim">No connections</div>
        ) : (
          connections.map((c) => (
            <div key={c.id} className="flex items-center gap-2 text-xs text-lm-dim py-0.5">
              <span
                className={`h-1.5 w-1.5 rounded-full ${c.health === "healthy" ? "bg-lm-clean" : "bg-lm-dim"}`}
              />
              {c.cloud.toUpperCase()} · {c.health === "healthy" ? "connected" : "not configured"}
            </div>
          ))
        )}
        <div className="text-[10px] text-lm-dim mt-4 font-mono">v2.4.0-secure</div>
      </div>
    </aside>
  );
}
