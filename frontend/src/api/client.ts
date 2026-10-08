// Typed fetch client for the /v1 API, mirroring shared/client/'s
// config-then-typed-calls shape (db_client.py + backend_client.py) but in
// TypeScript for the browser. Two base URLs because that split already
// exists on the backend: db-service owns assets/findings reads, backend-api
// owns runs/exports/connections (anything that talks to a cloud provider or
// triggers work).
import type {
  Asset, AttackPath, CloudProvider, Connection, Engagement, ExportFormat, ExportMeta, Finding, FindingGroup,
  FindingState, IntervalUnit, ListEnvelope, Profile, Run, ScanDepth, Schedule, ScheduleMode,
  ScheduleStatus, VerifyResult, WhoAmIProfileResult,
} from "./types";
import { clearStoredAuth, getStoredToken } from "../auth/authStorage";

const DB_SERVICE_URL = import.meta.env.VITE_DB_SERVICE_URL ?? "http://localhost:8001";
const BACKEND_API_URL = import.meta.env.VITE_BACKEND_API_URL ?? "http://localhost:8002";

async function request<T>(base: string, path: string, init?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  // /auth/login is expected to return 401 on wrong credentials while the
  // user is still on the login screen - that must surface as a normal
  // thrown error (handled by Login.tsx's own catch), not trigger the
  // "session expired, redirect to /login" handling below.
  if (res.status === 401 && path !== "/auth/login") {
    clearStoredAuth();
    if (window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${init?.method ?? "GET"} ${path} -> ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

function qs<T extends object>(params: T): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : "";
}

// ── Auth (backend-api) ───────────────────────────────────────────────────────

export interface AuthResponse {
  token: string;
  expires_at: string;
}

export const authApi = {
  login: (username: string, password: string) =>
    request<AuthResponse>(BACKEND_API_URL, "/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
};

// ── Assets / findings (db-service) ──────────────────────────────────────────

export interface AssetFilter {
  cloud?: string;
  asset_class?: string;
  exposure?: string;
  severity?: string;
  region?: string;
  account?: string;
  scan_status?: string;
  q?: string;
  cursor?: string;
  limit?: number;
  sort?: "name" | "findings" | "last_scanned";
  order?: "asc" | "desc";
  profile_id?: string;
  engagement_id?: string;
}

function parseProfile(raw: any): Profile {
  return {
    ...raw,
    whoami_result: typeof raw.whoami_result === "string" ? JSON.parse(raw.whoami_result) : null,
  };
}

export const dbApi = {
  listAssets: (filter: AssetFilter = {}) =>
    request<ListEnvelope<Asset>>(DB_SERVICE_URL, `/v1/assets${qs(filter)}`),

  getAsset: (assetId: string) =>
    request<Asset>(DB_SERVICE_URL, `/v1/assets/${encodeURIComponent(assetId)}`),

  getAssetFindings: (assetId: string) =>
    request<Finding[]>(DB_SERVICE_URL, `/v1/assets/${encodeURIComponent(assetId)}/findings`),

  getAttackPaths: (entryPoint: string) =>
    request<{ items: AttackPath[] }>(DB_SERVICE_URL, `/v1/paths${qs({ entry_point: entryPoint })}`),

  listFindings: (filter: {
    rule_id?: string; asset_id?: string; account?: string; severity?: string;
    state?: string; group_by?: "rule" | "asset" | "account"; cursor?: string; limit?: number;
    profile_id?: string; engagement_id?: string;
  } = {}) =>
    request<ListEnvelope<Finding | FindingGroup>>(DB_SERVICE_URL, `/v1/findings${qs(filter)}`),

  patchFindingState: (findingId: number, state: FindingState) =>
    request<Finding>(DB_SERVICE_URL, `/v1/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ state }),
    }),

  // Auth-gated like every other /v1 route, so this fetches the body as a
  // blob and triggers the download client-side rather than pointing an
  // <a href> straight at the endpoint (see backendApi.downloadExportFile's
  // identical fix).
  downloadRuleAssets: async (ruleId: string, filter: { severity?: string; state?: string } = {}) => {
    const token = getStoredToken();
    const res = await fetch(
      `${DB_SERVICE_URL}/v1/findings/rule/${encodeURIComponent(ruleId)}/assets.txt${qs(filter)}`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    );
    if (!res.ok) throw new Error(`GET assets.txt -> ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${ruleId}-affected-assets.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  // Pre-existing, non-/v1 endpoints (predate the /v1 surface, kept as-is).
  getCompartmentSummary: (filter: { profile_id?: string; engagement_id?: string } = {}) =>
    request<Record<string, number>>(DB_SERVICE_URL, `/assets/compartment-summary${qs(filter)}`),

  getAssetCountsByCompartment: (label: string, filter: { profile_id?: string; engagement_id?: string } = {}) =>
    request<Record<string, number>>(
      DB_SERVICE_URL, `/compartments/${encodeURIComponent(label)}/asset-counts${qs(filter)}`,
    ),

  listCompartments: (cloudProvider?: string) =>
    request<{ compartment_id: string; name: string; scope_type: string }[]>(
      DB_SERVICE_URL, `/compartments${qs({ cloud_provider: cloudProvider })}`,
    ),

  listRegions: (cloudProvider?: string) =>
    request<{ region: string }[]>(DB_SERVICE_URL, `/regions${qs({ cloud_provider: cloudProvider })}`),

  // ── Profiles ─────────────────────────────────────────────────────────────
  listProfiles: (cloudProvider?: string) =>
    request<{ items: any[]; total: number }>(DB_SERVICE_URL, `/v1/profiles${qs({ cloud_provider: cloudProvider })}`)
      .then((r) => ({ ...r, items: r.items.map(parseProfile) })),

  getProfile: (id: string) =>
    request<any>(DB_SERVICE_URL, `/v1/profiles/${id}`).then(parseProfile),

  createProfile: (payload: { name: string; cloud_provider: CloudProvider; config_profile_name: string }) =>
    request<any>(DB_SERVICE_URL, "/v1/profiles", { method: "POST", body: JSON.stringify(payload) }).then(parseProfile),

  updateProfile: (id: string, payload: { name?: string; config_profile_name?: string }) =>
    request<any>(DB_SERVICE_URL, `/v1/profiles/${id}`, { method: "PATCH", body: JSON.stringify(payload) }).then(parseProfile),

  activateProfile: (id: string) =>
    request<any>(DB_SERVICE_URL, `/v1/profiles/${id}/activate`, { method: "POST" }).then(parseProfile),

  deleteProfile: (id: string) =>
    request<{ status: string }>(DB_SERVICE_URL, `/v1/profiles/${id}`, { method: "DELETE" }),

  // ── Engagements ──────────────────────────────────────────────────────────
  listEngagements: () =>
    request<{ items: Engagement[]; total: number }>(DB_SERVICE_URL, "/v1/engagements"),

  getEngagement: (id: string) =>
    request<Engagement>(DB_SERVICE_URL, `/v1/engagements/${id}`),

  createEngagement: (payload: { name: string; profile_ids: string[]; asset_classes?: string[]; regions?: string[] }) =>
    request<Engagement>(DB_SERVICE_URL, "/v1/engagements", { method: "POST", body: JSON.stringify(payload) }),

  updateEngagement: (id: string, payload: { name?: string; asset_classes?: string[]; regions?: string[] }) =>
    request<Engagement>(DB_SERVICE_URL, `/v1/engagements/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),

  deleteEngagement: (id: string) =>
    request<{ status: string }>(DB_SERVICE_URL, `/v1/engagements/${id}`, { method: "DELETE" }),

  addProfileToEngagement: (engagementId: string, profileId: string) =>
    request<Engagement>(DB_SERVICE_URL, `/v1/engagements/${engagementId}/profiles`, {
      method: "POST", body: JSON.stringify({ profile_id: profileId }),
    }),

  removeProfileFromEngagement: (engagementId: string, profileId: string) =>
    request<Engagement>(DB_SERVICE_URL, `/v1/engagements/${engagementId}/profiles/${profileId}`, {
      method: "DELETE",
    }),
};

// ── Runs / exports / connections (backend-api) ──────────────────────────────

export const backendApi = {
  listConnections: () =>
    request<{ items: Connection[]; total: number }>(BACKEND_API_URL, "/v1/connections"),

  listRuns: (limit = 20, filter: { engagement_id?: string } = {}) =>
    request<{ items: Run[]; total: number }>(BACKEND_API_URL, `/v1/runs${qs({ limit, ...filter })}`),

  getRun: (runId: string) =>
    request<Run>(BACKEND_API_URL, `/v1/runs/${runId}`),

  startRun: (
    classes: string[], scanDepth: ScanDepth, compartmentIds?: string[],
    provider?: CloudProvider, profileId?: string, regions?: string[], assetIds?: string[],
  ) =>
    request<Run>(BACKEND_API_URL, "/v1/runs", {
      method: "POST",
      body: JSON.stringify({
        classes, scan_depth: scanDepth, compartment_ids: compartmentIds ?? null,
        regions: regions ?? null, asset_ids: assetIds ?? null,
        ...(provider ? { provider } : {}),
        ...(profileId ? { profile_id: profileId } : {}),
      }),
    }),

  listSchedules: (status?: ScheduleStatus) =>
    request<{ items: Schedule[]; total: number }>(BACKEND_API_URL, `/v1/schedules${qs({ status })}`),

  createSchedule: (payload: {
    classes: string[]; mode: ScheduleMode;
    interval_value?: number; interval_unit?: IntervalUnit; run_at?: string;
    scan_depth: ScanDepth; provider?: CloudProvider; profile_id?: string;
    compartment_ids?: string[]; regions?: string[]; asset_ids?: string[];
  }) =>
    request<Schedule>(BACKEND_API_URL, "/v1/schedules", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  setScheduleStatus: (scheduleId: string, status: "active" | "disabled") =>
    request<Schedule>(BACKEND_API_URL, `/v1/schedules/${scheduleId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  deleteSchedule: (scheduleId: string) =>
    request<{ status: string }>(BACKEND_API_URL, `/v1/schedules/${scheduleId}`, { method: "DELETE" }),

  createExport: (format: ExportFormat, sections: string[], filter: Record<string, unknown> = {}) =>
    request<ExportMeta>(BACKEND_API_URL, "/v1/exports", {
      method: "POST",
      body: JSON.stringify({ format, sections, filter }),
    }),

  getExport: (exportId: string) =>
    request<ExportMeta>(BACKEND_API_URL, `/v1/exports/${exportId}`),

  // Auth-gated like every other /v1 route, so this fetches the body as a
  // blob and triggers the download client-side rather than pointing an
  // <a href> straight at the endpoint (which never attaches the Bearer
  // token and 401s - see dbApi.downloadRuleAssets's identical fix).
  downloadExportFile: async (exportId: string, filename: string) => {
    const token = getStoredToken();
    const res = await fetch(`${BACKEND_API_URL}/v1/exports/${exportId}/file`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error(`GET exports/file -> ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  verifyProfile: (profileId: string) =>
    request<VerifyResult>(BACKEND_API_URL, `/v1/profiles/${profileId}/verify`, { method: "POST" }),

  checkPermissions: (profileId: string) =>
    request<WhoAmIProfileResult>(BACKEND_API_URL, `/v1/profiles/${profileId}/whoami`, { method: "POST" }),
};
