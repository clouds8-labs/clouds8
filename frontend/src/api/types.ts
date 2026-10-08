// Mirrors the /v1 response shapes from services/db-service/store.py (v1_*
// functions) and services/backend-api/routers/v1_runs.py. Kept in one file,
// the way shared/client/schemas.py is the single typed-model source for the
// Python clients.

export type Exposure = "internal" | "internet_facing";
// "info" is non-actionable context (e.g. a cloud-init line that correctly
// references an OCI Vault secret by OCID, rather than embedding it in
// plaintext) - not a vulnerability, so it never affects risk scoring, but
// it's still a real finding that should render distinctly from "no issue".
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingState = "open" | "accepted_risk" | "resolved";

export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface Asset {
  id: string;
  class: string;
  cloud: string;
  account_id: string | null;
  name: string;
  region: string | null;
  compartment: string | null;
  exposure: Exposure;
  risk: number;
  finding_counts: FindingCounts;
  scan_status: string | null;
  last_scanned_at: string | null;
  properties: Record<string, unknown>;
  profile_id: string | null;
  profile_name: string | null;
}

export interface ListEnvelope<T> {
  items: T[];
  next_cursor: string | null;
  total: number;
  expected_total: number;
  complete: boolean;
}

export interface Finding {
  id: number;
  rule_id: string;
  title: string;
  asset_id: string;
  asset_name: string | null;
  asset_class: string | null;
  account: string | null;
  status: string | null;
  severity: Severity | null;
  description: string | null;
  remediation: string | null;
  proof_of_concept: string | null;
  state: FindingState;
  scanned_at: string | null;
}

export interface AttackPathHop {
  asset_id: string;
  name: string;
  type: string;
  label: string;
}

export interface AttackPath {
  id: string;
  score: number;
  severity: "critical" | "high";
  title: string;
  hops: AttackPathHop[];
}

export interface FindingGroup {
  group_key: string;
  title: string;
  severity: Severity | null;
  affected_assets: number;
  finding_count: number;
  rule_id: string;
  description: string | null;
  remediation: string | null;
}

export interface RunCollector {
  scanner_type: string;
  job_id: string;
  status: string;
  progress_message: string | null;
}

export type RunState = "running" | "completed" | "partial" | "failed";

// "inventory" collects assets only; "rules" also runs security/compliance
// checks; "full" is identical to "rules" today - reserved for attack-graph
// analysis in a future release.
export type ScanDepth = "inventory" | "rules" | "full";

export interface Run {
  id: string;
  state: RunState;
  scan_depth: ScanDepth;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  classes: string[];
  asset_ids: string[] | null;
  progress: {
    percent: number;
    total: number;
    succeeded: number;
    failed: number;
    active: number;
  };
  collectors: RunCollector[];
}

export type ScheduleMode = "interval" | "once";
export type ScheduleStatus = "active" | "disabled" | "completed";
export type IntervalUnit = "hours" | "days";

export interface Schedule {
  id: string;
  classes: string[];
  provider: string;
  mode: ScheduleMode;
  interval_value: number | null;
  interval_unit: IntervalUnit | null;
  run_at: string | null;
  status: ScheduleStatus;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_id: string | null;
  created_at: string;
  scan_depth: ScanDepth;
  compartment_ids: string[] | null;
  regions: string[] | null;
  asset_ids: string[] | null;
}

export interface Connection {
  id: string;
  cloud: string;
  configured: boolean;
  health: "healthy" | "not_configured";
}

// A Profile is one persisted cloud account/tenancy, scoped to exactly one
// cloud provider, referencing a named section of the local SDK config file
// (e.g. the [SECTION] in ~/.oci/config for OCI) - no credentials stored.
// Replaces the old Connections stub (above) with a real CRUD entity.
export type CloudProvider = "oci" | "aws" | "azure" | "gcp";
export type VerifyStatus = "unverified" | "ok" | "failed";

export type WhoAmIRisk = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export interface WhoAmIRole {
  role: string;
  risk: WhoAmIRisk;
  scope?: string;
}

export interface WhoAmIError {
  stage: "identity" | "policy_lookup" | "probe";
  call: string;
  error_type: "PermissionDenied" | "NotFound" | "Timeout" | "Unknown";
  http_status: number | null;
  message: string;
}

export interface WhoAmIResult {
  identity: { type: string; id: string; name: string };
  method: "policy_lookup" | "permission_probe";
  risk: WhoAmIRisk;
  roles: WhoAmIRole[];
  permissions_confirmed: string[];
  permissions_denied: string[];
  errors: WhoAmIError[];
}

export interface WhoAmIProfileResult {
  profile_id: string;
  whoami: WhoAmIResult;
  whoami_checked_at: string;
}

export interface Profile {
  id: string;
  name: string;
  cloud_provider: CloudProvider;
  config_profile_name: string;
  is_active: boolean;
  verify_status: VerifyStatus;
  verify_message: string | null;
  verified_at: string | null;
  whoami_result: WhoAmIResult | null;
  whoami_checked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProfileSummary {
  id: string;
  name: string;
  cloud_provider: CloudProvider;
  is_active: boolean;
}

export interface VerifyResult {
  profile_id: string;
  status: "ok" | "failed";
  message: string;
  verified_at: string;
}

// An Engagement is a minimal named grouping of Profiles - no members,
// roles, or audit trail (this app has single-admin auth only).
export interface Engagement {
  id: string;
  name: string;
  asset_classes: string[] | null;
  regions: string[] | null;
  profiles: ProfileSummary[];
  created_at: string;
  updated_at: string;
}

export type ExportFormat = "csv" | "json" | "pdf" | "html";

export interface ExportMeta {
  id: string;
  state: "ready";
  format: ExportFormat;
  filename: string;
  content_type: string;
  created_at: number;
  bytes: number;
  counts: { assets: number; findings: number };
}

// The known asset classes. OCI: 1:1 with the 11 OCI scanners
// (services/backend-api/routers/scans.py's SCANNERS dict). GCP: the 5
// gcp_* scanners from the Phase 1 GCP vertical slice - same dict, GCP's
// own asset taxonomy (compute_instance/gcs_bucket/etc.) rather than OCI's.
export const ASSET_CLASSES = [
  { id: "bucket", label: "Storage Buckets", scanner: "bucket" },
  { id: "vm", label: "Virtual Machines", scanner: "vm" },
  { id: "adb", label: "Autonomous Databases", scanner: "db" },
  { id: "vault", label: "Vaults & Secrets", scanner: "vault" },
  { id: "volume", label: "Block Volumes", scanner: "volume" },
  { id: "image", label: "Custom Images", scanner: "image" },
  { id: "oke_cluster", label: "OKE Clusters", scanner: "oke" },
  { id: "function_app", label: "Functions Apps", scanner: "functions" },
  { id: "gcp_vm", label: "GCP Compute Instances", scanner: "gcp_vm" },
  { id: "gcs_bucket", label: "GCS Buckets", scanner: "gcp_bucket" },
  { id: "gcp_service_account", label: "GCP Service Accounts", scanner: "gcp_iam" },
  { id: "cloudsql_instance", label: "Cloud SQL Instances", scanner: "gcp_db" },
  { id: "gcp_secret", label: "GCP Secrets", scanner: "gcp_secrets" },
  { id: "gke_cluster", label: "GKE Clusters", scanner: "gcp_gke" },
  { id: "cloud_function", label: "Cloud Functions", scanner: "gcp_functions" },
  { id: "gcp_firewall_rule", label: "GCP Firewall Rules", scanner: "gcp_firewall" },
] as const;

export const SCANNER_CLASSES = [
  { scanner: "bucket", label: "Storage Buckets", icon: "database" },
  { scanner: "vm", label: "Virtual Machines", icon: "server" },
  { scanner: "vault", label: "Vaults & Secrets", icon: "key" },
  { scanner: "cis", label: "CIS Benchmark", icon: "shield" },
  { scanner: "iam", label: "IAM", icon: "users" },
  { scanner: "db", label: "Autonomous DB", icon: "database" },
  { scanner: "volume", label: "Block Volumes", icon: "hdd" },
  { scanner: "image", label: "Custom Images", icon: "disc" },
  { scanner: "secret", label: "Secret Scanner", icon: "user-secret" },
  { scanner: "oke", label: "OKE Clusters", icon: "box" },
  { scanner: "functions", label: "Functions", icon: "zap" },
  { scanner: "gcp_vm", label: "GCP Compute", icon: "server" },
  { scanner: "gcp_bucket", label: "GCS Buckets", icon: "database" },
  { scanner: "gcp_iam", label: "GCP IAM", icon: "users" },
  { scanner: "gcp_db", label: "Cloud SQL", icon: "database" },
  { scanner: "gcp_cis", label: "GCP CIS Benchmark", icon: "shield" },
  { scanner: "gcp_secrets", label: "GCP Secrets", icon: "key" },
  { scanner: "gcp_gke", label: "GKE Clusters", icon: "box" },
  { scanner: "gcp_functions", label: "GCP Functions", icon: "zap" },
  { scanner: "gcp_firewall", label: "GCP Firewall", icon: "shield" },
] as const;

// Mirrors services/backend-api/findings.py's _SCANNER_TO_ASSET_TYPES (inverted:
// asset_type -> the scanner(s) that can flip its scan_status to "scanned").
// Keep this in sync by hand if findings.py changes.
export const ASSET_TYPE_SCANNERS: Record<string, string[]> = {
  vm: ["vm"],
  bucket: ["bucket", "secret"],
  adb: ["db"],
  oke_cluster: ["oke"],
  function_app: ["functions"],
  policy: ["iam"],
  vault: ["vault"],
  volume: ["volume"],
  image: ["image"],
  user: ["iam"],
  group: ["iam"],
  dynamic_group: ["iam"],
  gcp_vm: ["gcp_vm"],
  gcs_bucket: ["gcp_bucket"],
  gcp_service_account: ["gcp_iam"],
  cloudsql_instance: ["gcp_db"],
  gcp_secret: ["gcp_secrets"],
  gke_cluster: ["gcp_gke"],
  cloud_function: ["gcp_functions"],
  gcp_firewall_rule: ["gcp_firewall"],
};

// Asset classes with no scanner ever marking them "scanned" - the Inventory
// "In progress" / "Scanned" filters are structurally meaningless for these.
// Empty today: vault/volume/image used to be here (no asset rows existed
// for them at all) until findings.py started upserting their scan results
// into `assets`, same as every other tracked class.
export const SCAN_STATUS_UNTRACKED_CLASSES: string[] = [];

// scanner -> asset_type(s), the inverse of ASSET_TYPE_SCANNERS. Built once
// instead of by hand so it can't drift from the table above. A scanner can
// map to more than one asset type (e.g. "iam" -> policy/user/group/
// dynamic_group) - keep every one of them, not just the last writer, or a
// multi-type scanner silently collapses to whichever type happened to be
// inserted last (iam -> "dynamic_group" only, picked by object-key
// insertion order rather than anything meaningful).
const SCANNER_ASSET_TYPES: Record<string, string[]> = {};
for (const [assetType, scanners] of Object.entries(ASSET_TYPE_SCANNERS)) {
  for (const scanner of scanners) {
    (SCANNER_ASSET_TYPES[scanner] ??= []).push(assetType);
  }
}

// Every distinct asset type a set of scanner classes maps to - e.g. a
// ["bucket", "db"] run -> ["bucket", "adb"], and "iam" alone -> all 4 of
// user/group/dynamic_group/policy. Empty for scanners with no tracked
// asset type at all (cis/vault/volume/image - see ASSET_TYPE_SCANNERS/
// SCAN_STATUS_UNTRACKED_CLASSES above). Shared by inventoryLinkForClasses
// (below) and assetClassFilterForClasses (an export-filter equivalent,
// frontend/src/pages/Scans.tsx's "Download report"). The backend's
// `asset_class` filter (store.py's v1_list_assets) accepts a
// comma-separated list, so joining these is enough to scope to all of them
// at once - no "pick the one unambiguous class or give up" fallback needed.
function allAssetTypesForClasses(classes: string[]): string[] {
  return [...new Set(classes.flatMap((c) => SCANNER_ASSET_TYPES[c] ?? []))];
}

// Where a run/schedule's "View in Inventory" link should point: scoped to
// every asset class the run touched (e.g. a ["bucket","vm"] run ->
// ?assetClass=bucket,vm), or the unscoped list when none of its scanners
// track a distinct asset type at all.
//
// `inProgress`: when the scan this links from is still running, point at
// Inventory's "In progress" status bucket instead of (or in addition to)
// an asset-class filter - Inventory derives the exact set of in-flight
// asset classes itself from the live Run it polls
// (computeInProgressClasses in Inventory.tsx), so this intentionally does
// NOT also pass assetClass.
export function inventoryLinkForClasses(classes: string[], inProgress = false): string {
  if (inProgress) return "/inventory?scanStatus=in_progress";
  const assetTypes = allAssetTypesForClasses(classes);
  return assetTypes.length > 0 ? `/inventory?assetClass=${encodeURIComponent(assetTypes.join(","))}` : "/inventory";
}

// The export `filter.asset_class` value for a run's classes: every asset
// type it touched, comma-joined, or undefined (an unfiltered, whole-
// inventory report) when none are tracked - applied to the export
// pipeline (POST /v1/exports) instead of a page link.
export function assetClassFilterForClasses(classes: string[]): string | undefined {
  const assetTypes = allAssetTypesForClasses(classes);
  return assetTypes.length > 0 ? assetTypes.join(",") : undefined;
}
