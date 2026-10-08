import { useEffect, useState } from "react";
import { backendApi, dbApi } from "../api/client";
import { ASSET_CLASSES } from "../api/types";
import type { CloudProvider, Engagement, Profile, WhoAmIRisk } from "../api/types";
import { Button } from "../components/Button";
import { PageHeader } from "../components/PageHeader";
import { SkeletonLines } from "../components/Skeleton";

const PROVIDER_LABEL: Record<CloudProvider, string> = {
  oci: "OCI", aws: "AWS", azure: "Azure", gcp: "GCP",
};

const PROVIDER_IMPLEMENTED: Record<CloudProvider, boolean> = {
  oci: true, aws: false, azure: false, gcp: true,
};

// How each provider's `config_profile_name` string is interpreted - an OCI
// config-file section name vs. a GCP service-account key file path.
const CONFIG_FIELD_LABEL: Partial<Record<CloudProvider, string>> = {
  gcp: "Service account JSON key file (path)",
};
const CONFIG_FIELD_PLACEHOLDER: Partial<Record<CloudProvider, string>> = {
  gcp: "/path/to/service-account.json",
};
const CONFIG_FIELD_HELP: Partial<Record<CloudProvider, string>> = {
  gcp: "Absolute path to a local GCP service-account key JSON file, readable by the Clouds8 " +
       "backend process. The key file itself is never uploaded to or stored by Clouds8 - only this path is saved.",
};

// Suppressed pending UI fixes (truncated permission list, per-item risk
// dots) - the button/result block below are untouched otherwise; flip
// back to true to re-enable (the backend route must also be re-enabled,
// see services/backend-api/routers/v1_profiles.py's WHOAMI_ENABLED).
const WHOAMI_ENABLED = false;

const VERIFY_STYLE: Record<Profile["verify_status"], { bg: string; fg: string; label: string }> = {
  unverified: { bg: "bg-lm-line", fg: "text-lm-dim", label: "Unverified" },
  ok: { bg: "bg-lm-clean/15", fg: "text-lm-clean", label: "Verified" },
  failed: { bg: "bg-lm-critical/15", fg: "text-lm-critical", label: "Verify failed" },
};

const WHOAMI_RISK_STYLE: Record<WhoAmIRisk, { bg: string; fg: string }> = {
  NONE: { bg: "bg-lm-clean/15", fg: "text-lm-clean" },
  LOW: { bg: "bg-lm-clean/15", fg: "text-lm-clean" },
  MEDIUM: { bg: "bg-lm-medium/15", fg: "text-lm-medium" },
  HIGH: { bg: "bg-lm-critical/15", fg: "text-lm-critical" },
  CRITICAL: { bg: "bg-lm-critical/15", fg: "text-lm-critical" },
  UNKNOWN: { bg: "bg-lm-line", fg: "text-lm-dim" },
};

function ProfileCard({ profile, onChanged }: { profile: Profile; onChanged: () => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(profile.name);
  const [editConfigProfileName, setEditConfigProfileName] = useState(profile.config_profile_name);
  const [verifying, setVerifying] = useState(false);
  const verify = VERIFY_STYLE[profile.verify_status];

  const saveEdit = async () => {
    await dbApi.updateProfile(profile.id, { name: editName, config_profile_name: editConfigProfileName });
    setEditing(false);
    await onChanged();
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      await backendApi.verifyProfile(profile.id);
      await onChanged();
    } finally {
      setVerifying(false);
    }
  };

  const [checkingPermissions, setCheckingPermissions] = useState(false);

  const handleCheckPermissions = async () => {
    setCheckingPermissions(true);
    try {
      await backendApi.checkPermissions(profile.id);
      await onChanged();
    } finally {
      setCheckingPermissions(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm(
      "Delete this profile? Assets already tagged with it keep the label, and it will be removed from any engagements."
    )) return;
    await dbApi.deleteProfile(profile.id);
    await onChanged();
  };

  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel-2 p-4">
      <div className="flex items-center justify-between mb-2 gap-2">
        <h3 className="font-display text-sm font-semibold truncate">
          {editing ? (
            <input
              type="text"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              className="w-full rounded-md border border-lm-line bg-lm-panel px-2 py-1 text-sm"
            />
          ) : (
            profile.name
          )}
        </h3>
        {profile.is_active && (
          <span className="shrink-0 inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-accent/15 text-lm-accent">
            Active
          </span>
        )}
      </div>
      <div className="flex items-center gap-2 mb-3">
        <span className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold bg-lm-line text-lm-dim uppercase">
          {profile.cloud_provider}
        </span>
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold ${verify.bg} ${verify.fg}`}>
          {verify.label}
        </span>
      </div>
      <div className="text-sm text-lm-dim mb-1">
        {profile.cloud_provider === "gcp" ? "Key file" : "Section"}:{" "}
        {editing ? (
          <input
            type="text"
            value={editConfigProfileName}
            onChange={(e) => setEditConfigProfileName(e.target.value)}
            className="rounded-md border border-lm-line bg-lm-panel px-2 py-1 text-xs"
          />
        ) : (
          <span className="font-mono text-lm-text">{profile.config_profile_name}</span>
        )}
      </div>
      {profile.verify_message && <div className="text-xs text-lm-dim mt-2">{profile.verify_message}</div>}
      {WHOAMI_ENABLED && profile.whoami_result && (
        <div className="mt-3 rounded-md border border-lm-line bg-lm-panel p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-lm-dim">
              {profile.whoami_result.identity.type === "service_account" ? "Service account" : "User"}:{" "}
              <span className="font-mono text-lm-text">{profile.whoami_result.identity.name}</span>
            </span>
            <span className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold ${WHOAMI_RISK_STYLE[profile.whoami_result.risk].bg} ${WHOAMI_RISK_STYLE[profile.whoami_result.risk].fg}`}>
              {profile.whoami_result.risk} risk
            </span>
          </div>
          {profile.whoami_result.method === "permission_probe" && (
            <div className="text-[11px] text-lm-dim mb-1">
              Direct policy lookup was denied — showing probed permissions instead.
            </div>
          )}
          <ul className="text-xs text-lm-text space-y-0.5">
            {(profile.whoami_result.roles.length > 0
              ? profile.whoami_result.roles
              // Probe path has no per-permission risk rating (unlike GCP's
              // PROBE_RISK map) - mirror the backend's own identity.*-is-
              // more-sensitive heuristic so the dot isn't flatly LOW next
              // to a HIGH/CRITICAL overall badge derived from this same list.
              : profile.whoami_result.permissions_confirmed.map((p) => ({
                  role: p, risk: (p.startsWith("identity.") ? "MEDIUM" : "LOW") as const,
                }))
            ).map((item, i) => (
              <li key={i} className="truncate">
                <span className={WHOAMI_RISK_STYLE[item.risk].fg}>●</span> {item.role}
              </li>
            ))}
          </ul>
          {profile.whoami_result.errors.length > 0 && (
            <div className="text-[11px] text-lm-dim mt-1">
              {profile.whoami_result.errors.length} check(s) couldn't run.
            </div>
          )}
        </div>
      )}
      <div className="flex flex-wrap gap-2 mt-4">
        {editing ? (
          <>
            <Button variant="primary" onClick={saveEdit}>Save</Button>
            <Button variant="secondary" onClick={() => setEditing(false)}>Cancel</Button>
          </>
        ) : (
          <>
            <Button variant="secondary" disabled={verifying} onClick={handleVerify}>
              {verifying ? "Verifying…" : "Verify"}
            </Button>
            {WHOAMI_ENABLED && (
              <Button variant="secondary" disabled={checkingPermissions} onClick={handleCheckPermissions}>
                {checkingPermissions ? "Checking…" : "Check Permissions"}
              </Button>
            )}
            <Button variant="secondary" disabled={profile.is_active} onClick={() => dbApi.activateProfile(profile.id).then(onChanged)}>
              Set Active
            </Button>
            <Button variant="secondary" onClick={() => setEditing(true)}>Edit</Button>
            <Button variant="destructive" onClick={handleDelete}>Delete</Button>
          </>
        )}
      </div>
    </div>
  );
}

function NewProfileForm({ onCreated, onCancel }: { onCreated: (id: string) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [cloudProvider, setCloudProvider] = useState<CloudProvider>("oci");
  const [configProfileName, setConfigProfileName] = useState("DEFAULT");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await dbApi.createProfile({
        name, cloud_provider: cloudProvider,
        config_profile_name: configProfileName.trim() || (cloudProvider === "oci" ? "DEFAULT" : ""),
      });
      await onCreated(created.id);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const match = message.match(/"detail":"([^"]+)"/);
      setError(match ? match[1] : message);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel-2 p-4">
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Name</div>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Prod Tenancy"
            className="w-full rounded-md border border-lm-line bg-lm-panel px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          />
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Cloud provider</div>
          <select
            value={cloudProvider}
            onChange={(e) => {
              const next = e.target.value as CloudProvider;
              setCloudProvider(next);
              // "DEFAULT" is a sensible OCI section name but not a file path -
              // clear it when switching to a provider that expects a path.
              setConfigProfileName(CONFIG_FIELD_PLACEHOLDER[next] ? "" : "DEFAULT");
            }}
            className="w-full rounded-md border border-lm-line bg-lm-panel px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          >
            {(Object.keys(PROVIDER_LABEL) as CloudProvider[]).map((p) => (
              <option key={p} value={p}>
                {PROVIDER_LABEL[p]}
                {!PROVIDER_IMPLEMENTED[p] ? " (not yet implemented — falls back to mock data)" : ""}
              </option>
            ))}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">
            {CONFIG_FIELD_LABEL[cloudProvider] ?? "Config profile / section name"}
          </div>
          <input
            type="text"
            value={configProfileName}
            onChange={(e) => setConfigProfileName(e.target.value)}
            placeholder={CONFIG_FIELD_PLACEHOLDER[cloudProvider] ?? "DEFAULT"}
            className="w-full rounded-md border border-lm-line bg-lm-panel px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
          />
        </div>
      </div>
      <p className="text-xs text-lm-dim mb-4">
        {CONFIG_FIELD_HELP[cloudProvider] ?? (
          <>
            Must match a section header in the local SDK config file (e.g. the <code>[SECTION]</code> in{" "}
            <code>~/.oci/config</code> for OCI). No credentials are entered here or stored in Clouds8.
          </>
        )}
      </p>
      {error && <p className="text-xs text-lm-critical mb-3">{error}</p>}
      <div className="flex gap-2">
        <Button
          variant="primary"
          disabled={!name.trim() || (cloudProvider !== "oci" && !configProfileName.trim()) || creating}
          onClick={handleCreate}
        >
          {creating ? "Creating…" : "Create profile"}
        </Button>
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

function AttachProfileForm({
  profiles, onAttach, onCancel,
}: {
  profiles: Profile[];
  onAttach: (profileId: string) => Promise<void>;
  onCancel: () => void;
}) {
  const [profileId, setProfileId] = useState(profiles[0]?.id ?? "");
  const [attaching, setAttaching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAttach = async () => {
    if (!profileId) return;
    setAttaching(true);
    setError(null);
    try {
      await onAttach(profileId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setAttaching(false);
    }
  };

  if (profiles.length === 0) {
    return (
      <div className="rounded-lg border border-lm-line bg-lm-panel-2 p-4">
        <p className="text-sm text-lm-dim mb-4">
          Every existing profile is already attached to this engagement. Create a new one instead.
        </p>
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel-2 p-4">
      <div className="mb-4 max-w-md">
        <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Existing profile</div>
        <select
          value={profileId}
          onChange={(e) => setProfileId(e.target.value)}
          className="w-full rounded-md border border-lm-line bg-lm-panel px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
        >
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({PROVIDER_LABEL[p.cloud_provider]} · {p.config_profile_name})
            </option>
          ))}
        </select>
      </div>
      {error && <p className="text-xs text-lm-critical mb-3">{error}</p>}
      <div className="flex gap-2">
        <Button variant="primary" disabled={!profileId || attaching} onClick={handleAttach}>
          {attaching ? "Attaching…" : "Attach profile"}
        </Button>
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

export function Engagements() {
  const [engagements, setEngagements] = useState<Engagement[] | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [selectedProfileIds, setSelectedProfileIds] = useState<string[]>([]);
  const [selectedClasses, setSelectedClasses] = useState<string[]>([]);
  const [regionsText, setRegionsText] = useState("");
  const [saving, setSaving] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showNewProfileFor, setShowNewProfileFor] = useState<string | null>(null);
  const [showAttachFor, setShowAttachFor] = useState<string | null>(null);

  const refresh = async () => {
    const [eRes, pRes] = await Promise.all([dbApi.listEngagements(), dbApi.listProfiles()]);
    setEngagements(eRes.items);
    setProfiles(pRes.items);
  };

  useEffect(() => {
    refresh();
  }, []);

  const resetForm = () => {
    setEditingId(null);
    setName("");
    setSelectedProfileIds([]);
    setSelectedClasses([]);
    setRegionsText("");
  };

  const startCreate = () => {
    resetForm();
    setShowForm(true);
  };

  const startEdit = (e: Engagement) => {
    setEditingId(e.id);
    setName(e.name);
    setSelectedProfileIds(e.profiles.map((p) => p.id));
    setSelectedClasses(e.asset_classes ?? []);
    setRegionsText((e.regions ?? []).join(", "));
    setShowForm(true);
  };

  const toggleProfile = (id: string) => {
    setSelectedProfileIds((prev) => (prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]));
  };

  const toggleClass = (id: string) => {
    setSelectedClasses((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));
  };

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      const regions = regionsText.split(",").map((r) => r.trim()).filter(Boolean);
      const assetClasses = selectedClasses.length > 0 ? selectedClasses : undefined;
      const regionsPayload = regions.length > 0 ? regions : undefined;

      if (editingId) {
        const before = engagements?.find((e) => e.id === editingId);
        const beforeIds = new Set(before?.profiles.map((p) => p.id) ?? []);
        const afterIds = new Set(selectedProfileIds);
        await dbApi.updateEngagement(editingId, { name, asset_classes: assetClasses, regions: regionsPayload });
        for (const id of afterIds) {
          if (!beforeIds.has(id)) await dbApi.addProfileToEngagement(editingId, id);
        }
        for (const id of beforeIds) {
          if (!afterIds.has(id)) await dbApi.removeProfileFromEngagement(editingId, id);
        }
      } else {
        await dbApi.createEngagement({
          name, profile_ids: selectedProfileIds, asset_classes: assetClasses, regions: regionsPayload,
        });
      }
      setShowForm(false);
      resetForm();
      await refresh();
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this engagement? Its profiles are not affected.")) return;
    await dbApi.deleteEngagement(id);
    await refresh();
  };

  const handleProfileCreated = async (engagementId: string, newProfileId: string) => {
    await dbApi.addProfileToEngagement(engagementId, newProfileId);
    setShowNewProfileFor(null);
    await refresh();
  };

  const handleAttachProfile = async (engagementId: string, profileId: string) => {
    await dbApi.addProfileToEngagement(engagementId, profileId);
    setShowAttachFor(null);
    await refresh();
  };

  return (
    <div>
      <PageHeader
        title="Engagements"
        subtitle="Named groupings of Profiles - pool accounts together for a review or assessment"
        actions={
          <Button variant="primary" onClick={startCreate}>
            + New Engagement
          </Button>
        }
      />

      {showForm && (
        <div className="rounded-lg border border-lm-line bg-lm-panel p-5 mb-6">
          <div className="mb-4">
            <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Name</div>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Q4 External Pentest"
              className="w-full max-w-md rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
            />
          </div>

          <div className="mb-4">
            <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Profiles</div>
            {profiles.length === 0 ? (
              <div className="text-sm text-lm-dim">No profiles yet - create one from an engagement below.</div>
            ) : (
              <div className="grid grid-cols-3 gap-2">
                {profiles.map((p) => (
                  <label
                    key={p.id}
                    className={`flex items-center gap-3 rounded-md border px-4 py-3 cursor-pointer ${
                      selectedProfileIds.includes(p.id)
                        ? "border-lm-accent bg-lm-accent/10"
                        : "border-lm-line hover:border-lm-dim"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedProfileIds.includes(p.id)}
                      onChange={() => toggleProfile(p.id)}
                      className="accent-lm-accent"
                    />
                    <span className="text-sm font-medium">{p.name}</span>
                    <span className="text-[10px] uppercase text-lm-dim ml-auto">{p.cloud_provider}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="mb-4">
            <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Asset classes (optional scope)</div>
            <div className="grid grid-cols-4 gap-2">
              {ASSET_CLASSES.map((c) => (
                <label
                  key={c.id}
                  className={`flex items-center gap-2 rounded-md border px-3 py-2 cursor-pointer ${
                    selectedClasses.includes(c.id) ? "border-lm-accent bg-lm-accent/10" : "border-lm-line hover:border-lm-dim"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedClasses.includes(c.id)}
                    onChange={() => toggleClass(c.id)}
                    className="accent-lm-accent"
                  />
                  <span className="text-xs font-medium">{c.label}</span>
                </label>
              ))}
            </div>
            <div className="text-xs text-lm-dim mt-1">Leave empty for all classes.</div>
          </div>

          <div className="mb-4">
            <div className="text-[11px] uppercase tracking-widest text-lm-dim mb-2">Regions (optional scope)</div>
            <input
              type="text"
              value={regionsText}
              onChange={(e) => setRegionsText(e.target.value)}
              placeholder="us-phoenix-1, us-ashburn-1"
              className="w-full max-w-md rounded-md border border-lm-line bg-lm-panel-2 px-3 py-2 text-sm focus:outline-none focus:border-lm-accent"
            />
            <div className="text-xs text-lm-dim mt-1">Comma-separated. Leave empty for all regions.</div>
          </div>

          <div className="flex gap-2">
            <Button variant="primary" disabled={!name.trim() || saving} onClick={handleSave}>
              {saving ? "Saving…" : editingId ? "Save changes" : "Create engagement"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setShowForm(false);
                resetForm();
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {engagements === null ? (
        <SkeletonLines widths={["60%", "60%", "60%"]} />
      ) : engagements.length === 0 ? (
        <div className="text-sm text-lm-dim">No engagements yet.</div>
      ) : (
        <div className="flex flex-col gap-3">
          {engagements.map((e) => {
            const expanded = expandedId === e.id;
            const engagementProfiles = profiles.filter((p) => e.profiles.some((ep) => ep.id === p.id));
            return (
              <div key={e.id} className="rounded-lg border border-lm-line bg-lm-panel overflow-hidden">
                <div
                  className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-lm-panel-2"
                  onClick={() => setExpandedId(expanded ? null : e.id)}
                >
                  <span className="text-lm-dim w-3 text-center">{expanded ? "▾" : "▸"}</span>
                  <span className="font-medium flex-1">{e.name}</span>
                  <span className="text-sm text-lm-dim">
                    {e.profiles.length} profile{e.profiles.length === 1 ? "" : "s"}
                  </span>
                  <span className="text-sm text-lm-dim">
                    {e.asset_classes ? `${e.asset_classes.length} class${e.asset_classes.length === 1 ? "" : "es"}` : "All classes"}
                    {" · "}
                    {e.regions ? `${e.regions.length} region${e.regions.length === 1 ? "" : "s"}` : "All regions"}
                  </span>
                  <div className="flex gap-2" onClick={(ev) => ev.stopPropagation()}>
                    <Button variant="secondary" onClick={() => startEdit(e)}>Edit</Button>
                    <Button variant="destructive" onClick={() => handleDelete(e.id)}>Delete</Button>
                  </div>
                </div>

                {expanded && (
                  <div className="border-t border-lm-line p-4 bg-lm-bg/40">
                    <div className="flex items-center justify-between mb-3">
                      <div className="text-[11px] uppercase tracking-widest text-lm-dim">Profiles in this engagement</div>
                      <div className="flex gap-2">
                        <Button variant="secondary" onClick={() => setShowAttachFor(e.id)}>Attach existing</Button>
                        <Button variant="primary" onClick={() => setShowNewProfileFor(e.id)}>+ New Profile</Button>
                      </div>
                    </div>

                    {showAttachFor === e.id && (
                      <div className="mb-3">
                        <AttachProfileForm
                          profiles={profiles.filter((p) => !engagementProfiles.some((ep) => ep.id === p.id))}
                          onAttach={(profileId) => handleAttachProfile(e.id, profileId)}
                          onCancel={() => setShowAttachFor(null)}
                        />
                      </div>
                    )}

                    {showNewProfileFor === e.id && (
                      <div className="mb-3">
                        <NewProfileForm
                          onCreated={(id) => handleProfileCreated(e.id, id)}
                          onCancel={() => setShowNewProfileFor(null)}
                        />
                      </div>
                    )}

                    {engagementProfiles.length === 0 ? (
                      <div className="text-sm text-lm-dim">No profiles attached yet.</div>
                    ) : (
                      <div className="grid grid-cols-3 gap-3">
                        {engagementProfiles.map((p) => (
                          <ProfileCard key={p.id} profile={p} onChanged={refresh} />
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
