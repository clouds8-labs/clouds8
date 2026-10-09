# Clouds8

**Multi-cloud security mapping tool**

Clouds8 scans OCI and GCP accounts for misconfigurations, builds an asset inventory, and derives real attack paths. Findings, inventory, and attack-path graphs are all browsable from the web frontend.

## Features

- 🗺️ **Asset Inventory** — cross-cloud asset list (VMs, buckets, databases, vaults, functions, clusters, IAM principals, ...) with risk scoring and exposure flags
- 🔗 **Attack Path Graphs** — real reachability paths derived from scanned data (VM/user/group/dynamic-group entry points → IAM policy grants → reachable resources), not a static diagram
- 📋 **Security Scanners** — CIS benchmark checks, IAM policy audits, and per-resource-type posture scanners across OCI and GCP
- 🔑 **Profiles & Engagements** — register multiple cloud accounts (OCI tenancies, GCP projects) as named Profiles, group them into Engagements for a scoped assessment
- 🔍 **Exposure Analysis** — identify publicly exposed resources and the policy grants that make them reachable from a compromised identity

## Architecture

Clouds8 is split into three services:

- **Database Service** (`services/db-service/`, port 8001) — the only process that opens `clouds8.db` directly. Exposes a `/v1/*` REST surface (polymorphic assets/findings, cursor pagination, attack-path derivation).
- **Backend API** (`services/backend-api/`, port 8002) — wraps cloud provider SDKs (OCI, GCP), runs scanners, triggers syncs/scans as tracked background jobs. Also handles admin login and Profile credential verification.
- **Frontend** (`frontend/`, port 3000 in Docker / 5173 in dev) — a React + Vite + Tailwind app talking to the `/v1` endpoints directly from the browser. `lynxctl` (`services/integration/cli/`) is a CLI alternative built on the same shared client SDK.

## Prerequisites

- Python 3.9+
- Node.js 18+ (for the frontend)
- Docker + Docker Compose (optional, for the containerized quick start)
- An OCI config file (`~/.oci/config`) and/or a GCP service-account JSON key, for live scanning. Without either, scans run against mock data.

## Quick Start (Docker Compose)

1. **Configure environment:**
   ```bash
   cp .env.example .env
   python3 -c "import secrets; print(secrets.token_hex(32))"   # run twice
   ```
   Paste the two generated values into `.env` as `AUTH_SECRET` and `INTERNAL_SERVICE_TOKEN`, and set `ADMIN_USERNAME`/`ADMIN_PASSWORD` to whatever you want to log in with.

2. **Start everything:**
   ```bash
   docker compose up --build
   ```
   Open `http://localhost:3000` and log in with the admin credentials from `.env`.

By default, `docker-compose.yml` mounts your `~/.oci` directory read-only into `backend-api` (at the identical host path, so any absolute `key_file` paths in `~/.oci/config` keep resolving) — if a valid config is found there, OCI scans run against real data; otherwise they fall back to mock data. Remove the `volumes:` entry under `backend-api` to force mock mode. GCP service-account key files aren't auto-mounted — if you want live GCP scanning under Docker, bind-mount the key file's path into the `backend-api` container yourself, matching the path you'll register as a GCP Profile's credential (see below).

To load demo data instead of connecting a real cloud account:
```bash
python services/integration/cli/lynxctl.py seed
```

## Quick Start (manual)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   cd frontend && npm install && cd ..
   ```

2. **Configure environment** — same as step 1 above (`cp .env.example .env`, generate `AUTH_SECRET`/`INTERNAL_SERVICE_TOKEN`, set admin credentials).

3. **Run each service** (separate terminals):
   ```bash
   cd services/db-service && uvicorn app:app --port 8001
   cd services/backend-api && uvicorn app:app --port 8002
   cd frontend && npm run dev
   ```

4. **Open the frontend:** `http://localhost:5173`, log in with the admin credentials from `.env`.

5. **Or use the CLI** instead of/alongside the web frontend:
   ```bash
   python services/integration/cli/lynxctl.py scan types
   python services/integration/cli/lynxctl.py scan run --type vm --watch
   python services/integration/cli/lynxctl.py assets list --type vm
   python services/integration/cli/lynxctl.py sync run --watch
   ```

## Connecting a cloud account

Scans run against a **Profile** — a named cloud credential registered from the Engagements page (or `POST /v1/profiles` on the DB service). Each Profile is scoped to one provider:

- **OCI:** `config_profile_name` is a section name in your local `~/.oci/config` (e.g. `DEFAULT`).
- **GCP:** `config_profile_name` is an absolute path to a local service-account JSON key file, readable by the `backend-api` process.

Credentials themselves are never stored by Clouds8 — only the config-file section name or key-file path. Group Profiles into an **Engagement** to scope a scan or an attack-path view to a specific assessment.

## Scanners

Each scanner (`playbooks/`) runs as a tracked background job via the Backend API and persists its findings to the database.

**OCI:**

| Scanner | What it checks |
|---|---|
| **CIS Benchmark** | Automated CIS OCI Foundations Benchmark checks across the tenancy |
| **IAM Policy Audit** | Overly permissive IAM policies, risky dynamic-group matching rules — also drives attack-path derivation |
| **Bucket Scanner** | Object Storage public-access exposure, encryption, versioning, lifecycle posture |
| **DB Scanner** | Autonomous Database security misconfigurations |
| **Vault Scanner** | Vaults, Keys, and Secrets inventory and lifecycle/metadata posture |
| **Secret Scanner** | Exposed secrets across scanned resources |
| **VM Scanner** | Compute instance public/private IPs, VNIC attachments, IMDS version, cloud-init metadata |
| **Volume Scanner** | Block Volume hygiene — customer-managed encryption, unattached volumes, missing backup policies |
| **Image Scanner** | Custom Compute Image posture — legacy BIOS firmware, in-transit encryption, management agent support, stale images |
| **OKE Scanner** | Kubernetes cluster configuration posture |
| **Functions Scanner** | Functions application configuration posture |

**GCP:**

| Scanner | What it checks |
|---|---|
| **GCP CIS Benchmark** | Automated CIS GCP Foundations Benchmark checks |
| **GCP IAM Scanner** | Service account and IAM policy posture |
| **GCP VM Scanner** | Compute instance exposure and configuration |
| **GCP Bucket Scanner** | GCS bucket public-access and configuration posture |
| **GCP DB Scanner** | Cloud SQL instance security misconfigurations |
| **GCP Secrets Scanner** | Secret Manager posture |
| **GCP GKE Scanner** | GKE cluster configuration posture |
| **GCP Functions Scanner** | Cloud Functions configuration posture |
| **GCP Firewall Scanner** | VPC firewall rule exposure |

## Attack Paths

The Attack Paths page picks an entry point — a VM, user, group, or dynamic group — and derives real reachable paths from already-scanned data: an internet-exposed VM with legacy IMDSv1 enabled is matched against every dynamic group's OCI matching-rule grammar, each matching dynamic group's IAM policy grants are resolved to a target compartment, and any scanned resource in that compartment (vault, database, bucket, ...) becomes a graph edge. This only surfaces what's actually been scanned — run the relevant scanners (at minimum `vm`, `iam`, and whatever resource-type scanners cover your likely targets) before expecting a path to render.

## Technology Stack

- **Backend:** FastAPI (DB service + Backend API), SQLite
- **Frontend:** React + Vite + Tailwind
- **Cloud SDKs:** OCI Python SDK, Google API Python Client
- **Configuration:** YAML playbooks, dotenv

## Roadmap

- ✅ OCI and GCP scanning, asset inventory, attack-path derivation
- 🔄 Broader CIS benchmark coverage, additional GCP resource types
- 🔜 Automated risk scoring and alerting
- 🔜 AWS and Azure support
