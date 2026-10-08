# Clouds8

**Cloud Security Mapping Tool**

Clouds8 is a modular security tool designed to help security teams understand and explore attack surface maps for Oracle Cloud Infrastructure (OCI).

## Features

- 📊 **Dashboard Overview** - High-level asset inventory with bar charts and risk scoring
- 🎯 **Attack Surface Visualization** - Interactive sunburst charts mapping resource relationships and blast radius
- 📋 **Security Playbooks** - Automated scanners covering CIS OCI Benchmarks, IAM policy audits, Object Storage buckets, Databases, Vaults, Secrets, VM instances, Block Volumes, and Custom Images
- 🔍 **Exposure Analysis** - Identify publicly exposed resources and potential attack paths


## Architecture

Clouds8 is split into three services:

- **Database Service** (`services/db-service/`, port 8001) — the only process that opens `clouds8.db` directly. Exposes a `/v1/*` REST surface (polymorphic assets/findings, cursor pagination, attack-path derivation) for the frontend.
- **Backend API** (`services/backend-api/`, port 8002) — wraps cloud provider SDKs (OCI, GCP), runs scanners, triggers syncs/scans/active-probes as tracked background jobs. Also exposes `/v1/runs`, `/v1/exports`, `/v1/connections` for the frontend.
- **Integration Service** — the React frontend (`frontend/`, port 3000 in Docker / 5173 in dev — see below) and the `lynxctl` CLI (`services/integration/cli/`), both built on the shared client SDK pattern so they never diverge in how they talk to the other two services.

### Frontend

`frontend/` is a React + Vite + Tailwind app talking to the `/v1` endpoints above directly from the browser. To run it in dev mode:

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, expects db-service on :8001 and backend-api on :8002
```

### OCI Credentials
The Backend API automatically fetches OCI credentials from the standard SDK configuration file (`~/.oci/config` on Linux/Mac, `%UserProfile%\.oci\config` on Windows, `[DEFAULT]` profile). If no configuration is found, it falls back to **Mock Data Mode** for demonstration.

## Playbooks (Scanners)

Each playbook (`playbooks/`) is triggered as a tracked background job via the Backend API and its findings persist to the database:

| Scanner | What it checks |
|---|---|
| **CIS Benchmark** | Automated CIS OCI Foundations Benchmark checks across the tenancy |
| **IAM Policy Audit** | Overly permissive IAM policies — broad `read/manage all-resources` and secret-access grants |
| **Bucket Scanner** | Object Storage public-access exposure, encryption, versioning, and lifecycle posture |
| **DB Scanner** | Autonomous Database security misconfigurations |
| **Vault Scanner** | Vaults, Keys, and Secrets inventory and lifecycle/metadata posture |
| **Secret Scanner** | Exposed secrets across scanned resources |
| **VM Scanner** | Compute instance public/private IPs, VNIC attachments, and cloud-init metadata |
| **Volume Scanner** | Block Volume hygiene — customer-managed encryption, unattached volumes, missing backup policies |
| **Image Scanner** | Custom Compute Image posture — legacy BIOS firmware, in-transit encryption, management agent support, stale images |

## Quick Start (Docker Compose)

```bash
docker compose up --build
```

This builds and starts all three services. Open `http://localhost:3000` for the frontend. By default `docker-compose.yml` mounts your `~/.oci` directory read-only into `backend-api` (at the identical host path, so any absolute `key_file` paths in `~/.oci/config` keep resolving) — if a valid config is found there, scans run against real OCI data; otherwise it falls back to Mock Data Mode. Remove the `volumes:` entry under `backend-api` to force mock mode.

To load demo data:
```bash
python services/integration/cli/lynxctl.py seed
```

## Quick Start (manual)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment** — copy `.env.example` to `.env`. It configures the URLs the frontend/CLI use to reach the other two services (`DB_SERVICE_URL`, `BACKEND_API_URL`), which default to `localhost:8001`/`localhost:8002`.

3. **Run each service** (separate terminals):
   ```bash
   cd services/db-service && uvicorn app:app --port 8001
   cd services/backend-api && uvicorn app:app --port 8002
   cd frontend && npm run dev
   ```

4. **Open in browser:** Navigate to `http://localhost:5173`

5. **Or use the CLI** instead of/alongside the web UI:
   ```bash
   python services/integration/cli/lynxctl.py assets list --type vm
   python services/integration/cli/lynxctl.py sync run --watch
   ```

## Technology Stack

- **Framework:** FastAPI (DB service + Backend API), React + Vite + Tailwind (frontend)
- **Cloud SDK:** OCI Python SDK, Google API Python Client
- **Configuration:** YAML playbooks, dotenv

## Roadmap

- **Phase 1:** ✅ Multi-page app architecture
- **Phase 2:** 🔄 Playbook scanning with CIS benchmarks
- **Phase 3:** 🔜 Automated risk scoring and alerting
- **Phase 4:** 🔜 Multi-cloud support (AWS, Azure, GCP)

