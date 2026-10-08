"""
Clouds8 Backend API - cloud provider wrapper service

Owns "how do I talk to a cloud provider": collectors/, playbooks/ (scanners)
and probes/ (active-probing tools). Persists everything via the DB service
over HTTP (through db/database.py's facade) - this process never opens
clouds8.db directly.

NOTE on collectors/playbooks/reports still living at the repo root rather
than physically under this directory: this service imports them from that
shared top-level location via sys.path rather than owning a private copy.
Nothing outside this service imports collectors/ or playbooks/ directly
anymore (see tests/test_clouds8.py for the one legitimate exception - it
tests that code's own logic directly, which is expected regardless of
where the files physically live) - the physical move is a pure
reorganization with no remaining functional blocker, deferred as a
non-urgent follow-up.

Run with:
    cd services/backend-api && uvicorn app:app --port 8002 --reload
"""
import sys
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))  # repo root: collectors/, playbooks/, db/, sync.py

from dotenv import load_dotenv

# Must run before the `from routers import ...` line below: that import
# transitively imports db/database.py, which reads INTERNAL_SERVICE_TOKEN
# at module-import time to build its shared httpx client. Loading .env
# after that import would silently bake in an empty token.
load_dotenv(Path(__file__).parent.parent.parent / ".env")

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import auth
from routers import auth as auth_router, objects, probes, scans, system, v1_profiles, v1_runs, v1_schedules
from db.database import init_database
import jobs
import scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    jobs.reconcile_orphaned_jobs()
    scheduler.start()
    yield


app = FastAPI(
    title="Clouds8 Backend API",
    description="Cloud provider wrapper — collectors, scanners, active-probing",
    version="1.0.0",
    lifespan=lifespan,
)

# Registered before CORSMiddleware below so CORS ends up outermost in the
# final stack: Starlette's add_middleware() inserts at the front of the
# middleware list, so the middleware added LAST wraps everything added
# before it. CORS must be outermost so it can both answer preflight
# OPTIONS requests and attach Access-Control-Allow-Origin to every
# response this middleware returns - including its own 401s - not just
# responses that reach the router.
@app.middleware("http")
async def _require_auth(request: Request, call_next):
    return await auth.auth_middleware(request, call_next, exempt_paths=frozenset({"/health", "/auth/login"}))


# CORS is only relevant to browser-based callers (this service's own SDK
# clients are server-side Python, not subject to CORS at all). Restricted to
# known UI origins now that clients are finite - was previously "*". The
# 5173/3000 origins are the new React frontend's Vite dev server and built
# container, respectively (see frontend/); 8050 is the (still-running)
# Dash UI.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8050", "http://127.0.0.1:8050",
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:3000", "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router.router)
app.include_router(system.router)
app.include_router(scans.router)
app.include_router(probes.router)
app.include_router(objects.router)
app.include_router(v1_profiles.router)
app.include_router(v1_runs.router)
app.include_router(v1_schedules.router)


@app.get("/", tags=["system"])
def root():
    return {"name": "Clouds8 Backend API", "version": app.version, "docs": "/docs"}
