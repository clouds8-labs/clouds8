"""
Clouds8 DB Service - Storage layer

This module owns the ONLY sqlite3 connection to clouds8.db in the whole
system. Every other service/process talks to it exclusively over HTTP
(see app.py). This is what fixes the historical "three uncoordinated
writers" concurrency bug: previously the API process, the Dash UI process,
and sync.py all opened the file directly and raced each other.
"""

import sqlite3
import json
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import contextmanager

import poc_templates

DB_DIR = Path(__file__).parent.parent.parent
DB_FILE = Path(os.getenv("CLOUDS8_DB_PATH", str(DB_DIR / "clouds8.db")))


def get_db_path() -> Path:
    return DB_FILE


@contextmanager
def get_connection():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize the database schema (idempotent) and run additive migrations."""
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                compartment TEXT,
                region TEXT,
                metadata TEXT,
                scan_status TEXT DEFAULT 'not_scanned',
                risk_score INTEGER DEFAULT 0,
                cloud_provider TEXT DEFAULT 'oci',
                scope_type TEXT DEFAULT 'compartment',
                scope_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(asset_id, cloud_provider)
            )
        """)

        existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(assets)").fetchall()}
        if "cloud_provider" not in existing_cols:
            cursor.execute("ALTER TABLE assets ADD COLUMN cloud_provider TEXT DEFAULT 'oci'")
        if "scope_type" not in existing_cols:
            cursor.execute("ALTER TABLE assets ADD COLUMN scope_type TEXT DEFAULT 'compartment'")
        if "scope_id" not in existing_cols:
            cursor.execute("ALTER TABLE assets ADD COLUMN scope_id TEXT")
            cursor.execute("UPDATE assets SET scope_id = compartment WHERE scope_id IS NULL")
        if "profile_id" not in existing_cols:
            cursor.execute("ALTER TABLE assets ADD COLUMN profile_id TEXT")
        if "profile_name" not in existing_cols:
            cursor.execute("ALTER TABLE assets ADD COLUMN profile_name TEXT")

        # Profiles = one persisted cloud account/tenancy, one cloud_provider
        # each, referencing a local SDK config file section by name - no
        # secrets stored (see docs/superpowers/plans for the full design).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                cloud_provider TEXT NOT NULL,
                config_profile_name TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 0,
                verify_status TEXT NOT NULL DEFAULT 'unverified',
                verify_message TEXT,
                verified_at TIMESTAMP,
                whoami_result TEXT,
                whoami_checked_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cloud_provider, config_profile_name)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_provider ON profiles(cloud_provider)")

        cursor.execute("PRAGMA table_info(profiles)")
        existing_profile_cols = {row[1] for row in cursor.fetchall()}
        if "whoami_result" not in existing_profile_cols:
            cursor.execute("ALTER TABLE profiles ADD COLUMN whoami_result TEXT")
        if "whoami_checked_at" not in existing_profile_cols:
            cursor.execute("ALTER TABLE profiles ADD COLUMN whoami_checked_at TIMESTAMP")

        # Engagements = a minimal named grouping of Profiles (many-to-many -
        # a Profile can belong to more than one Engagement). No members,
        # roles, audit trail, or retention - deliberately out of scope.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                asset_classes TEXT,
                regions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS engagement_profiles (
                engagement_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (engagement_id, profile_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_engprof_profile ON engagement_profiles(profile_id)")

        _migrate_composite_asset_uniqueness(conn)
        _migrate_assets_profile_uniqueness(conn)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_type ON assets(asset_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_compartment ON assets(compartment)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_region ON assets(region)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON assets(scan_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_provider ON assets(cloud_provider)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scope_id ON assets(scope_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_profile_id ON assets(profile_id)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT,
                message TEXT,
                remediation TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_asset ON scan_results(asset_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_results(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_severity ON scan_results(severity)")

        # Additive: finding lifecycle state for the /v1 findings surface
        # (open|accepted_risk|resolved). Pre-existing rows default to open.
        scan_result_cols = {row[1] for row in cursor.execute("PRAGMA table_info(scan_results)").fetchall()}
        if "state" not in scan_result_cols:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN state TEXT DEFAULT 'open'")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_state ON scan_results(state)")

        # Additive: who/where a policy finding is about - only IAM policy
        # findings populate these (attack_paths.py's edge derivation needs
        # to know which group/dynamic-group a risky grant applies to, and
        # which compartment's resources it reaches). NULL for every other
        # scanner's findings.
        if "subject" not in scan_result_cols:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN subject TEXT")
        if "resource_compartment_id" not in scan_result_cols:
            cursor.execute("ALTER TABLE scan_results ADD COLUMN resource_compartment_id TEXT")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compartments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                compartment_id TEXT UNIQUE,
                name TEXT NOT NULL,
                parent_id TEXT,
                scope_type TEXT DEFAULT 'compartment',
                scope_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        comp_cols = {row[1] for row in cursor.execute("PRAGMA table_info(compartments)").fetchall()}
        if "scope_type" not in comp_cols:
            cursor.execute("ALTER TABLE compartments ADD COLUMN scope_type TEXT DEFAULT 'compartment'")
        if "scope_id" not in comp_cols:
            cursor.execute("ALTER TABLE compartments ADD COLUMN scope_id TEXT")
            cursor.execute("UPDATE compartments SET scope_id = compartment_id WHERE scope_id IS NULL")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT,
                total_assets INTEGER,
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL DEFAULT 'INFO',
                source TEXT NOT NULL DEFAULT 'system',
                message TEXT NOT NULL,
                ip TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_level ON activity_logs(level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_source ON activity_logs(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_ts ON activity_logs(timestamp)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS service_costs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                cost REAL NOT NULL DEFAULT 0,
                currency TEXT DEFAULT 'USD',
                is_scannable INTEGER DEFAULT 0,
                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(service_name)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sc_name ON service_costs(service_name)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner_type TEXT NOT NULL,
                report_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sr_type ON scan_reports(scanner_type)")

        # Persisted job/task state - replaces api/jobs.py's in-memory dict and
        # the UI's module-global threading dicts. Single source of truth,
        # visible across every process because it's just rows read over HTTP.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                job_type TEXT NOT NULL,
                cloud_provider TEXT,
                scope_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                progress_pct INTEGER DEFAULT 0,
                progress_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                error_message TEXT,
                result_ref TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type)")

        job_cols = {row[1] for row in cursor.execute("PRAGMA table_info(jobs)").fetchall()}
        if "scan_depth" not in job_cols:
            cursor.execute("ALTER TABLE jobs ADD COLUMN scan_depth TEXT DEFAULT 'rules'")
        if "profile_id" not in job_cols:
            cursor.execute("ALTER TABLE jobs ADD COLUMN profile_id TEXT")
        if "profile_name" not in job_cols:
            cursor.execute("ALTER TABLE jobs ADD COLUMN profile_name TEXT")
        if "asset_ids" not in job_cols:
            cursor.execute("ALTER TABLE jobs ADD COLUMN asset_ids TEXT")  # JSON-encoded list, nullable

        # Persisted scan-scheduler definitions - a schedule's *definition*
        # needs the same durability as jobs (survive a backend-api restart),
        # so it follows the identical table+CRUD+HTTP pattern as `jobs` above
        # rather than living in an in-memory APScheduler store.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                classes TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'oci',
                mode TEXT NOT NULL,
                interval_value INTEGER,
                interval_unit TEXT,
                run_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'active',
                next_run_at TIMESTAMP,
                last_run_at TIMESTAMP,
                last_run_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_schedules_status_next_run ON schedules(status, next_run_at)")

        schedule_cols = {row[1] for row in cursor.execute("PRAGMA table_info(schedules)").fetchall()}
        if "scan_depth" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN scan_depth TEXT DEFAULT 'rules'")
        if "profile_id" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN profile_id TEXT")
        if "profile_name" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN profile_name TEXT")
        if "compartment_ids" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN compartment_ids TEXT")  # JSON-encoded list, nullable
        if "regions" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN regions TEXT")  # JSON-encoded list, nullable
        if "asset_ids" not in schedule_cols:
            cursor.execute("ALTER TABLE schedules ADD COLUMN asset_ids TEXT")  # JSON-encoded list, nullable

        conn.commit()
        print(f"Database initialized at {DB_FILE}")


def _migrate_composite_asset_uniqueness(conn: sqlite3.Connection):
    """One-time migration: replace the single-column UNIQUE(asset_id) constraint
    with a composite UNIQUE(asset_id, cloud_provider) constraint.

    SQLite doesn't support ALTER TABLE for constraint changes, so this uses the
    standard create-new/copy/drop/rename pattern, wrapped in a transaction, with
    a pre-migration integrity check so it fails loudly rather than silently
    dropping/reordering data.
    """
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='assets'"
    ).fetchone()
    if row is None:
        return  # table doesn't exist yet, nothing to migrate
    existing_sql = row[0] or ""
    normalized = existing_sql.upper().replace(" ", "").replace("\n", "")
    if "UNIQUE(ASSET_ID,CLOUD_PROVIDER)" in normalized:
        return  # already migrated
    if "ASSET_IDTEXTUNIQUENOTNULL" not in normalized:
        return  # not the old single-column-UNIQUE shape we know how to migrate; leave alone

    dupes = cursor.execute("""
        SELECT asset_id, cloud_provider, COUNT(*) c
        FROM assets GROUP BY asset_id, cloud_provider HAVING c > 1
    """).fetchall()
    if dupes:
        raise RuntimeError(
            f"Cannot migrate assets table: {len(dupes)} duplicate (asset_id, cloud_provider) "
            f"pairs found. Resolve duplicates before restarting the DB service."
        )

    cursor.execute("""
        CREATE TABLE assets_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            name TEXT NOT NULL,
            compartment TEXT,
            region TEXT,
            metadata TEXT,
            scan_status TEXT DEFAULT 'not_scanned',
            risk_score INTEGER DEFAULT 0,
            cloud_provider TEXT DEFAULT 'oci',
            scope_type TEXT DEFAULT 'compartment',
            scope_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_id, cloud_provider)
        )
    """)
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(assets)").fetchall()]
    common = [c for c in cols if c in (
        "id", "asset_id", "asset_type", "name", "compartment", "region", "metadata",
        "scan_status", "risk_score", "cloud_provider", "scope_type", "scope_id",
        "created_at", "updated_at",
    )]
    col_list = ", ".join(common)
    cursor.execute(f"INSERT INTO assets_new ({col_list}) SELECT {col_list} FROM assets")
    cursor.execute("DROP TABLE assets")
    cursor.execute("ALTER TABLE assets_new RENAME TO assets")
    conn.commit()
    print("Migrated assets table to composite UNIQUE(asset_id, cloud_provider)")


def _migrate_assets_profile_uniqueness(conn: sqlite3.Connection):
    """One-time migration: widen UNIQUE(asset_id, cloud_provider) to
    UNIQUE(asset_id, cloud_provider, profile_id). Must run after
    _ensure_default_profile_and_backfill(), which guarantees every existing
    row already has a non-null profile_id.

    Necessary because asset_id is not always a real cloud-native ID - e.g.
    OCI buckets are identified by their human-chosen name, not an OCID,
    and bucket names are only unique within one tenancy. Two Profiles of
    the same provider can legitimately produce the same asset_id, which
    the 2-column constraint would otherwise silently merge/overwrite.
    """
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='assets'"
    ).fetchone()
    if row is None:
        return
    normalized = (row[0] or "").upper().replace(" ", "").replace("\n", "")
    if "UNIQUE(ASSET_ID,CLOUD_PROVIDER,PROFILE_ID)" in normalized:
        return  # already migrated
    if "UNIQUE(ASSET_ID,CLOUD_PROVIDER)" not in normalized:
        return  # not the 2-column shape this function knows how to migrate from

    dupes = cursor.execute("""
        SELECT asset_id, cloud_provider, profile_id, COUNT(*) c
        FROM assets GROUP BY asset_id, cloud_provider, profile_id HAVING c > 1
    """).fetchall()
    if dupes:
        raise RuntimeError(
            f"Cannot migrate assets table: {len(dupes)} duplicate "
            f"(asset_id, cloud_provider, profile_id) rows found."
        )

    cursor.execute("""
        CREATE TABLE assets_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            name TEXT NOT NULL,
            compartment TEXT,
            region TEXT,
            metadata TEXT,
            scan_status TEXT DEFAULT 'not_scanned',
            risk_score INTEGER DEFAULT 0,
            cloud_provider TEXT DEFAULT 'oci',
            scope_type TEXT DEFAULT 'compartment',
            scope_id TEXT,
            profile_id TEXT,
            profile_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_id, cloud_provider, profile_id)
        )
    """)
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(assets)").fetchall()]
    common = [c for c in cols if c in (
        "id", "asset_id", "asset_type", "name", "compartment", "region", "metadata",
        "scan_status", "risk_score", "cloud_provider", "scope_type", "scope_id",
        "profile_id", "profile_name", "created_at", "updated_at",
    )]
    col_list = ", ".join(common)
    cursor.execute(f"INSERT INTO assets_new ({col_list}) SELECT {col_list} FROM assets")
    cursor.execute("DROP TABLE assets")
    cursor.execute("ALTER TABLE assets_new RENAME TO assets")
    conn.commit()
    print("Migrated assets table to composite UNIQUE(asset_id, cloud_provider, profile_id)")


# ── Asset import / query ────────────────────────────────────────────────────

def import_assets(assets: List[Dict], source_description: str = "API Import") -> Dict[str, Any]:
    """Upsert asset rows. Metadata is *merged* on top of whatever's already
    stored, not replaced wholesale - multiple independent sources write
    here (``/sync``'s coarse collectors, and each scanner's richer
    per-resource detail via `findings.py`), and a blind overwrite would mean
    whichever one ran most recently wins, silently erasing the other's
    fields on every subsequent call."""
    stats = {'total': len(assets), 'imported': 0, 'updated': 0, 'errors': 0, 'by_type': {}}
    fallback_profile_cache: Dict[str, Optional[Dict]] = {}

    def _fallback_profile(conn: sqlite3.Connection, cloud_provider: str) -> Optional[Dict]:
        if cloud_provider not in fallback_profile_cache:
            row = conn.execute(
                "SELECT id, name FROM profiles WHERE cloud_provider = ? ORDER BY created_at ASC LIMIT 1",
                (cloud_provider,),
            ).fetchone()
            fallback_profile_cache[cloud_provider] = dict(row) if row else None
        return fallback_profile_cache[cloud_provider]

    with get_connection() as conn:
        cursor = conn.cursor()
        for asset in assets:
            try:
                asset_type = asset.get('asset_type', 'unknown')
                stats['by_type'].setdefault(asset_type, 0)

                cloud_provider = asset.get('cloud_provider', 'oci')
                profile_id = asset.get('profile_id')
                profile_name = asset.get('profile_name')
                if not profile_id:
                    fallback = _fallback_profile(conn, cloud_provider)
                    if fallback:
                        profile_id = fallback['id']
                        profile_name = profile_name or fallback['name']

                meta_raw = asset.get('metadata', {})
                if isinstance(meta_raw, dict):
                    existing = cursor.execute(
                        "SELECT metadata FROM assets WHERE asset_id = ? AND cloud_provider = ? AND profile_id = ?",
                        (asset.get('asset_id'), cloud_provider, profile_id),
                    ).fetchone()
                    merged = {}
                    if existing and existing["metadata"]:
                        try:
                            merged = json.loads(existing["metadata"])
                        except (TypeError, ValueError):
                            merged = {}
                    merged.update(meta_raw)
                    metadata = json.dumps(merged)
                else:
                    metadata = str(meta_raw)
                compartment = asset.get('compartment')
                scope_id = asset.get('scope_id', compartment)
                scope_type = asset.get('scope_type', 'compartment')

                cursor.execute("""
                    INSERT INTO assets (asset_id, asset_type, name, compartment, region, metadata,
                                         scan_status, risk_score, cloud_provider, scope_type, scope_id,
                                         profile_id, profile_name, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id, cloud_provider, profile_id) DO UPDATE SET
                        name = excluded.name,
                        compartment = excluded.compartment,
                        region = excluded.region,
                        metadata = excluded.metadata,
                        risk_score = CASE WHEN excluded.risk_score > assets.risk_score THEN excluded.risk_score ELSE assets.risk_score END,
                        scope_type = excluded.scope_type,
                        scope_id = excluded.scope_id,
                        profile_name = excluded.profile_name,
                        updated_at = excluded.updated_at
                """, (
                    asset.get('asset_id'), asset_type, asset.get('name'), compartment,
                    asset.get('region'), metadata, asset.get('scan_status', 'not_scanned'),
                    asset.get('risk_score', 0), cloud_provider, scope_type, scope_id,
                    profile_id, profile_name, datetime.now().isoformat(),
                ))
                stats['imported'] += 1
                stats['by_type'][asset_type] += 1
            except Exception as e:
                stats['errors'] += 1
                print(f"Error importing asset {asset.get('asset_id', 'unknown')}: {e}")

        cursor.execute(
            "INSERT INTO import_history (source_file, total_assets, status) VALUES (?, ?, ?)",
            (source_description, stats['imported'], 'success' if stats['errors'] == 0 else 'partial'),
        )
        conn.commit()

    return stats


def get_asset_summary() -> Dict[str, int]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT asset_type, COUNT(*) as count FROM assets GROUP BY asset_type ORDER BY count DESC"
        ).fetchall()
        return {r['asset_type']: r['count'] for r in rows}


def get_assets_by_type(asset_type: str, limit: int = 100, offset: int = 0) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE asset_type = ? ORDER BY name LIMIT ? OFFSET ?",
            (asset_type, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_compartment_summary(profile_id: Optional[str] = None, engagement_id: Optional[str] = None) -> Dict[str, int]:
    clauses, params = [], []
    if profile_id:
        clauses.append("profile_id = ?")
        params.append(profile_id)
    if engagement_id:
        clauses.append("profile_id IN (SELECT profile_id FROM engagement_profiles WHERE engagement_id = ?)")
        params.append(engagement_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT compartment, COUNT(*) as count FROM assets {where} GROUP BY compartment ORDER BY count DESC",
            params,
        ).fetchall()
        return {r['compartment']: r['count'] for r in rows}


def get_scope_summary(scope_type: Optional[str] = None) -> Dict[str, int]:
    """Generic successor to get_compartment_summary — groups by scope_id,
    optionally filtered to one scope_type (compartment/account/resource_group/...)."""
    with get_connection() as conn:
        if scope_type:
            rows = conn.execute(
                "SELECT scope_id, COUNT(*) as count FROM assets WHERE scope_type = ? GROUP BY scope_id ORDER BY count DESC",
                (scope_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scope_id, COUNT(*) as count FROM assets GROUP BY scope_id ORDER BY count DESC"
            ).fetchall()
        return {r['scope_id']: r['count'] for r in rows}


def get_region_summary() -> Dict[str, int]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT region, COUNT(*) as count FROM assets GROUP BY region ORDER BY count DESC"
        ).fetchall()
        return {r['region']: r['count'] for r in rows}


def get_region_type_summary() -> Dict[str, Dict[str, int]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT region, asset_type, COUNT(*) as count FROM assets GROUP BY region, asset_type ORDER BY region, asset_type"
        ).fetchall()
    result: Dict[str, Dict[str, int]] = {}
    for row in rows:
        region = row['region'] or 'unknown'
        result.setdefault(region, {})[row['asset_type']] = row['count']
    return result


def upsert_service_costs(services: Dict[str, float], scannable_set: Optional[set] = None):
    scannable_set = scannable_set or set()
    ts = datetime.now().isoformat()
    with get_connection() as conn:
        for svc, cost in services.items():
            conn.execute("""
                INSERT INTO service_costs (service_name, cost, is_scannable, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE
                    SET cost=excluded.cost, is_scannable=excluded.is_scannable, fetched_at=excluded.fetched_at
            """, (svc, cost, 1 if svc in scannable_set else 0, ts))
        conn.commit()


def get_service_costs() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT service_name, cost, currency, is_scannable, fetched_at FROM service_costs ORDER BY cost DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_assets(limit: int = 1000, offset: int = 0) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets ORDER BY asset_type, name LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(r) for r in rows]


def get_assets_by_provider(provider: str, limit: int = 1000, offset: int = 0) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE cloud_provider = ? ORDER BY asset_type, name LIMIT ? OFFSET ?",
            (provider, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_assets_by_types(asset_types: List[str], query: str = "", limit: int = 20) -> List[Dict]:
    """Assets filtered to a set of types, optionally name/id search. Backs the
    Lynker exposed-asset picker (previously raw SQL in ui/pages/lynker.py)."""
    if not asset_types:
        return []
    placeholders = ",".join("?" for _ in asset_types)
    with get_connection() as conn:
        if query:
            rows = conn.execute(
                f"""SELECT asset_id, name, asset_type, compartment, metadata FROM assets
                    WHERE asset_type IN ({placeholders}) AND (name LIKE ? OR asset_id LIKE ?)
                    LIMIT ?""",
                (*asset_types, f'%{query}%', f'%{query}%', limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""SELECT asset_id, name, asset_type, compartment, metadata FROM assets
                    WHERE asset_type IN ({placeholders}) LIMIT ?""",
                (*asset_types, limit),
            ).fetchall()
        return [dict(r) for r in rows]


def update_asset_scan_status(asset_id: str, status: str = "scanned", risk_score: Optional[int] = None):
    with get_connection() as conn:
        if risk_score is not None:
            conn.execute(
                "UPDATE assets SET scan_status = ?, risk_score = ?, updated_at = ? WHERE asset_id = ?",
                (status, risk_score, datetime.now().isoformat(), asset_id),
            )
        else:
            conn.execute(
                "UPDATE assets SET scan_status = ?, updated_at = ? WHERE asset_id = ?",
                (status, datetime.now().isoformat(), asset_id),
            )
        conn.commit()


def mark_assets_scanned_by_type(asset_type: str, status: str = "scanned"):
    with get_connection() as conn:
        conn.execute(
            "UPDATE assets SET scan_status = ?, updated_at = ? WHERE asset_type = ?",
            (status, datetime.now().isoformat(), asset_type),
        )
        conn.commit()


def get_total_asset_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) as count FROM assets").fetchone()['count']


def get_sync_progress() -> Dict[str, int]:
    """Total known compartments vs. compartments that have at least one asset.
    Replaces raw SQL previously in ui/pages/home.py's progress callback."""
    with get_connection() as conn:
        total_comps = conn.execute("SELECT COUNT(*) as count FROM compartments").fetchone()['count']
        scanned_comps = conn.execute(
            "SELECT COUNT(DISTINCT compartment) as count FROM assets"
        ).fetchone()['count']
    return {"total_compartments": total_comps, "scanned_compartments": scanned_comps}


def search_assets(query: str, limit: int = 50) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE name LIKE ? OR asset_id LIKE ? ORDER BY name LIMIT ?",
            (f'%{query}%', f'%{query}%', limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_hierarchy_data() -> Dict:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT compartment, asset_type, COUNT(*) as count FROM assets GROUP BY compartment, asset_type ORDER BY compartment, asset_type"
        ).fetchall()
    hierarchy: Dict[str, Dict[str, int]] = {}
    for row in rows:
        comp = row['compartment'] or 'unknown'
        hierarchy.setdefault(comp, {})[row['asset_type']] = row['count']
    return hierarchy


def clear_database():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_results")
        cursor.execute("DELETE FROM assets")
        cursor.execute("DELETE FROM compartments")
        conn.commit()
        print("Database cleared")


def import_compartments(compartments: List[Dict]) -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        count = 0
        for comp in compartments:
            try:
                comp_id = comp.get('id', comp.get('compartment_id'))
                cursor.execute("""
                    INSERT INTO compartments (compartment_id, name, parent_id, scope_type, scope_id)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(compartment_id) DO UPDATE SET
                        name = excluded.name, parent_id = excluded.parent_id,
                        scope_type = excluded.scope_type, scope_id = excluded.scope_id
                """, (
                    comp_id, comp['name'], comp.get('parent_compartment_id'),
                    comp.get('scope_type', 'compartment'), comp.get('scope_id', comp_id),
                ))
                count += 1
            except Exception as e:
                print(f"Error importing compartment {comp.get('name')}: {e}")
        conn.commit()
    return count


def get_compartments_list(cloud_provider: Optional[str] = None) -> List[Dict]:
    """{compartment_id, name, scope_type} list for UI pickers. Replaces raw
    SQL previously in ui/pages/playbooks.py's _get_compartment_options().
    scope_type is "compartment" for OCI or "project" for GCP (a GCP project
    stands in for an OCI compartment - see gcp_collector.py's
    collect_compartment_details()) - callers that need to scope a picker to
    one provider can filter on it directly, or pass cloud_provider here to
    have the query do it."""
    scope_type = {"gcp": "project", "oci": "compartment"}.get(cloud_provider or "")
    with get_connection() as conn:
        if scope_type:
            rows = conn.execute(
                "SELECT compartment_id, name, scope_type FROM compartments WHERE scope_type = ? ORDER BY name",
                (scope_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT compartment_id, name, scope_type FROM compartments ORDER BY name"
            ).fetchall()
        return [dict(r) for r in rows]


def get_regions_list(cloud_provider: Optional[str] = None) -> List[Dict]:
    """Distinct region values seen in `assets`, for UI pickers - same
    convention as get_compartments_list() above. A never-scanned profile
    yields an empty list, same as it already does for compartments."""
    with get_connection() as conn:
        q = "SELECT DISTINCT region FROM assets WHERE region IS NOT NULL AND region != ''"
        params: List[Any] = []
        if cloud_provider:
            q += " AND cloud_provider = ?"
            params.append(cloud_provider)
        q += " ORDER BY region"
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]


def get_compartments_for_sunburst() -> Dict[str, Any]:
    with get_connection() as conn:
        rows = conn.execute("SELECT compartment_id, name, parent_id FROM compartments").fetchall()
        asset_counts = {
            r['compartment']: r['count'] for r in conn.execute(
                "SELECT compartment, COUNT(*) as count FROM assets GROUP BY compartment"
            ).fetchall()
        }

    ids, labels, parents, values = [], [], [], []
    all_known_ids = set(row['compartment_id'] for row in rows)

    tenancy_id = None
    for row in rows:
        if not row['parent_id']:
            tenancy_id = row['compartment_id']
            break

    for row in rows:
        ids.append(row['compartment_id'])
        labels.append(row['name'])
        parents.append(row['parent_id'] if row['parent_id'] else "")
        values.append(asset_counts.get(row['name'], 1))

    referenced_parents = set(row['parent_id'] for row in rows if row['parent_id'])
    for pid in referenced_parents:
        if pid not in all_known_ids:
            ids.append(pid)
            labels.append(f"Unknown Parent ({pid[-6:]})")
            parents.append(tenancy_id if tenancy_id else "")
            values.append(1)
            all_known_ids.add(pid)

    return {'ids': ids, 'labels': labels, 'parents': parents, 'values': values}


def get_assets_by_compartment_label(compartment_label: str) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE compartment = ? ORDER BY asset_type, name", (compartment_label,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_asset_counts_by_compartment(
    compartment_label: str, profile_id: Optional[str] = None, engagement_id: Optional[str] = None,
) -> Dict[str, int]:
    clauses, params = ["compartment = ?"], [compartment_label]
    if profile_id:
        clauses.append("profile_id = ?")
        params.append(profile_id)
    if engagement_id:
        clauses.append("profile_id IN (SELECT profile_id FROM engagement_profiles WHERE engagement_id = ?)")
        params.append(engagement_id)
    where = "WHERE " + " AND ".join(clauses)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT asset_type, COUNT(*) as count FROM assets {where} GROUP BY asset_type ORDER BY count DESC",
            params,
        ).fetchall()
        return {r['asset_type']: r['count'] for r in rows}


def get_assets_by_compartment_and_type(compartment_label: str, asset_type: str) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE compartment = ? AND asset_type = ? ORDER BY name",
            (compartment_label, asset_type),
        ).fetchall()
        return [dict(r) for r in rows]


def get_asset_by_id(asset_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return dict(row) if row else None


def get_asset_by_name(name: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM assets WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None


# ── Blast radius ─────────────────────────────────────────────────────────────

def calculate_blast_radius(asset: Dict) -> Dict[str, Any]:
    if not asset:
        return {"error": "Asset not found"}

    compartment = asset.get('compartment')
    region = asset.get('region')
    asset_type = asset.get('asset_type')
    asset_id = asset.get('asset_id')

    result = {
        'source_asset': asset,
        'direct_connections': [],
        'indirect_connections': [],
        'iam_exposure': [],
        'summary': {
            'total_impacted': 0, 'by_type': {}, 'risk_level': 'low',
            'compartments_affected': set(), 'regions_affected': set(),
        },
    }

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM assets WHERE compartment = ? AND asset_id != ? ORDER BY asset_type, name",
            (compartment, asset_id),
        )
        for row in cursor.fetchall():
            asset_dict = dict(row)
            asset_dict['connection_strength'] = _calculate_connection_strength(asset_type, asset_dict['asset_type'])
            asset_dict['connection_reason'] = f"Same compartment: {compartment}"
            result['direct_connections'].append(asset_dict)
            atype = asset_dict['asset_type']
            result['summary']['by_type'][atype] = result['summary']['by_type'].get(atype, 0) + 1
            result['summary']['compartments_affected'].add(compartment)

        cursor.execute(
            "SELECT * FROM assets WHERE region = ? AND compartment != ? AND asset_id != ? "
            "ORDER BY compartment, asset_type, name LIMIT 100",
            (region, compartment, asset_id),
        )
        for row in cursor.fetchall():
            asset_dict = dict(row)
            asset_dict['connection_strength'] = _calculate_connection_strength(asset_type, asset_dict['asset_type']) * 0.5
            asset_dict['connection_reason'] = f"Same region: {region}"
            result['indirect_connections'].append(asset_dict)
            result['summary']['compartments_affected'].add(asset_dict['compartment'])

        cursor.execute(
            "SELECT * FROM assets WHERE asset_type = 'iam' AND (compartment = ? OR region = ?) ORDER BY name",
            (compartment, region),
        )
        for row in cursor.fetchall():
            asset_dict = dict(row)
            asset_dict['connection_reason'] = "IAM policy with potential access"
            result['iam_exposure'].append(asset_dict)

    result['summary']['total_impacted'] = len(result['direct_connections']) + len(result['indirect_connections'])
    result['summary']['compartments_affected'] = list(result['summary']['compartments_affected'])
    result['summary']['regions_affected'] = [region] if region else []

    total = result['summary']['total_impacted']
    if total > 100:
        result['summary']['risk_level'] = 'critical'
    elif total > 50:
        result['summary']['risk_level'] = 'high'
    elif total > 20:
        result['summary']['risk_level'] = 'medium'
    else:
        result['summary']['risk_level'] = 'low'

    return result


def _calculate_connection_strength(source_type: str, target_type: str) -> float:
    strength_matrix = {
        'vm': {'vnic': 1.0, 'lb': 0.8, 'bucket': 0.6, 'iam': 0.9, 'vm': 0.5},
        'vnic': {'vm': 1.0, 'lb': 0.7, 'vnic': 0.4, 'bucket': 0.3, 'iam': 0.5},
        'lb': {'vm': 0.9, 'vnic': 0.7, 'lb': 0.3, 'bucket': 0.2, 'iam': 0.6},
        'bucket': {'vm': 0.5, 'iam': 0.9, 'bucket': 0.2, 'vnic': 0.1, 'lb': 0.1},
        'iam': {'vm': 0.9, 'vnic': 0.7, 'lb': 0.8, 'bucket': 0.9, 'iam': 0.5},
    }
    return strength_matrix.get(source_type, {}).get(target_type, 0.3)


def get_blast_radius_graph_data(asset: Dict) -> Dict[str, Any]:
    blast_radius = calculate_blast_radius(asset)
    if 'error' in blast_radius:
        return blast_radius

    nodes, edges = [], []
    source = blast_radius['source_asset']
    nodes.append({
        'id': source['asset_id'], 'label': source['name'][:30], 'type': source['asset_type'],
        'group': 'source', 'size': 30, 'color': '#ff4444',
    })

    for i, a in enumerate(blast_radius['direct_connections'][:30]):
        nodes.append({
            'id': a['asset_id'], 'label': a['name'][:20], 'type': a['asset_type'],
            'group': 'direct', 'size': 20, 'color': _get_asset_color(a['asset_type']),
        })
        edges.append({
            'source': source['asset_id'], 'target': a['asset_id'], 'strength': a['connection_strength'],
            'reason': a.get('connection_reason', 'Direct relationship'), 'hop': 1,
        })

    for i, a in enumerate(blast_radius['indirect_connections'][:20]):
        nodes.append({
            'id': a['asset_id'], 'label': a['name'][:20], 'type': a['asset_type'],
            'group': 'indirect', 'size': 15, 'color': _get_asset_color(a['asset_type'], faded=True),
        })
        if blast_radius['direct_connections']:
            connector = blast_radius['direct_connections'][i % len(blast_radius['direct_connections'])]
            edges.append({
                'source': connector['asset_id'], 'target': a['asset_id'], 'strength': a['connection_strength'],
                'reason': a.get('connection_reason', 'Indirect routing via region'), 'hop': 2,
            })

    return {
        'nodes': nodes, 'edges': edges, 'summary': blast_radius['summary'],
        'direct_count': len(blast_radius['direct_connections']),
        'indirect_count': len(blast_radius['indirect_connections']),
        'iam_count': len(blast_radius['iam_exposure']),
    }


def _get_asset_color(asset_type: str, faded: bool = False) -> str:
    colors = {'vm': '#0d6efd', 'vnic': '#0dcaf0', 'bucket': '#ffc107', 'iam': '#dc3545', 'lb': '#198754'}
    color = colors.get(asset_type, '#6c757d')
    return color + '80' if faded else color


def search_assets_for_blast_radius(query: str, limit: int = 20) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT asset_id, name, asset_type, compartment, region FROM assets
            WHERE name LIKE ? OR asset_id LIKE ?
            ORDER BY CASE WHEN name LIKE ? THEN 0 ELSE 1 END, name
            LIMIT ?
        """, (f'%{query}%', f'%{query}%', f'{query}%', limit)).fetchall()
        return [dict(r) for r in rows]


# ── Activity logs ────────────────────────────────────────────────────────────

def insert_activity_log(level: str, source: str, message: str, ip: Optional[str] = None,
                         metadata: Optional[str] = None, timestamp: Optional[str] = None):
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO activity_logs (timestamp, level, source, message, ip, metadata) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, level.upper(), source, message, ip, metadata),
        )
        conn.commit()


def get_activity_logs(level: Optional[str] = None, source: Optional[str] = None,
                       search: Optional[str] = None, limit: int = 200) -> List[Dict]:
    clauses, params = [], []
    if level:
        clauses.append("level = ?")
        params.append(level.upper())
    if source:
        clauses.append("source = ?")
        params.append(source)
    if search:
        clauses.append("(message LIKE ? OR source LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"SELECT id, timestamp, level, source, message, ip, metadata FROM activity_logs {where} ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def get_log_stats() -> Dict[str, Any]:
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
        errors = conn.execute("SELECT COUNT(*) FROM activity_logs WHERE level='ERROR'").fetchone()[0]
        warnings = conn.execute("SELECT COUNT(*) FROM activity_logs WHERE level='WARN'").fetchone()[0]
        sources = conn.execute("SELECT COUNT(DISTINCT source) FROM activity_logs").fetchone()[0]
        ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM activity_logs WHERE ip IS NOT NULL").fetchone()[0]
    return {"total": total, "errors": errors, "warnings": warnings, "sources": sources, "ips": ips}


# ── Config ────────────────────────────────────────────────────────────────────

def save_config(key: str, value: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO config_settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, datetime.now().isoformat()),
        )
        conn.commit()


def get_config(key: str, default: Optional[str] = None) -> Optional[str]:
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM config_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def get_all_configs() -> Dict[str, str]:
    with get_connection() as conn:
        rows = conn.execute("SELECT key, value FROM config_settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


# ── Scan findings / reports ──────────────────────────────────────────────────

def get_recent_scan_findings(limit: int = 20) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT sr.id, sr.asset_id, sr.check_id, sr.check_name, sr.status, sr.severity,
                   sr.message, sr.remediation, sr.scanned_at,
                   a.name AS asset_name, a.asset_type, a.compartment
            FROM scan_results sr
            LEFT JOIN assets a ON sr.asset_id = a.asset_id
            WHERE sr.status IN ('FAIL', 'WARNING', 'CRITICAL')
            ORDER BY sr.scanned_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_scan_results_by_asset_ids(asset_ids: List[str]) -> Dict[str, List[Dict]]:
    """scan_results rows for a set of asset_ids, grouped by asset_id. Replaces
    raw SQL previously in ui/pages/playbooks.py's bucket-results enrichment."""
    if not asset_ids:
        return {}
    placeholders = ",".join("?" for _ in asset_ids)
    with get_connection() as conn:
        rows = conn.execute(f"""
            SELECT asset_id, check_id, check_name, status, severity, message, remediation
            FROM scan_results WHERE asset_id IN ({placeholders})
        """, asset_ids).fetchall()
    grouped: Dict[str, List[Dict]] = {}
    for r in rows:
        grouped.setdefault(r["asset_id"], []).append(dict(r))
    return grouped


def insert_scan_results(findings: List[Dict]) -> int:
    """Bulk insert scan_results rows. Replaces raw executemany() previously in
    ui/pages/playbooks.py. Each finding dict needs: asset_id, check_id,
    check_name, status, severity, message, remediation."""
    if not findings:
        return 0
    with get_connection() as conn:
        conn.executemany(
            "INSERT INTO scan_results (asset_id, check_id, check_name, status, severity, message, remediation, "
            "subject, resource_compartment_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(
                f.get("asset_id", ""), f.get("check_id", ""), f.get("check_name", ""),
                f.get("status", ""), f.get("severity", ""), f.get("message", ""),
                f.get("remediation", ""), f.get("subject"), f.get("resource_compartment_id"),
            ) for f in findings],
        )
        conn.commit()
    return len(findings)


def save_scan_report(scanner_type: str, report: dict):
    with get_connection() as conn:
        conn.execute("DELETE FROM scan_reports WHERE scanner_type = ?", (scanner_type,))
        conn.execute(
            "INSERT INTO scan_reports (scanner_type, report_json) VALUES (?, ?)",
            (scanner_type, json.dumps(report)),
        )
        conn.commit()


def get_latest_scan_report(scanner_type: str) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT report_json FROM scan_reports WHERE scanner_type = ? ORDER BY created_at DESC LIMIT 1",
            (scanner_type,),
        ).fetchone()
    if row:
        try:
            return json.loads(row["report_json"])
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def get_most_recent_scanner_type() -> Optional[str]:
    with get_connection() as conn:
        row = conn.execute("SELECT scanner_type FROM scan_reports ORDER BY created_at DESC LIMIT 1").fetchone()
    return row["scanner_type"] if row else None


# ── Jobs (persisted, replaces api/jobs.py in-memory dict) ───────────────────

def create_job(job_type: str, cloud_provider: Optional[str] = None, scope_id: Optional[str] = None,
                scan_depth: str = "rules", profile_id: Optional[str] = None,
                profile_name: Optional[str] = None, asset_ids: Optional[List[str]] = None) -> Dict:
    job_id = uuid.uuid4().hex
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO jobs (id, job_type, cloud_provider, scope_id, status, created_at, scan_depth, "
            "profile_id, profile_name, asset_ids) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
            (job_id, job_type, cloud_provider, scope_id, now, scan_depth, profile_id, profile_name,
             json.dumps(asset_ids) if asset_ids else None),
        )
        conn.commit()
    return get_job(job_id)


def update_job(job_id: str, status: Optional[str] = None, progress_pct: Optional[int] = None,
               progress_message: Optional[str] = None, error_message: Optional[str] = None,
               result_ref: Optional[str] = None, started: bool = False, finished: bool = False) -> Optional[Dict]:
    sets, params = [], []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if progress_pct is not None:
        sets.append("progress_pct = ?")
        params.append(progress_pct)
    if progress_message is not None:
        sets.append("progress_message = ?")
        params.append(progress_message)
    if error_message is not None:
        sets.append("error_message = ?")
        params.append(error_message)
    if result_ref is not None:
        sets.append("result_ref = ?")
        params.append(result_ref)
    if started:
        sets.append("started_at = ?")
        params.append(datetime.now().isoformat())
    if finished:
        sets.append("finished_at = ?")
        params.append(datetime.now().isoformat())
    if not sets:
        return get_job(job_id)
    params.append(job_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
    return get_job(job_id)


def get_job(job_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row else None


def list_jobs(
    job_type: Optional[str] = None, status: Optional[str] = None, limit: int = 100,
    profile_id: Optional[str] = None, engagement_id: Optional[str] = None,
) -> List[Dict]:
    clauses, params = [], []
    if job_type:
        clauses.append("job_type = ?")
        params.append(job_type)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if profile_id:
        clauses.append("profile_id = ?")
        params.append(profile_id)
    if engagement_id:
        clauses.append("profile_id IN (SELECT profile_id FROM engagement_profiles WHERE engagement_id = ?)")
        params.append(engagement_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM jobs {where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
        return [dict(r) for r in rows]


# ── Schedules (persisted scan-scheduler definitions) ────────────────────────

def create_schedule(classes: List[str], provider: str, mode: str, next_run_at: str,
                     interval_value: Optional[int] = None, interval_unit: Optional[str] = None,
                     run_at: Optional[str] = None, scan_depth: str = "rules",
                     profile_id: Optional[str] = None, profile_name: Optional[str] = None,
                     compartment_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None,
                     asset_ids: Optional[List[str]] = None) -> Dict:
    schedule_id = uuid.uuid4().hex
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO schedules (id, classes, provider, mode, interval_value, interval_unit, "
            "run_at, status, next_run_at, scan_depth, profile_id, profile_name, "
            "compartment_ids, regions, asset_ids) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            (schedule_id, json.dumps(classes), provider, mode, interval_value, interval_unit, run_at,
             next_run_at, scan_depth, profile_id, profile_name,
             json.dumps(compartment_ids) if compartment_ids else None,
             json.dumps(regions) if regions else None,
             json.dumps(asset_ids) if asset_ids else None),
        )
        conn.commit()
    return get_schedule(schedule_id)


def update_schedule(schedule_id: str, status: Optional[str] = None, next_run_at: Optional[str] = None,
                     last_run_at: Optional[str] = None, last_run_id: Optional[str] = None) -> Optional[Dict]:
    sets, params = [], []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if next_run_at is not None:
        sets.append("next_run_at = ?")
        params.append(next_run_at)
    if last_run_at is not None:
        sets.append("last_run_at = ?")
        params.append(last_run_at)
    if last_run_id is not None:
        sets.append("last_run_id = ?")
        params.append(last_run_id)
    if not sets:
        return get_schedule(schedule_id)
    params.append(schedule_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE schedules SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
    return get_schedule(schedule_id)


def get_schedule(schedule_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        return dict(row) if row else None


def list_schedules(status: Optional[str] = None, limit: int = 100) -> List[Dict]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM schedules {where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
        return [dict(r) for r in rows]


def list_due_schedules(before: str, limit: int = 100) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM schedules WHERE status = 'active' AND next_run_at <= ? "
            "ORDER BY next_run_at LIMIT ?", (before, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_schedule(schedule_id: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        return cur.rowcount > 0


# ── Profiles ─────────────────────────────────────────────────────────────────
# One persisted cloud account/tenancy, scoped to exactly one cloud_provider,
# referencing a local SDK config file section by name - no secrets stored.

def _profile_row_to_dict(row: sqlite3.Row) -> Dict:
    """SQLite stores is_active as INTEGER 0/1 - convert to a real Python
    bool here so every Profile-returning function sends a JSON boolean,
    not a number. A raw 0 is falsy but still a renderable React child
    (unlike false/null/undefined), so an unconverted int renders the
    literal text "0" in the UI instead of nothing."""
    d = dict(row)
    d["is_active"] = bool(d["is_active"])
    return d


def create_profile(name: str, cloud_provider: str, config_profile_name: str) -> Dict:
    profile_id = uuid.uuid4().hex
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO profiles (id, name, cloud_provider, config_profile_name,
                                   is_active, verify_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 0, 'unverified', ?, ?)
        """, (profile_id, name, cloud_provider, config_profile_name, now, now))
        conn.commit()
    return get_profile(profile_id)


def get_profile(profile_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
        return _profile_row_to_dict(row) if row else None


def get_active_profile(cloud_provider: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM profiles WHERE cloud_provider = ? AND is_active = 1", (cloud_provider,)
        ).fetchone()
        return _profile_row_to_dict(row) if row else None


def list_profiles(cloud_provider: Optional[str] = None) -> List[Dict]:
    clauses, params = [], []
    if cloud_provider:
        clauses.append("cloud_provider = ?")
        params.append(cloud_provider)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(f"SELECT * FROM profiles {where} ORDER BY created_at ASC", params).fetchall()
        return [_profile_row_to_dict(r) for r in rows]


def update_profile(profile_id: str, name: Optional[str] = None, config_profile_name: Optional[str] = None,
                    verify_status: Optional[str] = None, verify_message: Optional[str] = None,
                    verified_at: Optional[str] = None, whoami_result: Optional[str] = None,
                    whoami_checked_at: Optional[str] = None) -> Optional[Dict]:
    sets, params = [], []
    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if config_profile_name is not None:
        sets.append("config_profile_name = ?")
        params.append(config_profile_name)
    if verify_status is not None:
        sets.append("verify_status = ?")
        params.append(verify_status)
    if verify_message is not None:
        sets.append("verify_message = ?")
        params.append(verify_message)
    if verified_at is not None:
        sets.append("verified_at = ?")
        params.append(verified_at)
    if whoami_result is not None:
        sets.append("whoami_result = ?")
        params.append(whoami_result)
    if whoami_checked_at is not None:
        sets.append("whoami_checked_at = ?")
        params.append(whoami_checked_at)
    if not sets:
        return get_profile(profile_id)
    sets.append("updated_at = ?")
    params.append(datetime.now().isoformat())
    params.append(profile_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE profiles SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
    return get_profile(profile_id)


def activate_profile(profile_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT cloud_provider FROM profiles WHERE id = ?", (profile_id,)).fetchone()
        if row is None:
            return None
        now = datetime.now().isoformat()
        conn.execute(
            "UPDATE profiles SET is_active = 0, updated_at = ? WHERE cloud_provider = ?",
            (now, row["cloud_provider"]),
        )
        conn.execute("UPDATE profiles SET is_active = 1, updated_at = ? WHERE id = ?", (now, profile_id))
        conn.commit()
    return get_profile(profile_id)


def delete_profile(profile_id: str) -> bool:
    with get_connection() as conn:
        conn.execute("DELETE FROM engagement_profiles WHERE profile_id = ?", (profile_id,))
        cur = conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
        conn.commit()
        return cur.rowcount > 0


# ── Engagements ──────────────────────────────────────────────────────────────
# A minimal named grouping of Profiles (many-to-many) - no members, roles,
# audit trail, or retention; deliberately out of scope for this feature.

def _engagement_with_profiles(conn: sqlite3.Connection, engagement_id: str) -> Optional[Dict]:
    row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
    if row is None:
        return None
    engagement = dict(row)
    engagement["asset_classes"] = json.loads(engagement["asset_classes"]) if engagement.get("asset_classes") else None
    engagement["regions"] = json.loads(engagement["regions"]) if engagement.get("regions") else None
    profile_rows = conn.execute("""
        SELECT p.id, p.name, p.cloud_provider, p.is_active
        FROM engagement_profiles ep JOIN profiles p ON p.id = ep.profile_id
        WHERE ep.engagement_id = ?
        ORDER BY p.created_at ASC
    """, (engagement_id,)).fetchall()
    engagement["profiles"] = [_profile_row_to_dict(r) for r in profile_rows]
    return engagement


def create_engagement(name: str, profile_ids: List[str], asset_classes: Optional[List[str]] = None,
                       regions: Optional[List[str]] = None) -> Dict:
    engagement_id = uuid.uuid4().hex
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO engagements (id, name, asset_classes, regions, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            engagement_id, name,
            json.dumps(asset_classes) if asset_classes else None,
            json.dumps(regions) if regions else None,
            now, now,
        ))
        for profile_id in profile_ids:
            conn.execute(
                "INSERT OR IGNORE INTO engagement_profiles (engagement_id, profile_id) VALUES (?, ?)",
                (engagement_id, profile_id),
            )
        conn.commit()
        return _engagement_with_profiles(conn, engagement_id)


def get_engagement(engagement_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        return _engagement_with_profiles(conn, engagement_id)


def list_engagements() -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT id FROM engagements ORDER BY created_at ASC").fetchall()
        return [_engagement_with_profiles(conn, r["id"]) for r in rows]


def update_engagement(engagement_id: str, name: Optional[str] = None,
                       asset_classes: Optional[List[str]] = None,
                       regions: Optional[List[str]] = None) -> Optional[Dict]:
    """Only non-None fields are updated (same convention as update_schedule) -
    there is no way to PATCH asset_classes/regions back to null, only to
    replace them with a different non-empty list. Acceptable for this
    feature's scope; matches the pre-existing limitation on every other
    PATCH endpoint in this file."""
    sets, params = [], []
    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if asset_classes is not None:
        sets.append("asset_classes = ?")
        params.append(json.dumps(asset_classes))
    if regions is not None:
        sets.append("regions = ?")
        params.append(json.dumps(regions))
    if not sets:
        return get_engagement(engagement_id)
    sets.append("updated_at = ?")
    params.append(datetime.now().isoformat())
    params.append(engagement_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE engagements SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
        return _engagement_with_profiles(conn, engagement_id)


def delete_engagement(engagement_id: str) -> bool:
    with get_connection() as conn:
        conn.execute("DELETE FROM engagement_profiles WHERE engagement_id = ?", (engagement_id,))
        cur = conn.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        conn.commit()
        return cur.rowcount > 0


def add_profile_to_engagement(engagement_id: str, profile_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        engagement = conn.execute("SELECT id FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        profile = conn.execute("SELECT id FROM profiles WHERE id = ?", (profile_id,)).fetchone()
        if engagement is None or profile is None:
            return None
        conn.execute(
            "INSERT OR IGNORE INTO engagement_profiles (engagement_id, profile_id) VALUES (?, ?)",
            (engagement_id, profile_id),
        )
        conn.commit()
        return _engagement_with_profiles(conn, engagement_id)


def remove_profile_from_engagement(engagement_id: str, profile_id: str) -> Optional[Dict]:
    with get_connection() as conn:
        engagement = conn.execute("SELECT id FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        if engagement is None:
            return None
        conn.execute(
            "DELETE FROM engagement_profiles WHERE engagement_id = ? AND profile_id = ?",
            (engagement_id, profile_id),
        )
        conn.commit()
        return _engagement_with_profiles(conn, engagement_id)


# ── V1 API — polymorphic assets/findings surface for the React frontend ─────
#
# Reshapes the existing `assets` + `scan_results` tables into the contract
# the new UI expects (see routers/v1.py), without changing either table's
# role for existing callers (Dash UI, lynxctl). `exposure` and `risk` are
# derived here rather than stored — deterministic, cheap to recompute, and
# never drift from the underlying findings.

# Known scan_results.check_id values that indicate internet-facing/public
# exposure, ported from services/backend-api/findings.py's per-scanner
# finding shapes (bucket-public, vm-public-ip).
_EXPOSURE_CHECK_IDS = ("bucket-public", "vm-public-ip")

_SEVERITY_RANK_SQL = """CASE UPPER(severity)
    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
    WHEN 'MEDIUM' THEN 2 WHEN 'WARNING' THEN 2
    WHEN 'LOW' THEN 1 ELSE 0 END"""

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# scan_results is insert-only: every scan run appends a fresh row per
# (asset_id, check_id) instead of upserting, so the table accumulates one
# row *per scan run*, not one row per logical finding. Every v1 query that
# counts or lists findings needs to first collapse this down to the latest
# row per (asset_id, check_id) - otherwise counts/badges roughly double
# (or worse) for any asset that has been scanned more than once, and a
# resolved/rescanned finding can appear as a literal duplicate card in the
# UI. `first_seen` (earliest scanned_at in the group) is preserved for
# display even though only the latest row's severity/message/state wins.
_LATEST_FINDINGS_CTE = """
    latest_findings AS (
        SELECT * FROM (
            SELECT sr.*,
                   ROW_NUMBER() OVER (PARTITION BY sr.asset_id, sr.check_id ORDER BY sr.scanned_at DESC) AS rn,
                   MIN(sr.scanned_at) OVER (PARTITION BY sr.asset_id, sr.check_id) AS first_seen
            FROM scan_results sr
        )
        WHERE rn = 1
    )
"""


def _asset_findings_subquery() -> str:
    """Per-asset finding counts + worst severity rank, excluding resolved
    findings from the counts (an asset with only resolved findings should
    not still show as critical). Callers must prepend
    `WITH {_LATEST_FINDINGS_CTE}` to whatever query embeds this."""
    return f"""
        SELECT asset_id,
            SUM(CASE WHEN UPPER(severity)='CRITICAL' THEN 1 ELSE 0 END) AS n_critical,
            SUM(CASE WHEN UPPER(severity)='HIGH' THEN 1 ELSE 0 END) AS n_high,
            SUM(CASE WHEN UPPER(severity) IN ('MEDIUM','WARNING') THEN 1 ELSE 0 END) AS n_medium,
            SUM(CASE WHEN UPPER(severity)='LOW' THEN 1 ELSE 0 END) AS n_low,
            SUM(CASE WHEN UPPER(severity)='INFO' THEN 1 ELSE 0 END) AS n_info,
            COUNT(*) AS n_total,
            MAX({_SEVERITY_RANK_SQL}) AS max_sev_rank
        FROM latest_findings
        WHERE state != 'resolved'
        GROUP BY asset_id
    """


def _asset_exposure_subquery() -> str:
    placeholders = ",".join("?" for _ in _EXPOSURE_CHECK_IDS)
    return f"""
        SELECT asset_id,
            CASE WHEN SUM(CASE WHEN check_id IN ({placeholders}) THEN 1 ELSE 0 END) > 0
                 THEN 'internet_facing' ELSE 'internal' END AS exposure
        FROM scan_results
        GROUP BY asset_id
    """


def _compute_risk(n_critical: int, n_high: int, n_medium: int, n_low: int, exposure: str) -> float:
    """Deterministic 0-10 risk score from finding severity counts + exposure.
    Not a stand-in for real risk modelling - just enough to sort/badge
    consistently until (if ever) a real scoring engine exists."""
    score = 2.0 * n_critical + 1.0 * n_high + 0.4 * n_medium + 0.1 * n_low
    if exposure == "internet_facing":
        score += 2.0
    return round(min(score, 10.0), 1)


def _asset_row_to_v1(row: Dict) -> Dict:
    """Shape one joined assets+findings+exposure row into the v1 Asset
    contract (core fields + parsed `properties` + computed `risk` +
    `finding_counts`)."""
    n_critical = row.get("n_critical") or 0
    n_high = row.get("n_high") or 0
    n_medium = row.get("n_medium") or 0
    n_low = row.get("n_low") or 0
    n_info = row.get("n_info") or 0
    exposure = row.get("exposure") or "internal"
    try:
        properties = json.loads(row["metadata"]) if row.get("metadata") else {}
    except (json.JSONDecodeError, TypeError):
        properties = {}
    return {
        "id": row["asset_id"],
        "class": row["asset_type"],
        "cloud": row.get("cloud_provider") or "oci",
        "account_id": row.get("scope_id") or row.get("compartment"),
        "name": row["name"],
        "region": row.get("region"),
        "compartment": row.get("compartment"),
        "exposure": exposure,
        "risk": _compute_risk(n_critical, n_high, n_medium, n_low, exposure),
        "finding_counts": {
            "critical": n_critical, "high": n_high, "medium": n_medium, "low": n_low, "info": n_info,
            "total": row.get("n_total") or 0,
        },
        "scan_status": row.get("scan_status"),
        "last_scanned_at": row.get("updated_at"),
        "properties": properties,
        "profile_id": row.get("profile_id"),
        "profile_name": row.get("profile_name"),
    }


# Sortable columns for v1_list_assets, mapped to their actual SQL
# expressions - never interpolate the `sort` query param directly into SQL.
# `fc`/`exp` are the aliases base_query already LEFT JOINs in below.
_ASSET_SORT_COLUMNS = {
    "name": "a.name",
    "findings": "COALESCE(fc.n_total, 0)",
    "last_scanned": "a.updated_at",
}


def v1_list_assets(
    cloud: Optional[str] = None,
    asset_class: Optional[str] = None,
    exposure: Optional[str] = None,
    severity: Optional[str] = None,
    region: Optional[str] = None,
    account: Optional[str] = None,
    scan_status: Optional[str] = None,
    q: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    sort: Optional[str] = None,
    order: Optional[str] = None,
    profile_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Polymorphic, filtered, paginated asset list. `cursor` is a plain
    stringified offset (a pragmatic simplification of the opaque-cursor
    contract in the design spec - stable enough for this UI's needs without
    inventing a token scheme) - this is also why changing `sort` mid-browse
    is safe: there's no opaque token encoding the old order to invalidate,
    just an offset into whatever ORDER BY is currently active."""
    limit = max(1, min(limit, 500))
    offset = int(cursor) if cursor and cursor.isdigit() else 0

    clauses, params = [], []
    if cloud:
        clauses.append("a.cloud_provider = ?")
        params.append(cloud)
    if asset_class:
        # Comma-separated for a multi-class filter (e.g. a run that scanned
        # several asset families at once) - a single value is just the
        # degenerate one-element case of the same IN clause.
        classes = [c for c in asset_class.split(",") if c]
        clauses.append(f"a.asset_type IN ({','.join('?' * len(classes))})")
        params.extend(classes)
    if region:
        clauses.append("a.region = ?")
        params.append(region)
    if account:
        clauses.append("(a.scope_id = ? OR a.compartment = ?)")
        params.extend([account, account])
    if profile_id:
        clauses.append("a.profile_id = ?")
        params.append(profile_id)
    if engagement_id:
        clauses.append("a.profile_id IN (SELECT profile_id FROM engagement_profiles WHERE engagement_id = ?)")
        params.append(engagement_id)
    if scan_status:
        clauses.append("a.scan_status = ?")
        params.append(scan_status)
    if q:
        clauses.append("(a.name LIKE ? OR a.asset_id LIKE ? OR a.compartment LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if exposure:
        clauses.append("COALESCE(exp.exposure, 'internal') = ?")
        params.append(exposure)
    if severity:
        rank = _SEVERITY_RANK.get(severity.lower())
        if rank:
            clauses.append("COALESCE(fc.max_sev_rank, 0) >= ?")
            params.append(rank)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    findings_sq = _asset_findings_subquery()
    exposure_sq = _asset_exposure_subquery()
    exposure_params = list(_EXPOSURE_CHECK_IDS)

    base_query = f"""
        FROM assets a
        LEFT JOIN ({findings_sq}) fc ON fc.asset_id = a.asset_id
        LEFT JOIN ({exposure_sq}) exp ON exp.asset_id = a.asset_id
        {where}
    """

    sort_col = _ASSET_SORT_COLUMNS.get(sort or "")
    sort_dir = "DESC" if (order or "").lower() == "desc" else "ASC"
    # Default (no/unknown sort) keeps the original grouped-by-type ordering;
    # an explicit sort always keeps a.asset_type, a.name as a stable tie-break.
    order_by = f"ORDER BY {sort_col} {sort_dir}, a.asset_type, a.name" if sort_col else "ORDER BY a.asset_type, a.name"

    with get_connection() as conn:
        total = conn.execute(
            f"WITH {_LATEST_FINDINGS_CTE} SELECT COUNT(*) AS c {base_query}",
            (*exposure_params, *params),
        ).fetchone()["c"]

        rows = conn.execute(
            f"""WITH {_LATEST_FINDINGS_CTE}
                SELECT a.*, fc.n_critical, fc.n_high, fc.n_medium, fc.n_low, fc.n_info, fc.n_total,
                       exp.exposure
                {base_query}
                {order_by}
                LIMIT ? OFFSET ?""",
            (*exposure_params, *params, limit, offset),
        ).fetchall()

    items = [_asset_row_to_v1(dict(r)) for r in rows]
    next_offset = offset + len(items)
    return {
        "items": items,
        "next_cursor": str(next_offset) if next_offset < total else None,
        "total": total,
        "expected_total": total,
        "complete": True,
    }


def v1_get_asset(asset_id: str) -> Optional[Dict]:
    findings_sq = _asset_findings_subquery()
    exposure_sq = _asset_exposure_subquery()
    with get_connection() as conn:
        row = conn.execute(
            f"""WITH {_LATEST_FINDINGS_CTE}
                SELECT a.*, fc.n_critical, fc.n_high, fc.n_medium, fc.n_low, fc.n_info, fc.n_total,
                       exp.exposure
                FROM assets a
                LEFT JOIN ({findings_sq}) fc ON fc.asset_id = a.asset_id
                LEFT JOIN ({exposure_sq}) exp ON exp.asset_id = a.asset_id
                WHERE a.asset_id = ?""",
            (*_EXPOSURE_CHECK_IDS, asset_id),
        ).fetchone()
    return _asset_row_to_v1(dict(row)) if row else None


def _finding_row_to_v1(row: Dict) -> Dict:
    return {
        "id": row["id"],
        "rule_id": row["check_id"],
        "title": row["check_name"],
        "asset_id": row["asset_id"],
        "asset_name": row.get("asset_name"),
        "asset_class": row.get("asset_type"),
        "account": row.get("compartment"),
        "status": row.get("status"),
        "severity": (row.get("severity") or "").lower() or None,
        "description": row.get("message"),
        "remediation": row.get("remediation"),
        "proof_of_concept": poc_templates.render(row.get("check_id"), row),
        "state": row.get("state") or "open",
        "scanned_at": row.get("scanned_at"),
        "first_seen": row.get("first_seen") or row.get("scanned_at"),
    }


def v1_get_asset_findings(asset_id: str) -> List[Dict]:
    with get_connection() as conn:
        rows = conn.execute(
            f"""WITH {_LATEST_FINDINGS_CTE}
               SELECT lf.*, a.name AS asset_name, a.asset_type, a.compartment
               FROM latest_findings lf
               LEFT JOIN assets a ON lf.asset_id = a.asset_id
               WHERE lf.asset_id = ?
               ORDER BY lf.scanned_at DESC""",
            (asset_id,),
        ).fetchall()
    return [_finding_row_to_v1(dict(r)) for r in rows]


def _finding_filter_clauses(
    rule_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    account: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    profile_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> tuple:
    """WHERE-clause builder shared by v1_list_findings and
    v1_list_rule_assets - both query the same latest_findings/assets join."""
    clauses, params = [], []
    if rule_id:
        clauses.append("sr.check_id = ?")
        params.append(rule_id)
    if asset_id:
        clauses.append("sr.asset_id = ?")
        params.append(asset_id)
    if account:
        clauses.append("a.compartment = ?")
        params.append(account)
    if severity:
        clauses.append("UPPER(sr.severity) = ?")
        params.append(severity.upper())
    if state:
        clauses.append("COALESCE(sr.state, 'open') = ?")
        params.append(state)
    if profile_id:
        clauses.append("a.profile_id = ?")
        params.append(profile_id)
    if engagement_id:
        clauses.append("a.profile_id IN (SELECT profile_id FROM engagement_profiles WHERE engagement_id = ?)")
        params.append(engagement_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def v1_list_findings(
    rule_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    account: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    group_by: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    profile_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Findings list, optionally grouped by rule/asset/account (matches the
    Findings screen's "Group by" control). Grouping returns aggregate rows
    (rule_id/title, severity, affected_asset_count) instead of individual
    findings - the UI expands a group to fetch its members via asset_id or
    rule_id filters."""
    limit = max(1, min(limit, 500))
    offset = int(cursor) if cursor and cursor.isdigit() else 0

    where, params = _finding_filter_clauses(rule_id, asset_id, account, severity, state, profile_id, engagement_id)

    with get_connection() as conn:
        if group_by in ("rule", "asset", "account"):
            group_col = {"rule": "sr.check_id", "asset": "sr.asset_id", "account": "a.compartment"}[group_by]
            sev_rank_expr = _SEVERITY_RANK_SQL.replace("severity", "sr.severity")
            rows = conn.execute(
                f"""WITH {_LATEST_FINDINGS_CTE}
                    SELECT {group_col} AS group_key, sr.check_name AS title,
                           MAX({sev_rank_expr}) AS severity_rank, COUNT(DISTINCT sr.asset_id) AS affected_assets,
                           COUNT(*) AS finding_count, MAX(sr.check_id) AS rule_id,
                           MAX(sr.message) AS description, MAX(sr.remediation) AS remediation
                    FROM latest_findings sr
                    LEFT JOIN assets a ON sr.asset_id = a.asset_id
                    {where}
                    GROUP BY {group_col}
                    ORDER BY severity_rank DESC, finding_count DESC
                    LIMIT ? OFFSET ?""",
                (*params, limit, offset),
            ).fetchall()
            total = conn.execute(
                f"""WITH {_LATEST_FINDINGS_CTE}
                    SELECT COUNT(DISTINCT {group_col}) AS c
                    FROM latest_findings sr LEFT JOIN assets a ON sr.asset_id = a.asset_id {where}""",
                params,
            ).fetchone()["c"]
            # Rank -> label, matching _SEVERITY_RANK's mapping (0 = below "low").
            _rank_to_label = {4: "critical", 3: "high", 2: "medium", 1: "low"}
            items = []
            for r in rows:
                d = dict(r)
                d["severity"] = _rank_to_label.get(d.pop("severity_rank", 0))
                items.append(d)
        else:
            rows = conn.execute(
                f"""WITH {_LATEST_FINDINGS_CTE}
                    SELECT sr.*, a.name AS asset_name, a.asset_type, a.compartment
                    FROM latest_findings sr
                    LEFT JOIN assets a ON sr.asset_id = a.asset_id
                    {where}
                    ORDER BY {_SEVERITY_RANK_SQL.replace('severity', 'sr.severity')} DESC, sr.scanned_at DESC
                    LIMIT ? OFFSET ?""",
                (*params, limit, offset),
            ).fetchall()
            total = conn.execute(
                f"""WITH {_LATEST_FINDINGS_CTE}
                    SELECT COUNT(*) AS c
                    FROM latest_findings sr LEFT JOIN assets a ON sr.asset_id = a.asset_id {where}""",
                params,
            ).fetchone()["c"]
            items = [_finding_row_to_v1(dict(r)) for r in rows]

    next_offset = offset + len(items)
    return {
        "items": items,
        "next_cursor": str(next_offset) if next_offset < total else None,
        "total": total,
        "expected_total": total,
        "complete": True,
    }


def v1_list_rule_assets(
    rule_id: str, severity: Optional[str] = None, state: Optional[str] = None
) -> List[Dict]:
    """All assets affected by a rule, uncapped - backs the affected-assets
    .txt download (unlike v1_list_findings, which paginates for interactive
    use)."""
    where, params = _finding_filter_clauses(rule_id=rule_id, severity=severity, state=state)
    with get_connection() as conn:
        rows = conn.execute(
            f"""WITH {_LATEST_FINDINGS_CTE}
                SELECT DISTINCT sr.asset_id, a.name AS asset_name
                FROM latest_findings sr
                LEFT JOIN assets a ON sr.asset_id = a.asset_id
                {where}
                ORDER BY a.name""",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def v1_patch_finding_state(finding_id: int, state: str) -> Optional[Dict]:
    if state not in ("open", "accepted_risk", "resolved"):
        raise ValueError(f"Invalid state '{state}'")
    with get_connection() as conn:
        conn.execute("UPDATE scan_results SET state = ? WHERE id = ?", (state, finding_id))
        conn.commit()
        row = conn.execute(
            """SELECT sr.*, a.name AS asset_name, a.asset_type, a.compartment
               FROM scan_results sr LEFT JOIN assets a ON sr.asset_id = a.asset_id
               WHERE sr.id = ?""",
            (finding_id,),
        ).fetchone()
    return _finding_row_to_v1(dict(row)) if row else None
