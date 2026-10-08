"""
Clouds8 Backend API - sync execution

The actual "collect from a cloud provider and import into the DB service"
logic. Used in-process by routers/system.py's POST /sync (backed by the
persisted jobs table), and is the thing the root sync.py CLI script now
triggers over HTTP instead of running itself - previously sync.py ran this
same logic directly, which meant a `python sync.py` invocation and an
API-triggered sync were two independent, untracked code paths that could
race each other. Now there is exactly one place this runs.

The old file-based .sync_lock mutual-exclusion is dropped: it existed to
guard against concurrent uncoordinated SQLite writers, which Phase 2
already fixed architecturally (the DB service is the sole writer, with
WAL mode). Concurrent sync jobs are no longer unsafe, just potentially
redundant - same as scans, which never had a lock.
"""
import logging

from collectors.registry import get_collector
from db.database import get_active_profile, import_assets, import_compartments, init_database

logger = logging.getLogger("Clouds8-BackendAPI")


def sync(cost_driven: bool = False, provider: str = "oci") -> dict:
    """Run the synchronization process for a given cloud provider.

    Args:
        cost_driven: When True, query the provider's Usage/Cost API first and
                     only scan services that are generating bills.
        provider:    Cloud provider key registered in collectors/registry.py
                     (e.g. "oci", "aws"). Defaults to "oci".

    Returns:
        Dict of aggregate sync statistics.
    """
    total_stats = {
        'total': 0,
        'imported': 0,
        'updated': 0,
        'errors': 0,
        'by_type': {},
        'provider': provider,
    }

    try:
        init_database()

        logger.info(f"Starting {provider.upper()} collection...")
        if cost_driven:
            logger.info("Cost-driven scan mode — only active billing services will be scanned")

        config_profile_name = None
        try:
            active_profile = get_active_profile(provider)
            if active_profile:
                config_profile_name = active_profile.get("config_profile_name")
        except Exception as e:
            logger.warning(f"Could not look up active profile for '{provider}': {e} — using provider default")
        collector = get_collector(provider, config_profile_name=config_profile_name)

        asset_generator = collector.collect_all(cost_driven=cost_driven)

        for batch in asset_generator:
            if collector.compartments and total_stats['total'] == 0:
                logger.info(f"Importing {len(collector.compartments)} compartments...")
                import_compartments(collector.compartments)

            if not batch:
                continue

            logger.info(f"Importing batch of {len(batch)} assets...")
            stats = import_assets(batch, source_description=f"{provider.upper()} API Sync")

            total_stats['total'] += stats['total']
            total_stats['imported'] += stats['imported']
            total_stats['updated'] += stats['updated']
            total_stats['errors'] += stats['errors']

            for atype, count in stats['by_type'].items():
                total_stats['by_type'][atype] = total_stats['by_type'].get(atype, 0) + count

    except Exception as e:
        logger.error(f"Error during synchronization: {e}")
        total_stats['error'] = str(e)

    logger.info("Sync complete!")
    logger.info(f"Total Stats: {total_stats}")
    return total_stats
