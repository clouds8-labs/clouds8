"""
Clouds8 - GCP Collector
Fetches infrastructure data from Google Cloud Platform.

Unlike OCI, a GCP SDK client isn't region-scoped - the same `compute`
client works across all regions/zones, you just pass region/zone as a
request parameter. setup_regional_clients() therefore just remembers the
current region for callers that want it, rather than rebuilding clients
per region the way OCICollector does.

GCP has no "compartment" concept; the closest analogue is a GCP *project*,
so collect_compartment_details() returns GCP projects and every asset's
"compartment" field is a GCP project_id.
"""

import logging
from typing import Any, Dict, List, Optional

from collectors.base_collector import BaseCollector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GCPAuthError(RuntimeError):
    """The service-account key parsed, but GCP itself rejected it (expired/
    revoked key, deleted service account, wrong project, ...) - raised
    instead of being swallowed into an empty project list, so a scan can't
    silently report "0 resources found" when it never actually connected."""


class GCPCollector(BaseCollector):
    """Collector for GCP infrastructure data.

    `profile` is a path to a local service-account JSON key file (GCP has
    no equivalent of OCI's multi-section ~/.oci/config, so there's no
    "section name" to look up - the profile string *is* the credential
    source), matching clouds8's no-stored-credentials philosophy: the key
    file lives on disk, clouds8 only ever stores the path to it.
    """

    PROVIDER = "gcp"

    credentials: Optional[Any]
    clients: Dict[str, Any]
    compartments: List[Dict[str, Any]]
    current_region: Optional[str]

    SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

    def __init__(self, key_path: Optional[str] = None, profile: Optional[str] = None):
        # `profile` is the registry's calling convention (get_collector()
        # always passes config_profile_name as `profile=`); `key_path` lets
        # tests/callers be explicit about intent. Either works.
        self.key_path = key_path or profile
        self.credentials = None
        # Mirrors OCICollector's `.config` (truthy dict once configured) so
        # playbooks can use the same `if self.collector and
        # self.collector.config:` live/mock branch regardless of provider.
        self.config: Optional[Dict[str, Any]] = None
        self.project_id = None
        self.clients = {}
        self.compartments = []
        self.current_region = None
        # The specific reason self.config stayed None, if any - so callers
        # like v1_profiles.py's verify endpoint can show the real failure
        # (e.g. malformed key JSON) instead of a generic "check the file
        # exists" hint when the file exists but is unparsable/invalid.
        self.init_error: Optional[str] = None
        self._initialize()

    def _initialize(self):
        if not self.key_path:
            logger.warning("No GCP service-account key path configured. Using mock data.")
            return
        try:
            from google.oauth2 import service_account
            self.credentials = service_account.Credentials.from_service_account_file(
                self.key_path, scopes=self.SCOPES
            )
            self.project_id = getattr(self.credentials, "project_id", None)
            self._setup_clients()
            if self.credentials:
                self.config = {"project_id": self.project_id, "key_path": self.key_path}
            logger.info(f"GCP Collector initialized from key file: {self.key_path}")
        except ImportError:
            self.init_error = "google-auth/google-api-python-client not installed."
            logger.warning("google-auth/google-api-python-client not installed. Using mock data.")
            self.credentials = None
        except Exception as e:
            self.init_error = str(e)
            logger.warning(f"Could not load GCP service-account key: {e}. Using mock data.")
            self.credentials = None

    def _setup_clients(self):
        if not self.credentials:
            return
        try:
            from googleapiclient.discovery import build
            self.clients = {
                "compute": build("compute", "v1", credentials=self.credentials, cache_discovery=False),
                "storage": build("storage", "v1", credentials=self.credentials, cache_discovery=False),
                "sqladmin": build("sqladmin", "v1", credentials=self.credentials, cache_discovery=False),
                "iam": build("iam", "v1", credentials=self.credentials, cache_discovery=False),
                "cloudresourcemanager": build(
                    "cloudresourcemanager", "v1", credentials=self.credentials, cache_discovery=False
                ),
                "secretmanager": build("secretmanager", "v1", credentials=self.credentials, cache_discovery=False),
                "container": build("container", "v1", credentials=self.credentials, cache_discovery=False),
                "cloudfunctions": build("cloudfunctions", "v2", credentials=self.credentials, cache_discovery=False),
            }
        except Exception as e:
            logger.error(f"Error setting up GCP clients: {e}")
            self.credentials = None

    def get_subscribed_regions(self) -> List[str]:
        """GCP regions the project's Compute API reports as UP."""
        if not self.credentials or "compute" not in self.clients or not self.project_id:
            return []
        try:
            resp = self.clients["compute"].regions().list(project=self.project_id).execute()
            regions = [r["name"] for r in resp.get("items", []) if r.get("status") == "UP"]
            logger.info(f"GCP regions ({len(regions)}): {', '.join(regions)}")
            return regions
        except Exception as e:
            logger.warning(f"Could not list GCP regions: {e}")
            return []

    def setup_regional_clients(self, region: str) -> None:
        """GCP clients aren't region-scoped - just remember the current
        region for scanners that want to pass it as a request param."""
        self.current_region = region

    def collect_compartment_details(self) -> List[Dict]:
        """GCP projects stand in for OCI compartments.

        A service-account key only ever grants access to its own project,
        not org-wide visibility - projects().list() needs the latter
        (resourcemanager.projects.list across the org/folder) and hangs or
        is denied for a normal single-project key. projects().get() on the
        key's own project_id needs only resourcemanager.projects.get,
        which a single-project key does have.
        """
        if not self.credentials or "cloudresourcemanager" not in self.clients or not self.project_id:
            return []
        try:
            p = self.clients["cloudresourcemanager"].projects().get(projectId=self.project_id).execute()
            return [{
                "id": p["projectId"],
                "name": p.get("name", p["projectId"]),
                "description": p.get("name"),
                "lifecycle_state": p.get("lifecycleState"),
                "parent_compartment_id": (p.get("parent") or {}).get("id"),
                # Without this, import_compartments() defaults scope_type
                # to "compartment" (OCI's value) - a GCP project becomes
                # indistinguishable from an OCI compartment in the DB.
                "scope_type": "project",
            }]
        except Exception as e:
            logger.error(f"Error collecting GCP project {self.project_id}: {e}")
            raise GCPAuthError(f"Could not read GCP project '{self.project_id}' with this profile's credentials — {e}") from e

    def _stamp_provider(self, assets: List[Dict]) -> List[Dict]:
        for asset in assets:
            asset.setdefault("cloud_provider", self.PROVIDER)
        return assets

    def collect_all(self, cost_driven: bool = False):
        if not self.credentials:
            logger.info("Using mock data for GCP collection")
            yield self._stamp_provider(self._get_mock_data_assets())
            return

        logger.info("Starting full GCP collection...")

        self.compartments = self.collect_compartment_details()
        logger.info(f"Found {len(self.compartments)} GCP projects")

        regions = self.get_subscribed_regions()
        if regions:
            self.setup_regional_clients(regions[0])

        for proj in self.compartments:
            project_id = proj["id"]
            if proj.get("lifecycle_state") not in (None, "ACTIVE"):
                continue
            try:
                project_assets = []
                project_assets.extend(self._collect_instances(project_id))
                project_assets.extend(self._collect_buckets(project_id))
                project_assets.extend(self._collect_sql_instances(project_id))
                project_assets.extend(self._collect_service_accounts(project_id))
                if project_assets:
                    yield self._stamp_provider(project_assets)
            except Exception as e:
                logger.error(f"Error collecting in project {project_id}: {e}")

        logger.info("Completed GCP collection")

    def _collect_instances(self, project_id: str) -> List[Dict]:
        instances = []
        try:
            resp = self.clients["compute"].instances().aggregatedList(project=project_id).execute()
            for scoped_list in resp.get("items", {}).values():
                for inst in scoped_list.get("instances", []):
                    zone = inst.get("zone", "").rsplit("/", 1)[-1]
                    instances.append({
                        "asset_id": str(inst.get("id")),
                        "asset_type": "gcp_vm",
                        "name": inst.get("name"),
                        "compartment": project_id,
                        "region": zone.rsplit("-", 1)[0] if zone else "unknown",
                        "scan_status": "not_scanned",
                        "metadata": {
                            "machine_type": (inst.get("machineType") or "").rsplit("/", 1)[-1],
                            "status": inst.get("status"),
                            "zone": zone,
                            "network_interfaces": inst.get("networkInterfaces", []),
                            "shielded_vm_config": inst.get("shieldedInstanceConfig"),
                        },
                    })
        except Exception as e:
            logger.debug(f"Error collecting instances in {project_id}: {e}")
        return instances

    def _collect_buckets(self, project_id: str) -> List[Dict]:
        buckets = []
        try:
            resp = self.clients["storage"].buckets().list(project=project_id).execute()
            for b in resp.get("items", []):
                buckets.append({
                    "asset_id": b.get("name"),
                    "asset_type": "gcs_bucket",
                    "name": b.get("name"),
                    "compartment": project_id,
                    "region": (b.get("location") or "unknown").lower(),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "storage_class": b.get("storageClass"),
                        "versioning": (b.get("versioning") or {}).get("enabled", False),
                        "iam_configuration": b.get("iamConfiguration"),
                    },
                })
        except Exception as e:
            logger.debug(f"Error collecting buckets in {project_id}: {e}")
        return buckets

    def _collect_sql_instances(self, project_id: str) -> List[Dict]:
        instances = []
        try:
            resp = self.clients["sqladmin"].instances().list(project=project_id).execute()
            for db in resp.get("items", []):
                instances.append({
                    "asset_id": db.get("name"),
                    "asset_type": "cloudsql_instance",
                    "name": db.get("name"),
                    "compartment": project_id,
                    "region": db.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "database_version": db.get("databaseVersion"),
                        "state": db.get("state"),
                        "ip_addresses": db.get("ipAddresses", []),
                        "settings": {
                            "ip_configuration": (db.get("settings") or {}).get("ipConfiguration"),
                        },
                    },
                })
        except Exception as e:
            logger.debug(f"Error collecting Cloud SQL instances in {project_id}: {e}")
        return instances

    def _collect_service_accounts(self, project_id: str) -> List[Dict]:
        accounts = []
        try:
            name = f"projects/{project_id}"
            resp = self.clients["iam"].projects().serviceAccounts().list(name=name).execute()
            for sa in resp.get("accounts", []):
                accounts.append({
                    "asset_id": sa.get("uniqueId"),
                    "asset_type": "gcp_service_account",
                    "name": sa.get("email"),
                    "compartment": project_id,
                    "region": "global",
                    "scan_status": "not_scanned",
                    "metadata": {
                        "display_name": sa.get("displayName"),
                        "disabled": sa.get("disabled", False),
                    },
                })
        except Exception as e:
            logger.debug(f"Error collecting service accounts in {project_id}: {e}")
        return accounts

    def _get_mock_data_assets(self) -> List[Dict]:
        return [
            {
                "asset_id": "1234567890",
                "asset_type": "gcp_vm",
                "name": "mock-web-server-01",
                "compartment": "mock-project",
                "region": "us-central1",
                "scan_status": "scanned",
                "risk_score": 10,
                "metadata": {"machine_type": "e2-medium", "status": "RUNNING"},
            },
            {
                "asset_id": "mock-public-bucket",
                "asset_type": "gcs_bucket",
                "name": "mock-public-bucket",
                "compartment": "mock-project",
                "region": "us",
                "scan_status": "scanned",
                "risk_score": 80,
                "metadata": {"storage_class": "STANDARD"},
            },
            {
                "asset_id": "mock-sql-1",
                "asset_type": "cloudsql_instance",
                "name": "mock-prod-db",
                "compartment": "mock-project",
                "region": "us-central1",
                "scan_status": "scanned",
                "risk_score": 20,
                "metadata": {"database_version": "POSTGRES_15"},
            },
        ]
