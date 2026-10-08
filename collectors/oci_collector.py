"""
Clouds8 - OCI Collector
Fetches infrastructure data from Oracle Cloud Infrastructure
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Maps OCI billing service names → internal collector method suffixes.
# When cost-driven scanning is enabled, only services appearing in the
# cost report will have their collector methods called.
OCI_SERVICE_MAP: Dict[str, Dict[str, Any]] = {
    "COMPUTE":          {"methods": ["instances"],                "label": "Compute",          "icon": "fa-server"},
    "BLOCK_STORAGE":    {"methods": ["instances"],                "label": "Block Storage",    "icon": "fa-hdd"},
    "OBJECT_STORAGE":   {"methods": ["buckets"],                  "label": "Object Storage",   "icon": "fa-bucket"},
    "NETWORKING":       {"methods": ["vcns", "subnets",
                                     "network_security_groups",
                                     "security_lists"],           "label": "Networking",       "icon": "fa-network-wired"},
    "LOAD_BALANCER":    {"methods": ["load_balancers"],            "label": "Load Balancer",    "icon": "fa-balance-scale"},
    "DATABASE":         {"methods": ["autonomous_databases"],     "label": "Database",         "icon": "fa-database"},
    "VAULT":            {"methods": [],                           "label": "Vault / KMS",      "icon": "fa-key"},
    "IDENTITY":         {"methods": [],                           "label": "Identity (IAM)",   "icon": "fa-users-cog"},
    "LOGGING":          {"methods": [],                           "label": "Logging",          "icon": "fa-file-alt"},
    "FUNCTIONS":        {"methods": [],                           "label": "Functions",        "icon": "fa-code"},
    "CONTAINER_ENGINE": {"methods": [],                           "label": "Kubernetes (OKE)", "icon": "fa-dharmachakra"},
    "API_GATEWAY":      {"methods": [],                           "label": "API Gateway",      "icon": "fa-door-open"},
}


from collectors.base_collector import BaseCollector


class OCICollector(BaseCollector):
    """Collector for OCI infrastructure data"""

    PROVIDER = "oci"

    config: Optional[Dict[str, Any]]
    clients: Dict[str, Any]
    compartments: List[Dict[str, Any]]
    subscribed_regions: List[str]
    active_services: Dict[str, float]  # {service: cost} from billing
    
    def __init__(self, config_path: Optional[str] = None, profile: str = "DEFAULT"):
        self.config_path = config_path or os.path.expanduser("~/.oci/config")
        self.profile = profile
        self.config = None
        self.clients = {}
        self.compartments = []  # Cache for compartments
        self.subscribed_regions = []  # Populated at collection time
        self.active_services = {}     # Populated by cost API
        # The specific reason self.config stayed None, if any - so callers
        # like v1_profiles.py's verify endpoint can show the real failure
        # instead of a generic "check the file exists" hint.
        self.init_error = None
        self._initialize()

    def _initialize(self):
        """Initialize OCI clients"""
        try:
            import oci
            self.config = oci.config.from_file(self.config_path, self.profile)
            self._setup_clients()
            logger.info(f"OCI Collector initialized with profile: {self.profile}")
        except ImportError:
            self.init_error = "OCI SDK not installed."
            logger.warning("OCI SDK not installed. Using mock data.")
            self.config = None
        except Exception as e:
            self.init_error = str(e)
            logger.warning(f"Could not load OCI config: {e}. Using mock data.")
            self.config = None
    
    def _setup_clients(self):
        """Setup OCI service clients"""
        if not self.config:
            return
            
        import oci
        try:
            self.clients = {
                "identity": oci.identity.IdentityClient(self.config),
                "compute": oci.core.ComputeClient(self.config),
                "block_storage": oci.core.BlockstorageClient(self.config),
                "network": oci.core.VirtualNetworkClient(self.config),
                "object_storage": oci.object_storage.ObjectStorageClient(self.config),
                "database": oci.database.DatabaseClient(self.config),
                "load_balancer": oci.load_balancer.LoadBalancerClient(self.config),
                "kms_vault": oci.key_management.KmsVaultClient(self.config),
                "secrets": oci.vault.VaultsClient(self.config),
                "secrets_read": oci.secrets.SecretsClient(self.config),
                "usage_api": oci.usage_api.UsageapiClient(self.config),
                "container_engine": oci.container_engine.ContainerEngineClient(self.config),
                "functions_management": oci.functions.FunctionsManagementClient(self.config),
            }

            # Increase connection pool for parallel scanning workloads
            # Default pool_maxsize=10 is too small for concurrent operations
            try:
                import requests.adapters
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=50,
                    pool_maxsize=50,
                )
                for client in self.clients.values():
                    if hasattr(client, "base_client") and hasattr(client.base_client, "session"):
                        client.base_client.session.mount("https://", adapter)
                logger.debug("Connection pool increased to 50 for all OCI clients")
            except Exception:
                pass  # non-critical — pool warnings are harmless

        except Exception as e:
            logger.error(f"Error setting up OCI clients: {e}")
            self.config = None
    
    def get_subscribed_regions(self) -> List[str]:
        """Discover all regions the tenancy is subscribed to."""
        if not self.config or "identity" not in self.clients:
            return []
        try:
            tenancy_id = self.config.get("tenancy")
            if not tenancy_id:
                return []
            subs = self.clients["identity"].list_region_subscriptions(tenancy_id).data
            regions = [r.region_name for r in subs if r.status == "READY"]
            logger.info(f"Subscribed regions ({len(regions)}): {', '.join(regions)}")
            return regions
        except Exception as e:
            logger.warning(f"Could not list subscribed regions: {e}")
            # Fall back to home region from config
            home = self.config.get("region")
            return [home] if home else []

    def setup_regional_clients(self, region: str):
        """Re-create service clients targeting a specific region."""
        if not self.config:
            return
        import oci
        self.config["region"] = region
        regional_config = dict(self.config)
        try:
            self.clients["compute"] = oci.core.ComputeClient(regional_config)
            self.clients["block_storage"] = oci.core.BlockstorageClient(regional_config)
            self.clients["network"] = oci.core.VirtualNetworkClient(regional_config)
            self.clients["object_storage"] = oci.object_storage.ObjectStorageClient(regional_config)
            self.clients["database"] = oci.database.DatabaseClient(regional_config)
            self.clients["load_balancer"] = oci.load_balancer.LoadBalancerClient(regional_config)
            self.clients["kms_vault"] = oci.key_management.KmsVaultClient(regional_config)
            self.clients["secrets"] = oci.vault.VaultsClient(regional_config)
            self.clients["secrets_read"] = oci.secrets.SecretsClient(regional_config)
            self.clients["container_engine"] = oci.container_engine.ContainerEngineClient(regional_config)
            self.clients["functions_management"] = oci.functions.FunctionsManagementClient(regional_config)
            # Bump connection pool for the new clients
            try:
                import requests.adapters
                adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
                for key, client in self.clients.items():
                    if key == "identity":
                        continue  # identity client stays on home region
                    if hasattr(client, "base_client") and hasattr(client.base_client, "session"):
                        client.base_client.session.mount("https://", adapter)
            except Exception:
                pass
            logger.debug(f"Regional clients ready for {region}")
        except Exception as e:
            logger.error(f"Error setting up regional clients for {region}: {e}")

    def _get_active_services_from_cost(self, lookback_days: int = 30) -> Dict[str, float]:
        """Query OCI Usage API to discover services generating costs.

        Returns a dict mapping OCI service names to their total cost
        over the lookback period (e.g. {"COMPUTE": 142.5, "OBJECT_STORAGE": 8.3}).
        """
        if not self.config or "usage_api" not in self.clients:
            return {}

        try:
            import oci
            tenancy_id = self.config.get("tenancy")
            if not tenancy_id:
                return {}

            now = datetime.utcnow()
            start = now - timedelta(days=lookback_days)

            request = oci.usage_api.models.RequestSummarizedUsagesDetails(
                tenant_id=tenancy_id,
                time_usage_started=start.strftime("%Y-%m-%dT00:00:00Z"),
                time_usage_ended=now.strftime("%Y-%m-%dT00:00:00Z"),
                granularity="MONTHLY",
                query_type="COST",
                group_by=["service"],
            )

            resp = self.clients["usage_api"].request_summarized_usages(request).data
            services: Dict[str, float] = {}
            for item in resp.items:
                svc = getattr(item, "service", None)
                cost = getattr(item, "computed_amount", 0) or 0
                if svc:
                    services[svc.upper()] = services.get(svc.upper(), 0) + float(cost)

            # Sort by cost descending
            services = dict(sorted(services.items(), key=lambda x: x[1], reverse=True))
            logger.info(
                f"Cost API: {len(services)} active services (last {lookback_days}d) — "
                f"top spenders: {', '.join(f'{k} ${v:.2f}' for k, v in list(services.items())[:5])}"
            )
            return services

        except Exception as e:
            logger.warning(f"Could not query Usage/Cost API: {e}")
            return {}

    def _get_scan_methods_for_active_services(self) -> Optional[set]:
        """Return the set of collector method suffixes to run based on cost data.

        Returns None if cost data is unavailable (scan everything),
        or a set like {"instances", "buckets", "vcns", ...}.
        """
        if not self.active_services:
            return None  # No cost data → scan everything

        methods: set = set()
        for svc_name in self.active_services:
            mapping = OCI_SERVICE_MAP.get(svc_name)
            if mapping and mapping["methods"]:
                methods.update(mapping["methods"])

        if not methods:
            return None  # Couldn't map any → scan everything

        logger.info(f"Cost-driven scan focus: {', '.join(sorted(methods))}")
        return methods

    def _stamp_provider(self, assets: List[Dict]) -> List[Dict]:
        """Tag each asset with this collector's cloud_provider identifier."""
        for asset in assets:
            asset.setdefault("cloud_provider", self.PROVIDER)
        return assets

    def collect_all(self, cost_driven: bool = False):
        """
        Collect all resources from OCI and normalize to standard asset format.
        Iterates over every subscribed region for full attack surface coverage.

        Args:
            cost_driven: When True, queries the OCI Usage/Cost API first and
                         only scans services that are generating bills.
        Yields batches of assets as they are collected.
        """
        config = self.config
        if not config:
            logger.info("Using mock data for collection")
            yield self._stamp_provider(self._get_mock_data_assets())
            return

        logger.info("Starting full OCI collection...")
        
        # 1. Collect Compartments (Foundation — global, region-independent)
        self.compartments = self.collect_compartment_details()
        logger.info(f"Found {len(self.compartments)} compartments")
        
        tenancy_id = config.get("tenancy")
        if not tenancy_id:
             logger.error("No tenancy ID found in config")
             return

        # 1b. (Optional) Query billing to focus scans
        focus_methods = None
        if cost_driven:
            logger.info("Cost-driven mode enabled — querying Usage API...")
            self.active_services = self._get_active_services_from_cost()
            focus_methods = self._get_scan_methods_for_active_services()
            # Persist cost data to DB for dashboard display
            if self.active_services:
                try:
                    from db.database import upsert_service_costs
                    scannable_names = {k for k, v in OCI_SERVICE_MAP.items() if v["methods"]}
                    upsert_service_costs(self.active_services, scannable_names)
                    logger.info(f"Persisted cost data for {len(self.active_services)} services")
                except Exception as e:
                    logger.warning(f"Could not persist cost data: {e}")

        # 2. Global Resources (IAM — not region-scoped)
        global_assets = []
        global_assets.extend(self._collect_users())
        global_assets.extend(self._collect_groups())
        global_assets.extend(self._collect_policies())
        if global_assets:
            yield self._stamp_provider(global_assets)

        # 3. Discover subscribed regions
        self.subscribed_regions = self.get_subscribed_regions()
        if not self.subscribed_regions:
            logger.warning("No subscribed regions found — falling back to home region")
            self.subscribed_regions = [config.get("region", "us-phoenix-1")]

        # 4. Sweep regional resources across every subscribed region
        # Helper: should we scan this collector method?
        def _should_scan(method_suffix: str) -> bool:
            return focus_methods is None or method_suffix in focus_methods

        for region in self.subscribed_regions:
            logger.info(f"▸ Scanning region: {region}")
            self.setup_regional_clients(region)

            for i, comp in enumerate(self.compartments):
                comp_id = comp['id']
                comp_name = comp['name']

                if comp.get('lifecycle_state') != 'ACTIVE':
                    continue

                try:
                    compartment_assets = []
                    if _should_scan("instances"):
                        compartment_assets.extend(self._collect_instances(comp_id, comp_name))
                    if _should_scan("vcns"):
                        compartment_assets.extend(self._collect_vcns(comp_id, comp_name, region))
                    if _should_scan("subnets"):
                        compartment_assets.extend(self._collect_subnets(comp_id, comp_name, region))
                    if _should_scan("network_security_groups"):
                        compartment_assets.extend(self._collect_network_security_groups(comp_id, comp_name, region))
                    if _should_scan("security_lists"):
                        compartment_assets.extend(self._collect_security_lists(comp_id, comp_name, region))
                    if _should_scan("buckets"):
                        compartment_assets.extend(self._collect_buckets(comp_id, comp_name, region))
                    if _should_scan("load_balancers"):
                        compartment_assets.extend(self._collect_load_balancers(comp_id, comp_name, region))
                    if _should_scan("autonomous_databases"):
                        compartment_assets.extend(self._collect_autonomous_databases(comp_id, comp_name, region))

                    if compartment_assets:
                        yield self._stamp_provider(compartment_assets)

                    if (i + 1) % 10 == 0:
                        logger.info(f"  [{region}] Processed {i + 1}/{len(self.compartments)} compartments")

                except Exception as e:
                    logger.error(f"Error collecting in {comp_name} / {region}: {e}")

            logger.info(f"✓ Completed region: {region}")


    def collect_compartment_details(self) -> List[Dict]:
        """Collect raw compartment hierarchy"""
        config = self.config
        if not config:
            return []
        
        # Check for identity client
        if "identity" not in self.clients:
            logger.error("Identity client not initialized")
            return []

        client = self.clients["identity"]
        tenancy_id = config.get("tenancy")
        if not tenancy_id:
             logger.error("Tenancy ID missing from config")
             return []
        
        compartments = []
        try:
            # Add root compartment
            root_comp = client.get_compartment(tenancy_id).data
            compartments.append({
                "id": root_comp.id,
                "name": root_comp.name,
                "description": root_comp.description,
                "lifecycle_state": root_comp.lifecycle_state,
                "parent_compartment_id": None
            })
            
            # Add sub compartments
            import oci
            all_comps = oci.pagination.list_call_get_all_results(
                client.list_compartments, tenancy_id,
                compartment_id_in_subtree=True, access_level="ACCESSIBLE"
            ).data
            for comp in all_comps:
                compartments.append({
                    "id": comp.id,
                    "name": comp.name,
                    "description": comp.description,
                    "lifecycle_state": comp.lifecycle_state,
                    "parent_compartment_id": comp.compartment_id
                })
        except Exception as e:
            logger.error(f"Error collecting compartments: {e}")
            
        return compartments

    def _collect_users(self) -> List[Dict]:
        """Collect IAM users"""
        users = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            import oci
            all_users = oci.pagination.list_call_get_all_results(
                client.list_users, tenancy_id
            ).data
            
            for user in all_users:
                users.append({
                    "asset_id": user.id,
                    "asset_type": "user",
                    "name": user.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "email": user.email,
                        "lifecycle_state": user.lifecycle_state,
                        "is_mfa_activated": getattr(user, "is_mfa_activated", False),
                        "time_created": str(user.time_created)
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting users: {e}")
        return users

    def _collect_groups(self) -> List[Dict]:
        groups = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            import oci
            all_groups = oci.pagination.list_call_get_all_results(
                client.list_groups, tenancy_id
            ).data
            for group in all_groups:
                groups.append({
                    "asset_id": group.id,
                    "asset_type": "group",
                    "name": group.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "description": group.description,
                        "time_created": str(group.time_created)
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting groups: {e}")
        return groups

    def _collect_policies(self) -> List[Dict]:
        policies = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            import oci
            all_policies = oci.pagination.list_call_get_all_results(
                client.list_policies, tenancy_id
            ).data
            for policy in all_policies:
                policies.append({
                    "asset_id": policy.id,
                    "asset_type": "policy",
                    "name": policy.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "scanned", # Policies are text, easy to scan
                    "metadata": {
                        "statements": policy.statements,
                        "description": policy.description,
                        "version_date": str(policy.version_date) if policy.version_date else None
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting policies: {e}")
        return policies

    def _collect_instances(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        instances = []
        try:
            client = self.clients["compute"]
            import oci
            all_instances = oci.pagination.list_call_get_all_results(
                client.list_instances, compartment_id
            ).data
            for inst in all_instances:
                # Get primary vnic for IP address (simplified)
                instances.append({
                    "asset_id": inst.id,
                    "asset_type": "vm",
                    "name": inst.display_name,
                    "compartment": compartment_name,
                    "region": inst.region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "shape": inst.shape,
                        "lifecycle_state": inst.lifecycle_state,
                        "availability_domain": inst.availability_domain,
                        "time_created": str(inst.time_created)
                    }
                })
        except Exception as e:
            # Specific compartments might fail, log debug
            logger.debug(f"Error collecting instances in {compartment_name}: {e}")
        return instances

    def _collect_vcns(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            import oci
            all_vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id
            ).data
            for vcn in all_vcns:
                assets.append({
                    "asset_id": vcn.id,
                    "asset_type": "vcn",
                    "name": vcn.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "cidr_block": vcn.cidr_block,
                        "dns_label": vcn.dns_label,
                        "lifecycle_state": vcn.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_subnets(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            import oci
            all_subnets = oci.pagination.list_call_get_all_results(
                client.list_subnets, compartment_id
            ).data
            for subnet in all_subnets:
                assets.append({
                    "asset_id": subnet.id,
                    "asset_type": "subnet",
                    "name": subnet.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "cidr_block": subnet.cidr_block,
                        "vcn_id": subnet.vcn_id,
                        "prohibit_public_ip_on_vnic": subnet.prohibit_public_ip_on_vnic,
                        "lifecycle_state": subnet.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets
    
    def _collect_network_security_groups(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            import oci
            all_nsgs = oci.pagination.list_call_get_all_results(
                client.list_network_security_groups, compartment_id
            ).data
            for nsg in all_nsgs:
                assets.append({
                    "asset_id": nsg.id,
                    "asset_type": "nsg",
                    "name": nsg.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "vcn_id": nsg.vcn_id,
                        "lifecycle_state": nsg.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_security_lists(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            import oci
            all_sls = oci.pagination.list_call_get_all_results(
                client.list_security_lists, compartment_id
            ).data
            for sl in all_sls:
                assets.append({
                    "asset_id": sl.id,
                    "asset_type": "security_list",
                    "name": sl.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "vcn_id": sl.vcn_id,
                        "lifecycle_state": sl.lifecycle_state,
                        "ingress_description": f"{len(sl.ingress_security_rules)} rules",
                        "egress_description": f"{len(sl.egress_security_rules)} rules"
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_buckets(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["object_storage"]
            namespace = client.get_namespace().data
            import oci
            all_buckets = oci.pagination.list_call_get_all_results(
                client.list_buckets, namespace, compartment_id
            ).data
            for bucket in all_buckets:
                assets.append({
                    "asset_id": bucket.name, # Buckets don't always have OCIDs in list response, name is unique in namespace
                    "asset_type": "bucket",
                    "name": bucket.name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "namespace": namespace,
                        "time_created": str(bucket.time_created),
                        "public_access_type": "unknown" # Need get_bucket to verify public access
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_load_balancers(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        assets = []
        try:
            client = self.clients["load_balancer"]
            import oci
            all_lbs = oci.pagination.list_call_get_all_results(
                client.list_load_balancers, compartment_id
            ).data
            for lb in all_lbs:
                assets.append({
                    "asset_id": lb.id,
                    "asset_type": "lb",
                    "name": lb.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "shape_name": lb.shape_name,
                        "is_private": lb.is_private,
                        "lifecycle_state": lb.lifecycle_state,
                        "ip_addresses": [ip.ip_address for ip in lb.ip_addresses]
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_autonomous_databases(self, compartment_id: str, compartment_name: str, region: str = "unknown") -> List[Dict]:
        """Collect Autonomous Databases in a compartment."""
        assets = []
        try:
            client = self.clients["database"]
            import oci
            all_adbs = oci.pagination.list_call_get_all_results(
                client.list_autonomous_databases, compartment_id
            ).data
            for db in all_adbs:
                assets.append({
                    "asset_id": db.id,
                    "asset_type": "adb",
                    "name": db.display_name,
                    "compartment": compartment_name,
                    "region": region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "db_name": getattr(db, "db_name", ""),
                        "db_workload": getattr(db, "db_workload", ""),
                        "lifecycle_state": db.lifecycle_state,
                        "is_free_tier": getattr(db, "is_free_tier", False),
                        "is_dedicated": getattr(db, "is_dedicated", False),
                        "is_mtls_connection_required": getattr(db, "is_mtls_connection_required", None),
                        "is_auto_scaling_enabled": getattr(db, "is_auto_scaling_enabled", False),
                        "cpu_core_count": getattr(db, "cpu_core_count", None),
                        "data_storage_size_in_tbs": getattr(db, "data_storage_size_in_tbs", None),
                        "time_created": str(getattr(db, "time_created", "")),
                        "whitelisted_ips": getattr(db, "whitelisted_ips", None),
                        "subnet_id": getattr(db, "subnet_id", None),
                        "nsg_ids": getattr(db, "nsg_ids", None),
                    }
                })
        except Exception as e:
            logger.debug(f"Error collecting autonomous databases in {compartment_name}: {e}")
        return assets

    def _get_mock_data_assets(self) -> List[Dict]:
        """Return mock data compatible with the database schema"""
        # Create some realistic mock data for visualization
        assets = []
        
        # 1. Compartment Structure
        # Root -> Prod -> Net, App
        # Root -> Dev
        
        # 2. Add some VMs
        assets.append({
            "asset_id": "ocid1.instance.oc1.phx.mock1",
            "asset_type": "vm",
            "name": "prod-web-server-01",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 10,
            "metadata": {"shape": "VM.Standard2.1", "public_ip": "140.2.1.1"}
        })
        assets.append({
            "asset_id": "ocid1.instance.oc1.phx.mock2",
            "asset_type": "vm",
            "name": "prod-db-server-01",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 5,
            "metadata": {"shape": "VM.Standard2.4", "public_ip": None}
        })
        
        # 3. Add Buckets
        assets.append({
            "asset_id": "mock-bucket-public",
            "asset_type": "bucket",
            "name": "public-assets-bucket",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 80,
            "metadata": {"public_access": "ObjectRead", "namespace": "test-ns"}
        })
        
        # 4. IAM Policies
        assets.append({
            "asset_id": "ocid1.policy.oc1..mock1",
            "asset_type": "policy",
            "name": "Manage-All-Policy",
            "compartment": "root",
            "region": "global",
            "scan_status": "scanned",
            "risk_score": 90,
            "metadata": {"statements": ["Allow group Administrators to manage all-resources in tenancy"]}
        })
        
        # Fill in more mock data to match the UI screenshots
        for i in range(5):
             assets.append({
                "asset_id": f"ocid1.vnic.oc1.phx.mock{i}",
                "asset_type": "vnic",
                "name": f"primary-vnic-{i}",
                "compartment": "FSC_HCP_systems_DevTest",
                "region": "us-phoenix-1",
                "scan_status": "scanned",
                "metadata": {"public_ip": f"129.1.{i}.1"}
            })
            
        return assets
