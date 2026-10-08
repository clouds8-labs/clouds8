"""
Clouds8 - Abstract Base Collector
All cloud provider collectors must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional


class BaseCollector(ABC):
    """Common interface for all cloud provider collectors.

    Subclasses set PROVIDER to a lowercase string identifier (e.g. "oci", "aws")
    and implement collect_all().

    After collect_all() runs, `self.compartments` holds the list of collected
    compartment / account / subscription dicts for that provider.

    Every asset dict yielded by collect_all() must include:
        asset_id, asset_type, name, compartment, region, metadata,
        risk_score, cloud_provider

    Scanners (playbooks/) that need to call the provider SDK directly (for
    checks collect_all() doesn't cover) should go through get_client() and
    the methods below rather than reaching into a collector subclass's own
    attributes/private methods - that's what makes it possible to port a
    scanner to a new provider by swapping which collector it's handed,
    instead of re-deriving that provider's internals from scratch.
    """

    PROVIDER: str = ""
    compartments: List[Dict]  # populated during collect_all()
    clients: Dict[str, Any]  # logical service name -> provider SDK client, populated by subclasses

    @abstractmethod
    def collect_all(self, cost_driven: bool = False) -> Iterator[List[Dict]]:
        """Yield batches of normalized asset dicts from the cloud provider."""
        ...

    def get_client(self, service_name: str) -> Optional[Any]:
        """Return the provider SDK client for a logical service name
        (e.g. "object_storage", "compute", "identity", "kms_vault").
        Returns None if that service isn't configured/available."""
        return getattr(self, "clients", {}).get(service_name)

    def get_subscribed_regions(self) -> List[str]:
        """Return the regions this provider account/tenancy is active in."""
        raise NotImplementedError

    def collect_compartment_details(self) -> List[Dict]:
        """Return this provider's account/compartment/subscription/resource-group hierarchy."""
        raise NotImplementedError

    def setup_regional_clients(self, region: str) -> None:
        """Point self.clients at SDK clients scoped to `region`. Required
        before per-region scanning via get_client()."""
        raise NotImplementedError
