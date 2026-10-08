"""
Clouds8 - Collector Registry
Maps cloud provider names to their collector classes.
Register new providers here as they are implemented.
"""

from collectors.base_collector import BaseCollector
from collectors.oci_collector import OCICollector
from collectors.gcp_collector import GCPCollector

REGISTRY: dict[str, type[BaseCollector]] = {
    "oci": OCICollector,
    "gcp": GCPCollector,
    # "aws": AWSCollector,    # add when implemented
    # "azure": AzureCollector,
}


def get_collector(provider: str, config_profile_name: str = None) -> BaseCollector:
    """Instantiate and return the collector for the given cloud provider.

    `config_profile_name` is the named section of that provider's local SDK
    config file to use (e.g. the `[SECTION]` in ~/.oci/config for OCI) -
    when omitted, falls back to the collector class's own default (today,
    OCICollector's "DEFAULT"). Every collector class registered here must
    accept a `profile: str` constructor kwarg, matching OCICollector's
    existing shape.
    """
    cls = REGISTRY.get(provider.lower())
    if not cls:
        available = list(REGISTRY.keys())
        raise ValueError(
            f"Unknown cloud provider '{provider}'. Available: {available}"
        )
    if config_profile_name:
        return cls(profile=config_profile_name)
    return cls()


def list_providers() -> list[str]:
    """Return all registered provider names."""
    return list(REGISTRY.keys())
