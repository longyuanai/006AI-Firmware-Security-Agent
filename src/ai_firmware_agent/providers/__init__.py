"""Optional external-tool providers used by the static scan pipeline."""

from ai_firmware_agent.providers.base import (
    InventoryProvider,
    InventoryResult,
    ToolCapability,
)
from ai_firmware_agent.providers.inventory import (
    CVEBinaryInventoryProvider,
    SyftInventoryProvider,
    collect_inventory,
    merge_components,
)
from ai_firmware_agent.providers.unblob import UnblobRunner

__all__ = [
    "CVEBinaryInventoryProvider",
    "InventoryProvider",
    "InventoryResult",
    "SyftInventoryProvider",
    "ToolCapability",
    "UnblobRunner",
    "collect_inventory",
    "merge_components",
]
