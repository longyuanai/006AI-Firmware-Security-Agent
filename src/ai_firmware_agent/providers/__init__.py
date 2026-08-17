"""Optional external-tool providers used by the static scan pipeline."""

from ai_firmware_agent.providers.base import (
    InventoryProvider,
    InventoryResult,
    ToolCapability,
)
from ai_firmware_agent.providers.emba import (
    EmbaImportError,
    EmbaMissingFieldError,
    EmbaParseError,
    EmbaReport,
    EmbaSchemaError,
    EmbaUnsupportedVersionError,
    emba_report_to_envelope,
    import_emba_path_to_envelope,
    load_emba_report,
    parse_emba_report,
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
    "EmbaImportError",
    "EmbaMissingFieldError",
    "EmbaParseError",
    "EmbaReport",
    "EmbaSchemaError",
    "EmbaUnsupportedVersionError",
    "InventoryProvider",
    "InventoryResult",
    "SyftInventoryProvider",
    "ToolCapability",
    "UnblobRunner",
    "collect_inventory",
    "emba_report_to_envelope",
    "import_emba_path_to_envelope",
    "load_emba_report",
    "merge_components",
    "parse_emba_report",
]
