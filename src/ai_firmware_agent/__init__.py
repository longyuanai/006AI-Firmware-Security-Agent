"""AI-Firmware-Security-Agent: SBOM + CVE matching for IoT firmware.

PoC scope: parses a small synthetic firmware (tar.gz with a manifest.yml),
extracts a component inventory, looks each component up against a tiny
local mock CVE database, then asks the LLM (via shared-llm-core) for a
business-language risk narrative.
"""

from ai_firmware_agent.analyzer import enrich_top_components, ComponentNarrative
from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import parse_firmware
from ai_firmware_agent.reporter import render_markdown

__version__ = "0.1.0"

__all__ = [
    "Component",
    "ComponentNarrative",
    "CveRecord",
    "enrich_top_components",
    "mock_lookup",
    "parse_firmware",
    "render_markdown",
    "__version__",
]