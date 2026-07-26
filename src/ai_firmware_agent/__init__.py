"""AI-Firmware-Security-Agent: SBOM + CVE matching for IoT firmware.

PoC scope: parses a small synthetic firmware (tar.gz with a manifest.yml),
extracts a component inventory, looks each component up against a tiny
local mock CVE database, then asks the LLM (via shared-llm-core) for a
business-language risk narrative.
"""

from typing import TYPE_CHECKING, Any

from ai_firmware_agent._version import __version__
from ai_firmware_agent.analyzer import enrich_top_components, ComponentNarrative
from ai_firmware_agent.attack_chain import AttackChain, reconstruct_attack_chain
from ai_firmware_agent.charts import render_vulnerability_pie
from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.eps import epss_lookup
from ai_firmware_agent.emulator import EmulationResult, emulate_firmware
from ai_firmware_agent.kev import kev_lookup
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.nvd import nvd_lookup
from ai_firmware_agent.parsers import parse_firmware
from ai_firmware_agent.reporter import render_markdown
from ai_firmware_agent.scoring import PRiskScore, rank_matches, score_component
from ai_firmware_agent.unpack import FirmwareUnpackError, unpack_firmware
from ai_firmware_agent.zeroday import KnownCvePattern, predict_zero_days

if TYPE_CHECKING:
    from ai_firmware_agent.adapter import FirmwareProductAdapter


def __getattr__(name: str) -> Any:
    """Load the section 10 adapter lazily.

    ``adapter`` is the one module that needs the shared gateway layer. Import
    it eagerly and a shared-core build without that layer breaks every import
    of this package, including the CLI, which does not use the adapter at all.
    """
    if name == "FirmwareProductAdapter":
        from ai_firmware_agent.adapter import FirmwareProductAdapter

        return FirmwareProductAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Component",
    "ComponentNarrative",
    "CveRecord",
    "AttackChain",
    "EmulationResult",
    "FirmwareUnpackError",
    "FirmwareProductAdapter",
    "KnownCvePattern",
    "PRiskScore",
    "enrich_top_components",
    "emulate_firmware",
    "epss_lookup",
    "kev_lookup",
    "mock_lookup",
    "nvd_lookup",
    "parse_firmware",
    "predict_zero_days",
    "render_markdown",
    "rank_matches",
    "reconstruct_attack_chain",
    "render_vulnerability_pie",
    "score_component",
    "unpack_firmware",
    "__version__",
]
