"""AI-Firmware-Security-Agent: SBOM + CVE matching for IoT firmware.

PoC scope: parses a small synthetic firmware (tar.gz with a manifest.yml),
extracts a component inventory, looks each component up against a tiny
local mock CVE database, then asks the LLM (via shared-llm-core) for a
business-language risk narrative.
"""

from ai_firmware_agent.analyzer import enrich_top_components, ComponentNarrative
from ai_firmware_agent.adapter import FirmwareProductAdapter
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

__version__ = "0.1.0"

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
