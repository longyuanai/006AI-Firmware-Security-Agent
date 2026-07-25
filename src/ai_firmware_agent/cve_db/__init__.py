"""Embedded CVE database plus the frozen deterministic mock lookup."""

from ai_firmware_agent.cve_db.mock import CveRecord, mock_lookup
from ai_firmware_agent.cve_db.query import CVEEntry, EmbeddedCVEDatabase

__all__ = [
    "CVEEntry",
    "CveRecord",
    "EmbeddedCVEDatabase",
    "mock_lookup",
]
