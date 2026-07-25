"""Embedded CVE database plus the frozen deterministic mock lookup."""

from ai_firmware_agent.cve_db.mock import CveRecord, mock_lookup
from ai_firmware_agent.cve_db.query import (
    CVEEntry,
    EmbeddedCVEDatabase,
    local_db_lookup,
)
from ai_firmware_agent.cve_db.version import VersionRange, matches_version, parse_cpe

__all__ = [
    "CVEEntry",
    "CveRecord",
    "EmbeddedCVEDatabase",
    "VersionRange",
    "local_db_lookup",
    "matches_version",
    "mock_lookup",
    "parse_cpe",
]
