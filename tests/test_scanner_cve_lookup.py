"""Scanner integration with the embedded CVE cache."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from shared_llm_core.finding import FindingSeverity, FindingSource

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase
from ai_firmware_agent.scanner import FirmwareScanner

SAMPLE = Path(__file__).parent / "fixtures" / "sample.bin"


class _UnavailableRunner:
    async def is_available(self) -> bool:
        return False


def _database(tmp_path, *, kev: bool = False) -> EmbeddedCVEDatabase:
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    asyncio.run(database.initialize())
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            """
            INSERT INTO cve_entries
                (cve_id, cpe_id, cvss_v3, description, in_known_exploited)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "CVE-2025-6006",
                "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
                9.4,
                "embedded cache fixture",
                int(kev),
            ),
        )
    return database


def test_scanner_emits_finding_for_cached_cve(tmp_path):
    result = asyncio.run(
        FirmwareScanner(
            _UnavailableRunner(),
            _database(tmp_path),
        ).scan(SAMPLE)
    )
    assert len(result.findings) == 1
    assert result.findings[0].source is FindingSource.FIRMWARE
    assert result.findings[0].cve == "CVE-2025-6006"


def test_scanner_maps_cvss_to_finding_severity(tmp_path):
    result = asyncio.run(
        FirmwareScanner(
            _UnavailableRunner(),
            _database(tmp_path),
        ).scan(SAMPLE)
    )
    assert result.findings[0].severity is FindingSeverity.CRITICAL
    assert result.findings[0].metadata["cvss_v3"] == 9.4


def test_scanner_kev_entry_has_higher_confidence(tmp_path):
    result = asyncio.run(
        FirmwareScanner(
            _UnavailableRunner(),
            _database(tmp_path, kev=True),
        ).scan(SAMPLE)
    )
    assert result.findings[0].confidence == 0.9
    assert "cpe=" in result.findings[0].evidence[1]
