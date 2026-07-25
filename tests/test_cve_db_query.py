"""Offline lookup tests using a prefilled temporary SQLite database."""

from __future__ import annotations

import asyncio
import sqlite3

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase


def _database(tmp_path) -> EmbeddedCVEDatabase:
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
                "CVE-2024-0001",
                "cpe:2.3:a:openbsd:openssh:8.5p1:*:*:*:*:*:*:*",
                8.1,
                "fixture vulnerability",
                1,
            ),
        )
    return database


def test_lookup_matches_component_and_version(tmp_path):
    entries = asyncio.run(_database(tmp_path).lookup("openssh", "8.5p1"))
    assert [entry.cve_id for entry in entries] == ["CVE-2024-0001"]
    assert entries[0].cvss_v3 == 8.1
    assert entries[0].in_known_exploited is True


def test_lookup_is_case_insensitive(tmp_path):
    entries = asyncio.run(_database(tmp_path).lookup("OpenSSH", "8.5P1"))
    assert len(entries) == 1


def test_lookup_wrong_version_returns_empty(tmp_path):
    assert asyncio.run(_database(tmp_path).lookup("openssh", "9.0")) == []


def test_lookup_empty_input_returns_empty_without_database(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    assert asyncio.run(database.lookup("", "8.5p1")) == []
    assert not database.path.exists()
