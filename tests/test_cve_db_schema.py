"""SQLite schema initialization tests."""

from __future__ import annotations

import asyncio
import sqlite3

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase


def test_schema_creates_cve_entries_table(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    asyncio.run(database.initialize())
    with sqlite3.connect(database.path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "cve_entries" in tables


def test_schema_creates_cpe_index(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    asyncio.run(database.initialize())
    with sqlite3.connect(database.path) as connection:
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(cve_entries)")
        }
    assert "idx_cpe" in indexes


def test_database_file_is_created_only_on_initialize(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "nested" / "cache.db")
    assert not database.path.exists()
    asyncio.run(database.initialize())
    assert database.path.is_file()
