"""The offline CVE cache is reachable from the CLI, not just from tests.

Until ``cve-db`` and ``--cve-source local`` existed, the embedded SQLite cache
had no production entry point: nothing outside the test-suite could populate
or query it.
"""

from __future__ import annotations

import asyncio
import sqlite3

from click.testing import CliRunner

from ai_firmware_agent.cli import cli
from ai_firmware_agent.cve_db import EmbeddedCVEDatabase


def _populated(tmp_path, *, version: str = "1.36.1", cvss: float = 9.4):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    asyncio.run(database.initialize())
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            """
            INSERT INTO cve_entries
                (cve_id, cpe_id, cvss_v3, description, in_known_exploited,
                 product)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "CVE-2025-7007",
                f"cpe:2.3:a:busybox:busybox:{version}:*:*:*:*:*:*:*",
                cvss,
                "cache-backed fixture",
                1,
                "busybox",
            ),
        )
    return database


def test_cve_db_status_reports_empty_cache(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["cve-db", "status", "--db-path", str(tmp_path / "cache.db")],
    )
    assert result.exit_code == 0, result.output
    assert "Cache is empty" in result.output


def test_cve_db_status_counts_rows(tmp_path):
    database = _populated(tmp_path)
    result = CliRunner().invoke(
        cli,
        ["cve-db", "status", "--db-path", str(database.path)],
    )
    assert result.exit_code == 0, result.output
    assert "CVEs:     1" in result.output
    assert "Cache is empty" not in result.output


def test_cve_db_sync_reports_written_rows(monkeypatch, tmp_path):
    import ai_firmware_agent.cli as cli_module

    seen: dict[str, object] = {}

    async def fake_sync(database, *, components=None, **_kwargs):
        seen["path"] = database.path
        seen["components"] = components
        await database.initialize()
        return 42

    monkeypatch.setattr(cli_module, "sync_database", fake_sync)
    result = CliRunner().invoke(
        cli,
        [
            "cve-db",
            "sync",
            "--db-path",
            str(tmp_path / "cache.db"),
            "--component",
            "busybox",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "42" in result.output
    assert seen["components"] == ["busybox"]
    assert seen["path"] == tmp_path / "cache.db"


def test_scan_help_lists_cve_source():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--cve-source" in result.output


def test_scan_with_local_source_uses_the_cache(monkeypatch, tmp_path, stub_router_factory):
    stub_router_factory({})
    database = _populated(tmp_path)
    monkeypatch.setenv("AI_FIRMWARE_CVE_DB", str(database.path))
    report = tmp_path / "report.md"

    result = CliRunner().invoke(
        cli,
        ["scan", "--demo", "--cve-source", "local", "--top-n", "0", "-o", str(report)],
    )

    assert result.exit_code == 0, result.output
    assert "local embedded CVE cache" in result.output
    assert "CVE-2025-7007" in report.read_text(encoding="utf-8")


def test_scan_with_local_source_warns_when_cache_is_empty(
    monkeypatch,
    tmp_path,
    stub_router_factory,
):
    stub_router_factory({})
    monkeypatch.setenv("AI_FIRMWARE_CVE_DB", str(tmp_path / "empty.db"))

    result = CliRunner().invoke(
        cli,
        ["scan", "--demo", "--cve-source", "local", "--top-n", "0"],
    )

    assert result.exit_code == 0, result.output
    assert "cve-db sync" in result.output


def test_scan_with_mock_source_does_not_call_nvd(monkeypatch, tmp_path, stub_router_factory):
    import ai_firmware_agent.cli as cli_module

    stub_router_factory({})

    def fail(*_args, **_kwargs):
        raise AssertionError("NVD must not be queried for --cve-source mock")

    monkeypatch.setattr(cli_module, "nvd_lookup", fail)
    report = tmp_path / "report.md"
    result = CliRunner().invoke(
        cli,
        ["scan", "--demo", "--cve-source", "mock", "--top-n", "0", "-o", str(report)],
    )

    assert result.exit_code == 0, result.output
    assert "bundled mock CVE data" in result.output
