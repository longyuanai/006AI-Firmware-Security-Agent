"""Regression cover for the (cve_id, cpe_id) storage identity.

Before the composite primary key, a CVE affecting several versions kept only
whichever CPE was written last, so every other version silently stopped
matching while ``sync_database`` still reported them as written.
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import httpx

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase
from ai_firmware_agent.cve_db.sync import sync_database


def _cpe_match(criteria: str, **bounds: str) -> dict[str, Any]:
    return {"vulnerable": True, "criteria": criteria, **bounds}


def _payload(*matches: dict[str, Any], cve_id: str = "CVE-2025-0001") -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "fixture"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                    "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}],
                }
            }
        ]
    }


def _sync(database: EmbeddedCVEDatabase, payload: dict[str, Any]) -> int:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async def run() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await sync_database(
                database,
                client=client,
                components=["busybox"],
            )

    return asyncio.run(run())


def _versioned_payload() -> dict[str, Any]:
    return _payload(
        _cpe_match("cpe:2.3:a:busybox:busybox:1.36.0:*:*:*:*:*:*:*"),
        _cpe_match("cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"),
        _cpe_match("cpe:2.3:a:busybox:busybox:1.36.2:*:*:*:*:*:*:*"),
    )


def test_every_cpe_of_one_cve_is_stored(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    written = _sync(database, _versioned_payload())

    assert written == 3
    with sqlite3.connect(database.path) as connection:
        stored = connection.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    assert stored == 3


def test_all_affected_versions_remain_queryable(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    _sync(database, _versioned_payload())

    for version in ("1.36.0", "1.36.1", "1.36.2"):
        entries = asyncio.run(database.lookup("busybox", version))
        assert [entry.cve_id for entry in entries] == ["CVE-2025-0001"], version
    assert asyncio.run(database.lookup("busybox", "1.37.0")) == []


def test_lookup_returns_one_entry_per_cve(tmp_path):
    """Several CPE rows of one CVE must not fan out into duplicate findings."""
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    _sync(
        database,
        _payload(
            _cpe_match("cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"),
            _cpe_match("cpe:2.3:o:busybox:busybox:1.36.1:*:*:*:*:*:*:*"),
        ),
    )
    assert len(asyncio.run(database.lookup("busybox", "1.36.1"))) == 1


def test_version_range_records_are_matched(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    written = _sync(
        database,
        _payload(
            _cpe_match(
                "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*",
                versionStartIncluding="1.30.0",
                versionEndExcluding="1.36.1",
            )
        ),
    )

    assert written == 1
    assert asyncio.run(database.lookup("busybox", "1.33.2"))[0].cve_id == "CVE-2025-0001"
    assert asyncio.run(database.lookup("busybox", "1.36.1")) == []
    assert asyncio.run(database.lookup("busybox", "1.20.0")) == []


def test_resync_updates_rows_without_duplicating_them(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    _sync(database, _versioned_payload())
    _sync(database, _versioned_payload())

    with sqlite3.connect(database.path) as connection:
        stored = connection.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    assert stored == 3


def test_unrelated_product_in_the_same_response_is_ignored(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    _sync(
        database,
        _payload(
            _cpe_match("cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"),
            _cpe_match("cpe:2.3:a:gnu:bash:5.1:*:*:*:*:*:*:*"),
        ),
    )
    with sqlite3.connect(database.path) as connection:
        products = {
            row[0]
            for row in connection.execute("SELECT product FROM cve_entries")
        }
    assert products == {"busybox"}


def test_nested_running_on_configuration_is_traversed(tmp_path):
    """NVD nests application CPEs under node children for 'running on' rules."""
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-9009",
                    "descriptions": [{"lang": "en", "value": "nested fixture"}],
                    "configurations": [
                        {
                            "operator": "AND",
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        _cpe_match(
                                            "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*",
                                            versionEndIncluding="1.35.0",
                                        )
                                    ],
                                    "children": [
                                        {
                                            "cpeMatch": [
                                                _cpe_match(
                                                    "cpe:2.3:o:linux:linux_kernel:"
                                                    "5.10:*:*:*:*:*:*:*"
                                                )
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        ]
    }

    assert _sync(database, payload) == 1
    assert asyncio.run(database.lookup("busybox", "1.34.1"))[0].cve_id == (
        "CVE-2025-9009"
    )
    assert asyncio.run(database.lookup("busybox", "1.36.0")) == []
    # The kernel CPE belongs to a different product and must not be stored
    # under the busybox sync.
    assert asyncio.run(database.lookup("linux_kernel", "5.10")) == []


def test_legacy_database_is_rebuilt_on_initialize(tmp_path):
    """A cache written by the old single-column schema must not break lookups."""
    path = tmp_path / "cache.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE cve_entries (
                cve_id TEXT PRIMARY KEY,
                cpe_id TEXT NOT NULL,
                cvss_v3 REAL,
                description TEXT,
                in_known_exploited BOOLEAN DEFAULT 0,
                synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        connection.execute(
            "INSERT INTO cve_entries (cve_id, cpe_id) VALUES (?, ?)",
            ("CVE-2000-0001", "cpe:2.3:a:busybox:busybox:1.0:*:*:*:*:*:*:*"),
        )

    database = EmbeddedCVEDatabase(path)
    asyncio.run(database.initialize())

    assert asyncio.run(database.lookup("busybox", "1.0")) == []
    assert _sync(database, _versioned_payload()) == 3
    assert asyncio.run(database.lookup("busybox", "1.36.2"))[0].cve_id == (
        "CVE-2025-0001"
    )
