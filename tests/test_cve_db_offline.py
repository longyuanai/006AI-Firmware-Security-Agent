"""A synchronized SQLite cache remains queryable without network access."""

from __future__ import annotations

import asyncio

import httpx

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase
from ai_firmware_agent.cve_db.sync import sync_database


def test_synced_database_lookup_is_offline(tmp_path):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-4242",
                    "descriptions": [
                        {"lang": "en", "value": "offline fixture"}
                    ],
                    "configurations": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        "cpe:2.3:a:openbsd:openssh:"
                                        "8.5p1:*:*:*:*:*:*:*"
                                    ),
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    def online(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    database = EmbeddedCVEDatabase(tmp_path / "cache.db")

    async def run_sync() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(online)
        ) as client:
            await sync_database(
                database,
                client=client,
                components=["openssh"],
            )

    asyncio.run(run_sync())

    entries = asyncio.run(database.lookup("openssh", "8.5p1"))
    assert [entry.cve_id for entry in entries] == ["CVE-2025-4242"]
