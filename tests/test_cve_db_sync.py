"""NVD synchronization tests use MockTransport and never call the network."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import httpx

from ai_firmware_agent.cve_db import EmbeddedCVEDatabase
from ai_firmware_agent.cve_db.sync import sync_database


def _payload(*, score: float = 9.1, description: str = "fixture") -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-0001",
                    "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": (
                                                "cpe:2.3:a:busybox:busybox:"
                                                "1.36.1:*:*:*:*:*:*:*"
                                            ),
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def test_sync_upserts_nvd_response(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_payload())

    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    sleep = AsyncMock()

    async def run_sync() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            return await sync_database(
                database,
                client=client,
                sleep=sleep,
                components=["busybox"],
            )

    written = asyncio.run(run_sync())
    assert written == 1
    entries = asyncio.run(database.lookup("busybox", "1.36.1"))
    assert entries[0].cve_id == "CVE-2025-0001"
    assert entries[0].cvss_v3 == 9.1


def test_sync_updates_existing_cve(tmp_path):
    responses = iter(
        [
            _payload(score=5.0, description="old"),
            _payload(score=8.8, description="new"),
        ]
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(responses))

    database = EmbeddedCVEDatabase(tmp_path / "cache.db")

    async def run_sync_twice() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            await sync_database(
                database,
                client=client,
                components=["busybox"],
            )
            await sync_database(
                database,
                client=client,
                components=["busybox"],
            )

    asyncio.run(run_sync_twice())
    entry = asyncio.run(database.lookup("busybox", "1.36.1"))[0]
    assert entry.cvss_v3 == 8.8
    assert entry.description == "new"


def test_sync_without_api_key_uses_five_request_rate(monkeypatch, tmp_path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    sleep = AsyncMock()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    async def run_sync() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            await sync_database(
                EmbeddedCVEDatabase(tmp_path / "cache.db"),
                client=client,
                sleep=sleep,
                components=["busybox", "openssh"],
            )

    asyncio.run(run_sync())
    sleep.assert_awaited_once_with(6.0)


def test_sync_with_api_key_uses_header_and_faster_rate(monkeypatch, tmp_path):
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    requests: list[httpx.Request] = []
    sleep = AsyncMock()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"vulnerabilities": []})

    async def run_sync() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            await sync_database(
                EmbeddedCVEDatabase(tmp_path / "cache.db"),
                client=client,
                sleep=sleep,
                components=["busybox", "openssh"],
            )

    asyncio.run(run_sync())
    sleep.assert_awaited_once_with(0.6)
    assert requests[0].headers["apiKey"] == "test-key"
    assert "test-key" not in str(requests[0].url)


def test_sync_failure_is_fail_open(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    async def run_sync() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            return await sync_database(
                EmbeddedCVEDatabase(tmp_path / "cache.db"),
                client=client,
                components=["busybox"],
            )

    written = asyncio.run(run_sync())
    assert written == 0
