"""Live FirmwareAdapter coverage against the official OpenWrt sample."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

PROJECT_ROOT = Path(__file__).parents[2]
SHARED_INTEGRATION_SRC = PROJECT_ROOT.parent / "000shared-integration" / "src"
SAMPLE = (
    PROJECT_ROOT
    / "samples"
    / "openwrt-23.05.5-ath79-tiny-engenius-eap350-v1-initramfs-kernel.bin"
)

if not SHARED_INTEGRATION_SRC.is_dir():
    pytest.skip(
        "000shared-integration sibling checkout is required",
        allow_module_level=True,
    )
sys.path.insert(0, str(SHARED_INTEGRATION_SRC))

from shared_integration.adapters import FirmwareAdapter  # noqa: E402
from shared_llm_core import (  # noqa: E402
    FindingRegistry,
    FindingSource,
    IntegrationGateway,
)

def _gateway() -> IntegrationGateway:
    return IntegrationGateway(
        products={
            FindingSource.FIRMWARE: FirmwareAdapter(PROJECT_ROOT),
        },
        registry=FindingRegistry(),
    )


async def _request(
    gateway: IntegrationGateway,
    method: str,
    path: str,
    *,
    json_payload: dict[str, Any] | None = None,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://gateway.test",
    ) as client:
        return await client.request(method, path, json=json_payload)


def test_post_scan_returns_findings():
    gateway = _gateway()
    response = asyncio.run(
        _request(
            gateway,
            "POST",
            "/v0.5/006/scan",
            json_payload={"firmware_path": str(SAMPLE.resolve())},
        )
    )

    assert response.status_code == 200
    envelope = response.json()
    assert envelope["source"] == "006"
    assert envelope["count"] == 1
    assert envelope["findings"][0]["cve"] == "CVE-2023-39810"
    assert len(gateway.registry.findings) == 1


def test_health_endpoint_reports_firmware_ok():
    response = asyncio.run(_request(_gateway(), "GET", "/v0.5/health"))

    assert response.status_code == 200
    health = response.json()
    assert health["status"] == "ok"
    assert health["products"]["006"]["status"] == "ok"
    assert health["products"]["006"]["available"] is True
