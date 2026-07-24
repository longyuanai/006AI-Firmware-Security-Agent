"""006 firmware security product adapter for v0.5 IntegrationGateway."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource
from shared_llm_core.gateway import ProductAdapter


class FirmwareProductAdapter(ProductAdapter):
    """Expose firmware scan requests through the in-process §10 contract."""

    source = FindingSource.FIRMWARE

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        firmware = payload.get("firmware_path") or payload.get("firmware_url")
        if not firmware:
            return
        yield Finding(
            id="",
            source=self.source,
            severity=FindingSeverity.MEDIUM,
            confidence=0.7,
            title=f"firmware scan of {firmware}",
            evidence=(f"path={firmware}",),
        )

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "product": "006-firmware",
            "version": "0.5.0",
        }
