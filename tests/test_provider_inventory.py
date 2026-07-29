"""Tests for optional inventory providers and evidence merging."""

from __future__ import annotations

import asyncio
import json
import shutil
from unittest.mock import AsyncMock

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.providers import (
    CVEBinaryInventoryProvider,
    SyftInventoryProvider,
    ToolCapability,
    collect_inventory,
    merge_components,
)
from ai_firmware_agent.providers.base import InventoryResult
from ai_firmware_agent.providers.inventory import (
    parse_cve_bin_inventory,
    parse_syft_inventory,
)


class _Process:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        return None

    async def wait(self) -> int:
        return self.returncode


def test_tool_capability_is_json_ready():
    capability = ToolCapability(
        name="syft",
        available=True,
        version="1.0",
        features=("purl",),
    )
    assert capability.to_dict() == {
        "name": "syft",
        "available": True,
        "version": "1.0",
        "mode": "local",
        "reason": "",
        "features": ["purl"],
    }


def test_parse_syft_inventory_preserves_evidence():
    components = parse_syft_inventory(
        {
            "artifacts": [
                {
                    "name": "busybox",
                    "version": "1.36.1",
                    "type": "apk",
                    "purl": "pkg:apk/busybox@1.36.1",
                    "locations": [{"path": "/bin/busybox"}],
                    "licenses": [{"value": "GPL-2.0-only"}],
                }
            ]
        }
    )
    assert len(components) == 1
    assert components[0].path == "/bin/busybox"
    assert components[0].extra["purl"] == "pkg:apk/busybox@1.36.1"
    assert components[0].extra["license"] == "GPL-2.0-only"


def test_parse_syft_inventory_rejects_unknown_shape():
    assert parse_syft_inventory([]) == []
    assert parse_syft_inventory({"artifacts": "invalid"}) == []


def test_parse_cve_bin_inventory_walks_nested_reports():
    components = parse_cve_bin_inventory(
        {
            "results": [
                {
                    "product": "openssl",
                    "version": "1.1.1",
                    "vendor": "openssl",
                    "filename": "/usr/lib/libssl.so",
                },
                {"product": "OpenSSL", "version": "1.1.1"},
            ]
        }
    )
    assert len(components) == 1
    assert components[0].name == "openssl"
    assert components[0].path == "/usr/lib/libssl.so"


def test_merge_components_combines_sources_and_confidence():
    merged = merge_components(
        [
            Component(
                name="busybox",
                version="1.36.1",
                path="/bin/busybox",
                extra={
                    "detection_sources": ["syft"],
                    "confidence": 0.9,
                    "purl": "pkg:generic/busybox@1.36.1",
                },
            )
        ],
        [
            Component(
                name="BusyBox",
                version="1.36.1",
                extra={
                    "detection_sources": ["cve-bin-tool"],
                    "confidence": 0.85,
                },
            )
        ],
    )
    assert len(merged) == 1
    assert merged[0].extra["detection_sources"] == [
        "cve-bin-tool",
        "syft",
    ]
    assert merged[0].extra["confidence"] == 0.93
    assert merged[0].extra["evidence_paths"] == ["/bin/busybox"]


def test_merge_components_tolerates_invalid_confidence():
    merged = merge_components(
        [
            Component(
                name="zlib",
                version="1.3",
                extra={"confidence": "not-a-number"},
            )
        ]
    )
    assert merged[0].extra["confidence"] == 0.5


def test_syft_capability_is_optional(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _command: None)
    capability = asyncio.run(SyftInventoryProvider().capability())
    assert capability.available is False
    assert capability.reason == "executable not found on PATH"


def test_syft_inventory_invokes_json_cli(monkeypatch, tmp_path):
    payload = {
        "artifacts": [{"name": "dropbear", "version": "2020.80"}]
    }
    create = AsyncMock(
        return_value=_Process(json.dumps(payload).encode("utf-8"))
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    result = asyncio.run(SyftInventoryProvider().inventory(tmp_path))

    create.assert_awaited_once_with(
        "syft",
        f"dir:{tmp_path.resolve()}",
        "-o",
        "syft-json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert result.components[0].name == "dropbear"


def test_cve_binary_provider_uses_offline_mode():
    provider = CVEBinaryInventoryProvider()
    assert provider.command(__import__("pathlib").Path("root").resolve())[:3] == (
        "cve-bin-tool",
        "--offline",
        "--format",
    )


def test_collect_inventory_isolates_provider_failure(tmp_path):
    class BrokenProvider:
        name = "broken"

        async def capability(self) -> ToolCapability:
            return ToolCapability(name=self.name, available=True)

        async def inventory(self, root):
            raise RuntimeError("do not leak")

    class HealthyProvider:
        name = "healthy"

        async def capability(self) -> ToolCapability:
            return ToolCapability(name=self.name, available=True)

        async def inventory(self, root):
            return InventoryResult(
                provider=self.name,
                components=[Component(name="zlib", version="1.3")],
            )

    result = asyncio.run(
        collect_inventory(tmp_path, [BrokenProvider(), HealthyProvider()])
    )
    assert result.components[0].name == "zlib"
    assert result.warnings == ["broken inventory failed: RuntimeError"]
