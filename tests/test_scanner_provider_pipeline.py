"""Scanner integration tests for optional extraction and inventory providers."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ai_firmware_agent.binwalk_runner import ExtractResult
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.providers import InventoryResult, ToolCapability
from ai_firmware_agent.scanner import FirmwareScanner

SAMPLE = Path(__file__).parent / "fixtures" / "sample.bin"


class _Runner:
    def __init__(
        self,
        *,
        name: str,
        available: bool,
        files: list[Path] | None = None,
    ) -> None:
        self.name = name
        self.available = available
        self.files = files or []

    async def is_available(self) -> bool:
        return self.available

    async def extract(
        self,
        firmware_path: Path,
        *,
        output_dir: Path,
    ) -> ExtractResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        return ExtractResult(
            firmware_path=firmware_path.resolve(),
            output_dir=output_dir.resolve(),
            files=self.files,
            signatures=[],
            error=None,
            extractor=self.name,
        )


class _Inventory:
    name = "syft"

    async def capability(self) -> ToolCapability:
        return ToolCapability(name=self.name, available=True)

    async def inventory(self, root: Path) -> InventoryResult:
        return InventoryResult(
            provider=self.name,
            components=[
                Component(
                    name="dropbear",
                    version="2020.80",
                    extra={
                        "detection_sources": ["syft"],
                        "confidence": 0.9,
                    },
                )
            ],
        )


def test_scanner_uses_unblob_after_binwalk_unavailable(tmp_path):
    output = tmp_path / "unblob"
    output.mkdir()
    manifest = output / "manifest.yml"
    manifest.write_text(
        "components:\n  - name: dnsmasq\n    version: '2.90'\n",
        encoding="utf-8",
    )
    scanner = FirmwareScanner(
        runner=_Runner(name="binwalk", available=False),
        secondary_runner=_Runner(
            name="unblob",
            available=True,
            files=[manifest],
        ),
        inventory_providers=[],
    )
    result = asyncio.run(scanner.scan(SAMPLE, output_dir=output))
    assert result.parser == "unblob"
    assert result.components[0].name == "dnsmasq"
    assert result.providers == ["unblob"]


def test_scanner_uses_inventory_when_manifest_missing(tmp_path):
    scanner = FirmwareScanner(
        runner=_Runner(name="binwalk", available=True),
        secondary_runner=_Runner(name="unblob", available=False),
        inventory_providers=[_Inventory()],
    )
    result = asyncio.run(scanner.scan(SAMPLE, output_dir=tmp_path / "extract"))
    assert result.parser == "binwalk+syft"
    assert result.components[0].name == "dropbear"
    assert result.errors == []


def test_scanner_provider_failure_falls_back_to_mock(tmp_path):
    class BrokenInventory:
        name = "broken"

        async def capability(self) -> ToolCapability:
            return ToolCapability(name=self.name, available=True)

        async def inventory(self, root: Path) -> InventoryResult:
            raise RuntimeError("provider details must not escape")

    scanner = FirmwareScanner(
        runner=_Runner(name="binwalk", available=True),
        secondary_runner=_Runner(name="unblob", available=False),
        inventory_providers=[BrokenInventory()],
    )
    result = asyncio.run(scanner.scan(SAMPLE, output_dir=tmp_path / "extract"))
    assert result.parser == "mock"
    assert result.components[0].name == "busybox"
    assert "broken inventory failed: RuntimeError" in result.errors


def test_scanner_runner_exception_is_fail_open(tmp_path):
    class BrokenRunner:
        async def is_available(self) -> bool:
            return True

        async def extract(self, firmware_path: Path, *, output_dir: Path):
            raise RuntimeError("firmware detail must not escape")

    scanner = FirmwareScanner(
        runner=BrokenRunner(),
        secondary_runner=_Runner(name="unblob", available=False),
        inventory_providers=[],
    )
    result = asyncio.run(scanner.scan(SAMPLE, output_dir=tmp_path / "extract"))
    assert result.parser == "mock"
    assert result.components[0].name == "busybox"
    assert "binwalk extraction failed: RuntimeError" in result.errors
