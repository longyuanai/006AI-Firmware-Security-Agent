"""Scanner backend selection and fail-open behavior."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from ai_firmware_agent.binwalk_runner import ExtractResult
from ai_firmware_agent.scanner import FirmwareScanner

SAMPLE = Path(__file__).parent / "fixtures" / "sample.bin"


class _UnavailableRunner:
    async def is_available(self) -> bool:
        return False


class _AvailableRunner:
    def __init__(self, manifest: Path) -> None:
        self._manifest = manifest

    async def is_available(self) -> bool:
        return True

    async def extract(
        self,
        firmware_path: Path,
        *,
        output_dir: Path,
    ) -> ExtractResult:
        return ExtractResult(
            firmware_path=firmware_path.resolve(),
            output_dir=output_dir.resolve(),
            files=[self._manifest],
            signatures=["Squashfs filesystem"],
            error=None,
        )


def test_scanner_falls_back_when_binwalk_unavailable():
    result = asyncio.run(
        FirmwareScanner(_UnavailableRunner()).scan(SAMPLE)
    )
    assert result.parser == "mock"
    assert result.components[0].name == "busybox"
    assert "binwalk unavailable" in result.errors[0]


def test_scanner_uses_binwalk_manifest_when_available(tmp_path):
    output = tmp_path / "extracted"
    output.mkdir()
    manifest = output / "manifest.yml"
    manifest.write_text(
        "components:\n  - name: dropbear\n    version: '2020.80'\n",
        encoding="utf-8",
    )
    result = asyncio.run(
        FirmwareScanner(_AvailableRunner(manifest)).scan(
            SAMPLE,
            output_dir=output,
        )
    )
    assert result.parser == "binwalk"
    assert result.components[0].name == "dropbear"
    assert result.errors == []


def test_scanner_dry_run_skips_binwalk():
    result = asyncio.run(
        FirmwareScanner(_AvailableRunner(Path("unused"))).scan(
            SAMPLE,
            dry_run=True,
        )
    )
    assert result.parser == "mock"
    assert "dry-run enabled" in result.errors[0]


def test_scanner_invalid_firmware_fails_open(tmp_path):
    firmware = tmp_path / "opaque.bin"
    firmware.write_bytes(b"not an archive")
    result = asyncio.run(
        FirmwareScanner(_UnavailableRunner()).scan(firmware)
    )
    assert result.components == []
    assert result.parser == "mock"
    assert result.errors[-1].startswith("mock parser failed:")


@pytest.mark.integration
def test_real_binwalk_integration_is_opt_in(tmp_path):
    if os.getenv("RUN_BINWALK_INTEGRATION") != "1":
        pytest.skip("set RUN_BINWALK_INTEGRATION=1 to run binwalk")
    result = asyncio.run(
        FirmwareScanner().scan(SAMPLE, output_dir=tmp_path / "extract")
    )
    assert result.extraction is not None
