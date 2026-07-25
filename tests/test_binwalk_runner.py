"""Unit tests for the asynchronous binwalk subprocess wrapper."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from ai_firmware_agent.binwalk_runner import BinwalkRunner


class _Process:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


def test_extract_invokes_binwalk_without_executing_firmware(monkeypatch, tmp_path):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"fixture")
    output = tmp_path / "extract"
    process = _Process(stdout=b"0 0 Squashfs filesystem\n")
    create = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    result = asyncio.run(
        BinwalkRunner(timeout=5).extract(firmware, output_dir=output)
    )

    create.assert_awaited_once_with(
        "binwalk",
        "-e",
        "--directory",
        str(output.resolve()),
        str(firmware.resolve()),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert result.error is None
    assert result.signatures == ["Squashfs filesystem"]


def test_extract_returns_only_extracted_file_paths(monkeypatch, tmp_path):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"fixture")
    output = tmp_path / "extract"
    output.mkdir()
    extracted = output / "rootfs" / "manifest.yml"
    extracted.parent.mkdir()
    extracted.write_text("secret contents are not returned", encoding="utf-8")
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=_Process()),
    )

    result = asyncio.run(BinwalkRunner().extract(firmware, output_dir=output))

    assert result.files == [extracted.resolve()]
    assert "secret contents" not in repr(result)


def test_extract_nonzero_exit_is_fail_open(monkeypatch, tmp_path):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"fixture")
    process = _Process(stderr=b"extractor failed", returncode=2)
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=process),
    )

    result = asyncio.run(
        BinwalkRunner().extract(firmware, output_dir=tmp_path / "extract")
    )

    assert result.files == []
    assert result.error == "binwalk exited with status 2: extractor failed"


def test_extract_missing_firmware_does_not_spawn(monkeypatch, tmp_path):
    create = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    result = asyncio.run(
        BinwalkRunner().extract(
            tmp_path / "missing.bin",
            output_dir=tmp_path / "extract",
        )
    )

    create.assert_not_awaited()
    assert result.error == "firmware path does not exist"
