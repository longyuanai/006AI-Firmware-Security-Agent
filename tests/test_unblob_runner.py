"""Tests for the optional unblob extraction adapter."""

from __future__ import annotations

import asyncio
import json
import shutil
from unittest.mock import AsyncMock

from ai_firmware_agent.binwalk_runner import collect_extracted_files
from ai_firmware_agent.providers import UnblobRunner


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

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        return None

    async def wait(self) -> int:
        return self.returncode


def test_unblob_availability_is_optional(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _command: None)
    capability = asyncio.run(UnblobRunner().capability())
    assert capability.available is False
    assert "chunk-carving" in capability.features


def test_unblob_extract_uses_bounded_cli(monkeypatch, tmp_path):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"fixture")
    output = tmp_path / "extract"
    output.mkdir()
    report = output / "unblob-report.json"
    report.write_text(
        json.dumps({"chunks": [{"handler_name": "SquashFS"}]}),
        encoding="utf-8",
    )
    extracted = output / "rootfs" / "manifest.yml"
    extracted.parent.mkdir()
    extracted.write_text("components: []", encoding="utf-8")
    create = AsyncMock(return_value=_Process())
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)

    result = asyncio.run(
        UnblobRunner(max_depth=3).extract(firmware, output_dir=output)
    )

    create.assert_awaited_once_with(
        "unblob",
        "-e",
        str(output.resolve()),
        "--report",
        str(report),
        "-d",
        "3",
        str(firmware.resolve()),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert result.extractor == "unblob"
    assert result.signatures == ["SquashFS"]
    assert extracted.resolve() in result.files


def test_unblob_missing_firmware_does_not_spawn(monkeypatch, tmp_path):
    create = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    result = asyncio.run(
        UnblobRunner().extract(
            tmp_path / "missing.bin",
            output_dir=tmp_path / "extract",
        )
    )
    create.assert_not_awaited()
    assert result.error == "firmware path does not exist"


def test_unblob_error_redacts_firmware_path(monkeypatch, tmp_path):
    firmware = tmp_path / "private.bin"
    firmware.write_bytes(b"fixture")
    process = _Process(
        stderr=f"failed to parse {firmware.resolve()}".encode(),
        returncode=2,
    )
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=process),
    )
    result = asyncio.run(
        UnblobRunner().extract(
            firmware,
            output_dir=tmp_path / "extract",
        )
    )
    assert str(firmware.resolve()) not in (result.error or "")
    assert "<firmware>" in (result.error or "")


def test_extraction_collection_enforces_file_limit(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).write_bytes(b"x")
    files, warnings, truncated = collect_extracted_files(
        tmp_path,
        max_files=1,
        max_total_bytes=100,
    )
    assert len(files) == 1
    assert truncated is True
    assert warnings == ["extracted file limit reached (1)"]


def test_extraction_collection_ignores_symlinks(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        return
    files, _, _ = collect_extracted_files(
        tmp_path,
        max_files=10,
        max_total_bytes=100,
    )
    assert link.resolve() not in files or files.count(link.resolve()) == 1
