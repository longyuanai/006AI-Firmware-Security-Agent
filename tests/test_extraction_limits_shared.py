"""Both extraction paths enforce the same caps on untrusted images.

The async binwalk path used to have no output bound at all, so the guard
added to unpack_firmware could be bypassed simply by reaching the scanner
through FirmwareScanner instead of the CLI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ai_firmware_agent.binwalk_runner import ExtractResult
from ai_firmware_agent.extraction import (
    MAX_EXTRACTED_BYTES,
    MAX_EXTRACTED_FILES,
    FirmwareUnpackError,
    check_extraction_size,
)
from ai_firmware_agent.parsers.binwalk import extract_components

MANIFEST = """
components:
  - name: dropbear
    version: 2020.80
"""


class _Runner:
    """Fake binwalk that writes a fixed payload into the output directory."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    async def extract(self, firmware_path: Path, *, output_dir: Path) -> ExtractResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        written = []
        for name, payload in self._files.items():
            target = output_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            written.append(target.resolve())
        return ExtractResult(
            firmware_path=firmware_path,
            output_dir=output_dir.resolve(),
            files=sorted(written, key=str),
            signatures=[],
            error=None,
        )


def _extract(tmp_path, files, **limits):
    return asyncio.run(
        extract_components(
            tmp_path / "router.bin",
            output_dir=tmp_path / "out",
            runner=_Runner(files),
            **limits,
        )
    )


def test_async_path_refuses_output_over_the_byte_cap(tmp_path):
    result, components = _extract(
        tmp_path,
        {"squashfs-root/manifest.yml": MANIFEST.encode(), "blob": b"x" * 4096},
        max_bytes=1024,
    )
    assert components == []
    assert result.error is not None
    assert "exceeded" in result.error
    # The oversized listing must not be handed on for parsing.
    assert result.files == []


def test_async_path_refuses_output_over_the_file_cap(tmp_path):
    result, components = _extract(
        tmp_path,
        {f"file-{index}": b"x" for index in range(20)},
        max_files=5,
    )
    assert components == []
    assert "more than 5 files" in (result.error or "")


def test_async_path_within_caps_still_parses(tmp_path):
    _result, components = _extract(
        tmp_path,
        {"squashfs-root/manifest.yml": MANIFEST.encode()},
        max_bytes=1024 * 1024,
        max_files=100,
    )
    assert [component.name for component in components] == ["dropbear"]


def test_both_paths_share_one_set_of_limits():
    from ai_firmware_agent import unpack

    assert unpack.MAX_EXTRACTED_BYTES is MAX_EXTRACTED_BYTES
    assert unpack.MAX_EXTRACTED_FILES is MAX_EXTRACTED_FILES
    assert unpack.FirmwareUnpackError is FirmwareUnpackError


def test_symlinks_are_not_counted_towards_the_byte_cap(tmp_path):
    """A symlink loop must not be walked into an inflated total."""
    root = tmp_path / "tree"
    root.mkdir()
    (root / "real").write_bytes(b"x" * 16)
    try:
        (root / "link").symlink_to(root / "real")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this host")

    check_extraction_size(root, max_bytes=32, max_files=10)
