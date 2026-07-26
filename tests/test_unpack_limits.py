"""Extraction caps for untrusted firmware images.

binwalk -Me expands recursively, so a crafted image can inflate without
bound. These caps stop the scan before the expanded tree is walked.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ai_firmware_agent.unpack import FirmwareUnpackError, unpack_firmware

MANIFEST = """
components:
  - name: busybox
    version: 1.36.1
"""


def _firmware(tmp_path):
    path = tmp_path / "router.bin"
    path.write_bytes(b"hsqs" + b"\x00" * 64)
    return path


def _runner_writing(files: dict[str, bytes]):
    """Return a fake binwalk that writes ``files`` into its output directory."""

    def runner(command, *, cwd, **_kwargs):
        root = Path(cwd)
        if "--directory" in command:
            root = Path(command[command.index("--directory") + 1])
        for name, payload in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


def test_extraction_over_byte_cap_is_refused(tmp_path):
    runner = _runner_writing({"payload.bin": b"x" * 4096})

    with pytest.raises(FirmwareUnpackError, match="exceeded"):
        unpack_firmware(
            _firmware(tmp_path),
            runner=runner,
            max_bytes=1024,
        )


def test_extraction_over_file_cap_is_refused(tmp_path):
    runner = _runner_writing({f"file-{index}": b"x" for index in range(20)})

    with pytest.raises(FirmwareUnpackError, match="more than 5 files"):
        unpack_firmware(
            _firmware(tmp_path),
            runner=runner,
            max_files=5,
        )


def test_extraction_within_caps_still_parses(tmp_path):
    runner = _runner_writing({"squashfs-root/manifest.yml": MANIFEST.encode()})

    components = unpack_firmware(
        _firmware(tmp_path),
        runner=runner,
        max_bytes=1024 * 1024,
        max_files=100,
    )

    assert [component.name for component in components] == ["busybox"]
