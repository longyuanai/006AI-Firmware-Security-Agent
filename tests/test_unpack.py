"""Tests for binwalk and SquashFS firmware extraction."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ai_firmware_agent.unpack import FirmwareUnpackError, unpack_firmware


def _write_manifest(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.yml").write_text(
        "components:\n"
        "  - name: busybox\n"
        "    version: 1.36.1\n"
        "    vendor: busybox.net\n",
        encoding="utf-8",
    )


def test_unpack_reads_manifest_extracted_by_binwalk(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"vendor-header")
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--directory") + 1])
        _write_manifest(output / "_router.bin.extracted" / "squashfs-root")
        return subprocess.CompletedProcess(command, 0, "", "")

    components = unpack_firmware(firmware, runner=runner)

    assert components[0].name == "busybox"
    assert components[0].version == "1.36.1"
    assert calls[0][0:2] == ["binwalk", "-Me"]


def test_unpack_uses_unsquashfs_for_direct_squashfs_image(tmp_path):
    firmware = tmp_path / "rootfs.bin"
    firmware.write_bytes(b"hsqs" + b"\0" * 32)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[0] == "binwalk":
            return subprocess.CompletedProcess(command, 1, "", "not recognized")
        destination = Path(command[command.index("-d") + 1])
        _write_manifest(destination)
        return subprocess.CompletedProcess(command, 0, "", "")

    components = unpack_firmware(firmware, runner=runner)

    assert [component.name for component in components] == ["busybox"]
    assert any(command[0] == "unsquashfs" for command in calls)


def test_unpack_reports_missing_tools_without_crashing_pipeline(tmp_path):
    firmware = tmp_path / "rootfs.bin"
    firmware.write_bytes(b"hsqs" + b"\0" * 32)

    def runner(command, **kwargs):
        raise FileNotFoundError(command[0])

    with pytest.raises(FirmwareUnpackError, match="No firmware manifest"):
        unpack_firmware(firmware, runner=runner)


def test_unpack_rejects_image_without_manifest(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"vendor-header")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(FirmwareUnpackError, match="No firmware manifest"):
        unpack_firmware(firmware, runner=runner)


@pytest.mark.skipif(
    shutil.which("unsquashfs") is None,
    reason="squashfs-tools is not installed",
)
def test_real_squashfs_sample_extracts():
    sample = (
        Path(__file__).parents[1]
        / "samples"
        / "firmware_demo"
        / "demo-router.squashfs.bin"
    )

    def runner(command, **kwargs):
        if command[0] == "binwalk":
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.run(command, **kwargs)

    components = unpack_firmware(sample, runner=runner)
    assert {component.name for component in components} >= {"busybox", "openssl"}
