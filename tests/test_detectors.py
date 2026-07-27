"""Component detection on a rootfs that carries no manifest.yml.

manifest.yml is a test fixture format. Real firmware does not contain one, so
before these detectors existed the scanner returned an empty inventory for
every real image, and the accuracy target in tech-spec section 9 was not
measurable at all.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ai_firmware_agent.detectors import (
    detect_components,
    detect_in_tree,
    iter_rootfs_candidates,
    merge_components,
)
from ai_firmware_agent.detectors.binary import scan_bytes
from ai_firmware_agent.detectors.packages import upstream_version
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.unpack import unpack_firmware

ROOTFS = Path(__file__).parent / "fixtures" / "rootfs"


def _by_name(components):
    return {component.name: component for component in components}


def test_fixture_rootfs_has_no_manifest():
    """Guards the premise: this fixture must stay manifest-free."""
    assert not list(ROOTFS.rglob("manifest.y*ml"))


def test_package_database_is_the_primary_source():
    found = _by_name(detect_components(ROOTFS))
    assert found["busybox"].extra["detector"] == "opkg"
    assert found["dropbear"].extra["detector"] == "opkg"
    assert found["busybox"].extra["evidence"] == "opkg:usr/lib/opkg/status"


def test_epoch_and_revision_are_stripped_for_cve_matching():
    found = _by_name(detect_components(ROOTFS))
    # "1:1.36.1-r2" would never match a CPE version of "1.36.1".
    assert found["busybox"].version == "1.36.1"
    assert found["busybox"].extra["package_version"] == "1:1.36.1-r2"
    assert found["dropbear"].version == "2022.82"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.36.1", "1.36.1"),
        ("1:1.36.1-r2", "1.36.1"),
        ("2022.82-5", "2022.82"),
        ("3.0.0", "3.0.0"),
        ("1.2.3-1ubuntu2", "1.2.3"),
    ],
)
def test_upstream_version_normalization(raw, expected):
    assert upstream_version(raw) == expected


def test_uninstalled_packages_are_skipped():
    assert "removed-package" not in _by_name(detect_components(ROOTFS))


def test_os_release_identifies_the_distribution():
    distro = _by_name(detect_components(ROOTFS))["openwrt"]
    assert distro.version == "23.05.5"
    assert distro.category == "os"
    assert distro.extra["detector"] == "os-release"


def test_binary_banners_find_components_absent_from_the_package_database():
    found = _by_name(detect_components(ROOTFS))
    # lighttpd is not in the opkg status file; only its binary reveals it.
    assert found["lighttpd"].version == "1.4.50"
    assert found["lighttpd"].extra["detector"] == "binary"


def test_non_elf_files_are_not_scanned():
    """A README claiming BusyBox v9.9.9 must not enter the inventory."""
    assert _by_name(detect_components(ROOTFS))["busybox"].version == "1.36.1"


def test_scan_bytes_recognises_known_banners():
    found = dict(
        (name, version) for name, version, _vendor, _category in scan_bytes(
            b"BusyBox v1.36.1\x00OpenSSL 1.1.1w\x00Linux version 5.10.176\x00"
        )
    )
    assert found == {
        "busybox": "1.36.1",
        "openssl": "1.1.1w",
        "kernel": "5.10.176",
    }


def test_stronger_evidence_wins_and_the_conflict_stays_visible():
    merged = merge_components(
        [
            Component(
                name="busybox",
                version="1.30.0",
                extra={"detector": "binary", "evidence": "binary:bin/busybox"},
            ),
            Component(
                name="busybox",
                version="1.36.1",
                extra={"detector": "opkg", "evidence": "opkg:usr/lib/opkg/status"},
            ),
        ]
    )
    assert len(merged) == 1
    assert merged[0].version == "1.36.1"
    assert merged[0].extra["also_detected_by"] == ["binary:bin/busybox=1.30.0"]


def test_agreeing_detectors_do_not_record_a_conflict():
    merged = merge_components(
        [
            Component(
                name="busybox",
                version="1.36.1",
                extra={"detector": "binary", "evidence": "binary:bin/busybox"},
            ),
            Component(
                name="busybox",
                version="1.36.1",
                extra={"detector": "opkg", "evidence": "opkg:status"},
            ),
        ]
    )
    assert "also_detected_by" not in merged[0].extra


def test_detection_is_deterministic():
    assert detect_components(ROOTFS) == detect_components(ROOTFS)


def test_missing_rootfs_yields_nothing(tmp_path):
    assert detect_components(tmp_path / "absent") == []
    assert detect_components(tmp_path) == []


def test_nested_rootfs_is_found_inside_an_extraction_tree(tmp_path):
    """binwalk nests what it carves, so the tree root is not the rootfs."""
    nested = tmp_path / "_router.bin.extracted" / "squashfs-root"
    nested.parent.mkdir(parents=True)
    shutil.copytree(ROOTFS, nested)

    assert iter_rootfs_candidates(tmp_path) == [nested]
    assert "busybox" in _by_name(detect_in_tree(tmp_path))


def test_unpack_uses_detection_when_binwalk_leaves_no_manifest(tmp_path):
    """End to end: a real-shaped image with no manifest now yields components."""
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"vendor-header")

    def runner(command, **_kwargs):
        output = Path(command[command.index("--directory") + 1])
        destination = output / "_router.bin.extracted" / "squashfs-root"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOTFS, destination)
        return subprocess.CompletedProcess(command, 0, "", "")

    found = _by_name(unpack_firmware(firmware, runner=runner))
    assert found["busybox"].version == "1.36.1"
    assert found["dropbear"].version == "2022.82"
    assert found["openwrt"].version == "23.05.5"
