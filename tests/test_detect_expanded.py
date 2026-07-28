"""DETECT-002: wider binary banner coverage plus Python and Node detectors.

Each new binary pattern matches a documented, single hardcoded string
literal or compile-time adjacent-literal concatenation, so the joined
"name version" bytes are guaranteed contiguous in the binary. Patterns that
rely on a runtime sprintf join (format string and version stored apart) are
deliberately excluded, since a substring scan could never match them.
"""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.detectors import detect_components
from ai_firmware_agent.detectors.binary import scan_bytes
from ai_firmware_agent.detectors.node_packages import detect as detect_node
from ai_firmware_agent.detectors.python_packages import detect as detect_python

ROOTFS = Path(__file__).parent / "fixtures" / "rootfs"


def _by_name(components):
    return {component.name: component for component in components}


# --- expanded binary banners ------------------------------------------------


def test_new_banners_are_recognised_by_scan_bytes():
    blob = (
        b" deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler \n"
        b"wpa_supplicant v2.9\n"
        b"hostapd v2.9\n"
        b"mbed TLS 2.28.0\n"
        b"Server: nginx/1.21.0\n"
    )
    found = {name: version for name, version, _v, _c in scan_bytes(blob)}
    assert found == {
        "zlib": "1.2.11",
        "wpa_supplicant": "2.9",
        "hostapd": "2.9",
        "mbedtls": "2.28.0",
        "nginx": "1.21.0",
    }


def test_new_banners_are_found_in_the_fixture_rootfs():
    found = _by_name(detect_components(ROOTFS))
    for name, version in (
        ("zlib", "1.2.11"),
        ("wpa_supplicant", "2.9"),
        ("hostapd", "2.9"),
        ("mbedtls", "2.28.0"),
        ("nginx", "1.21.0"),
    ):
        assert found[name].version == version
        assert found[name].extra["detector"] == "binary"


def test_libcurl_is_not_claimed():
    """libcurl assembles its banner at runtime; a static scan cannot find it."""
    found = _by_name(detect_components(ROOTFS))
    assert "libcurl" not in found


# --- Python dist-info / egg-info -------------------------------------------


def test_python_dist_info_is_detected():
    components = detect_python(ROOTFS)
    found = _by_name(components)
    assert found["requests"].version == "2.31.0"
    assert found["requests"].category == "python-package"
    assert found["requests"].extra["detector"] == "python-dist-info"


def test_python_egg_info_is_also_detected():
    found = _by_name(detect_python(ROOTFS))
    assert found["oldpkg"].version == "1.0"


def test_metadata_body_is_not_scanned_as_headers(tmp_path):
    """A blank line ends the header block; anything after it is not a field."""
    dist_info = tmp_path / "evil-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: evil\n"
        "Version: 1.0\n"
        "\n"
        "Name: hijacked\n"
        "Version: 99.99\n",
        encoding="utf-8",
    )
    found = _by_name(detect_python(tmp_path))
    assert found["evil"].version == "1.0"
    assert "hijacked" not in found


def test_metadata_missing_required_fields_is_skipped(tmp_path):
    dist_info = tmp_path / "broken-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Metadata-Version: 2.1\n", encoding="utf-8")
    assert detect_python(tmp_path) == []


def test_detect_components_merges_python_packages_into_the_inventory():
    found = _by_name(detect_components(ROOTFS))
    assert "requests" in found
    assert "oldpkg" in found


# --- Node.js package.json ---------------------------------------------------


def test_node_application_manifest_is_detected():
    found = _by_name(detect_node(ROOTFS))
    assert found["router-webui"].version == "3.2.1"
    assert found["router-webui"].category == "node-package"


def test_node_dependency_under_node_modules_is_also_detected():
    """node_modules holds the installed dependencies, not just the app itself."""
    found = _by_name(detect_node(ROOTFS))
    assert found["express"].version == "4.18.2"
    assert found["express"].extra["detector"] == "node-package-json"


def test_malformed_package_json_is_skipped(tmp_path):
    (tmp_path / "package.json").write_text("{not valid json", encoding="utf-8")
    assert detect_node(tmp_path) == []


def test_package_json_missing_version_is_skipped(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    assert detect_node(tmp_path) == []


def test_non_object_package_json_is_skipped(tmp_path):
    (tmp_path / "package.json").write_text("[1, 2, 3]", encoding="utf-8")
    assert detect_node(tmp_path) == []


def test_detect_components_merges_node_packages_into_the_inventory():
    found = _by_name(detect_components(ROOTFS))
    assert "router-webui" in found
    assert "express" in found


# --- cross-detector merge ----------------------------------------------------


def test_full_fixture_inventory_has_no_unexpected_collisions():
    """Every added detector must keep the whole inventory internally consistent."""
    names = [component.name for component in detect_components(ROOTFS)]
    assert len(names) == len(set(names))
