"""Tests for the firmware parser."""

from __future__ import annotations

from io import BytesIO

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware, parse_firmware


def test_parse_firmware_extracts_components():
    components = [
        Component(name="busybox", version="1.36.0", vendor="busybox.net"),
        Component(name="openssl", version="1.1.0", vendor="openssl.org"),
    ]
    blob = make_demo_firmware(components)
    parsed = parse_firmware(BytesIO(blob))
    assert len(parsed) == 2
    assert parsed[0].name == "busybox"
    assert parsed[0].version == "1.36.0"
    assert parsed[1].name == "openssl"


def test_parse_firmware_without_manifest_returns_empty():
    import tarfile

    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="rootfs/usr/bin/empty")
        info.size = 0
        tf.addfile(info)
    assert parse_firmware(BytesIO(buf.getvalue())) == []


def test_parse_firmware_skips_invalid_entries():
    import tarfile

    buf = BytesIO()
    manifest = b"components:\n  - name: foo\n    version: '1.0'\n  - not_a_dict: true\n  - name: bar\n    version: '2.0'\n"
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="manifest.yml")
        info.size = len(manifest)
        tf.addfile(info, BytesIO(manifest))
    parsed = parse_firmware(BytesIO(buf.getvalue()))
    assert len(parsed) == 2
    assert {c.name for c in parsed} == {"foo", "bar"}