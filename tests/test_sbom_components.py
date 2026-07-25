"""Fixture inventory to CycloneDX component mapping."""

from __future__ import annotations

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware, parse_firmware_file
from ai_firmware_agent.sbom import build_cyclonedx_bom


def test_fixture_components_are_exported(tmp_path):
    fixture = tmp_path / "firmware.bin"
    fixture.write_bytes(
        make_demo_firmware(
            [
                Component(
                    name="busybox",
                    version="1.36.1",
                    extra={"license": "GPL-2.0-only"},
                )
            ]
        )
    )
    components = parse_firmware_file(fixture)
    bom = build_cyclonedx_bom(components)
    assert bom["components"][0]["name"] == "busybox"
    assert bom["components"][0]["version"] == "1.36.1"
    assert bom["components"][0]["purl"] == (
        "pkg:generic/busybox@1.36.1"
    )


def test_empty_inventory_exports_empty_components():
    assert build_cyclonedx_bom([])["components"] == []
