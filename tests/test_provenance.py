"""Finding provenance must distinguish local scans from EMBA imports."""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.gateway_envelope import scan_path_to_envelope
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware
from ai_firmware_agent.providers.emba import EmbaReport, emba_report_to_envelope


def _component() -> Component:
    return Component(
        name="lighttpd",
        version="1.4.50",
        category="application",
        extra={"detection_sources": ["emba"]},
    )


def _native_envelope(tmp_path: Path) -> dict:
    firmware = tmp_path / "synthetic-firmware.tar.gz"
    firmware.write_bytes(make_demo_firmware([_component()]))
    return scan_path_to_envelope(firmware)


def _imported_envelope() -> dict:
    return emba_report_to_envelope(
        EmbaReport(components=(_component(),), tool_version="synthetic-test")
    )


def test_native_pipeline_findings_are_tagged(tmp_path: Path) -> None:
    finding = _native_envelope(tmp_path)["findings"][0]
    assert finding["metadata"]["finding_origin"] == "native_pipeline"


def test_imported_findings_are_tagged() -> None:
    finding = _imported_envelope()["findings"][0]
    assert finding["metadata"]["finding_origin"] == "emba_import"


def test_envelope_top_level_shape_unchanged(tmp_path: Path) -> None:
    expected = {"findings", "errors", "summary"}
    assert set(_native_envelope(tmp_path)) == expected
    assert set(_imported_envelope()) == expected
