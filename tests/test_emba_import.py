"""Import-only interoperability tests for EMBA's F15 JSON output."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from copy import deepcopy

import pytest
from click.testing import CliRunner

from ai_firmware_agent.cli import cli
from ai_firmware_agent.providers.emba import (
    EmbaMissingFieldError,
    EmbaParseError,
    EmbaSchemaError,
    EmbaUnsupportedVersionError,
    load_emba_report,
    parse_emba_report,
)


def _recorded_report() -> dict[str, object]:
    """Synthetic recording of the documented F15 CycloneDX 1.5 shape."""
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000014",
        "version": 1,
        "metadata": {
            "timestamp": "2026-08-17T00:00:00+00:00",
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "EMBA community",
                        "name": "EMBA binary analysis environment",
                        "version": "1.5.2-test",
                        "description": "EMBA firmware analyzer",
                    }
                ]
            },
            "component": {
                "type": "file",
                "name": "synthetic-firmware.bin",
                "bom-ref": "urn:uuid:00000000-0000-4000-8000-000000000015",
            },
        },
        "components": [
            {
                "type": "application",
                "bom-ref": "pkg:generic/lighttpd@1.4.50",
                "name": "lighttpd",
                "version": "1.4.50",
                "supplier": {"name": "lighttpd.net"},
                "purl": "pkg:generic/lighttpd@1.4.50",
                "properties": [
                    {"name": "synthetic.report.note", "value": "fixture only"}
                ],
            }
        ],
        "dependencies": [],
        "vulnerabilities": [],
    }


@pytest.fixture(autouse=True)
def _no_process_or_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any accidental EMBA execution or network use fail immediately."""

    def blocked(*_args, **_kwargs):
        raise AssertionError("EMBA import must not invoke subprocesses or network")

    async def blocked_async(*_args, **_kwargs):
        blocked()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", blocked_async)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def test_parses_recorded_report() -> None:
    report = parse_emba_report(_recorded_report())
    assert report.tool_version == "1.5.2-test"
    assert len(report.components) == 1


def test_unknown_schema_fails_closed() -> None:
    payload = deepcopy(_recorded_report())
    payload["$schema"] = "https://example.invalid/unknown.schema.json"
    with pytest.raises(EmbaSchemaError, match="unsupported EMBA report schema"):
        parse_emba_report(payload)


def test_missing_required_field_raises_typed_error() -> None:
    payload = deepcopy(_recorded_report())
    del payload["components"]
    with pytest.raises(EmbaMissingFieldError, match="components"):
        parse_emba_report(payload)


def test_unsupported_version_raises_typed_error() -> None:
    payload = deepcopy(_recorded_report())
    payload["specVersion"] = "1.6"
    with pytest.raises(EmbaUnsupportedVersionError, match="1.6"):
        parse_emba_report(payload)


def test_invalid_json_raises_parse_error() -> None:
    with pytest.raises(EmbaParseError, match="invalid EMBA JSON"):
        parse_emba_report("{not-json")


def test_components_map_to_internal_model() -> None:
    component = parse_emba_report(_recorded_report()).components[0]
    assert (component.name, component.version, component.vendor) == (
        "lighttpd",
        "1.4.50",
        "lighttpd.net",
    )
    assert component.category == "application"
    assert component.path == ""
    assert component.extra == {
        "detection_sources": ["emba"],
        "confidence": 0.9,
        "emba_bom_ref": "pkg:generic/lighttpd@1.4.50",
        "purl": "pkg:generic/lighttpd@1.4.50",
    }


def test_import_does_not_invoke_any_subprocess(tmp_path) -> None:
    path = tmp_path / "EMBA_cyclonedx_sbom.json"
    path.write_text(json.dumps(_recorded_report()), encoding="utf-8")
    assert load_emba_report(path).components[0].name == "lighttpd"


def test_nonempty_vulnerabilities_are_rejected_not_guessed() -> None:
    payload = deepcopy(_recorded_report())
    payload["vulnerabilities"] = [{"id": "CVE-SYNTHETIC"}]
    with pytest.raises(EmbaSchemaError, match="vulnerabilities must be empty"):
        parse_emba_report(payload)


def test_cli_import_produces_valid_envelope(tmp_path) -> None:
    path = tmp_path / "EMBA_cyclonedx_sbom.json"
    path.write_text(json.dumps(_recorded_report()), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["scan", "--emba-report", str(path), "--json"],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert set(envelope) == {"findings", "errors", "summary"}
    assert envelope["errors"] == []
    assert envelope["summary"] == {
        "component_count": 1,
        "finding_count": 1,
        "status": "ok",
    }
    assert envelope["findings"][0]["cve"] == "CVE-2018-19052"
