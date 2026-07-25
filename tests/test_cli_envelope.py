"""FirmwareAdapter JSON envelope and subprocess contract tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from ai_firmware_agent.cli import cli
from ai_firmware_agent.gateway_envelope import scan_payload_to_envelope
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware


def _firmware(tmp_path: Path) -> Path:
    path = tmp_path / "mini-firmware.tar.gz"
    path.write_bytes(
        make_demo_firmware(
            [
                Component(
                    name="lighttpd",
                    version="1.4.50",
                    category="web_server",
                )
            ]
        )
    )
    return path.resolve()


def _invoke_json(path: Path):
    payload = json.dumps({"firmware_path": str(path)})
    return CliRunner().invoke(
        cli,
        ["scan", "--input", payload, "--json"],
    )


def test_scan_firmware_path(tmp_path):
    result = _invoke_json(_firmware(tmp_path))
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["errors"] == []
    assert len(envelope["findings"]) == 1
    assert envelope["findings"][0]["cve"] == "CVE-2018-19052"
    assert envelope["findings"][0]["host"].endswith("mini-firmware.tar.gz")


def test_scan_corrupted_firmware_graceful(tmp_path):
    corrupted = (tmp_path / "corrupted.tar.gz").resolve()
    corrupted.write_bytes(b"not a firmware archive")
    result = _invoke_json(corrupted)
    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert envelope["findings"] == []
    assert envelope["errors"]
    assert "ReadError" in envelope["errors"][0]


def test_envelope_contains_prisk_narrative(tmp_path):
    result = _invoke_json(_firmware(tmp_path))
    finding = json.loads(result.output)["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["confidence"] == 0.99
    assert "PRisk " in finding["narrative"]
    assert "not KEV listed" in finding["narrative"]
    assert finding["metadata"]["prisk"] > 0


def test_json_payload_can_be_read_from_stdin(tmp_path):
    payload = json.dumps({"firmware_path": str(_firmware(tmp_path))})
    result = CliRunner().invoke(cli, ["scan", "--json"], input=payload)
    assert result.exit_code == 0
    assert json.loads(result.output)["findings"]


def test_scan_firmware_url_with_mock_transport(tmp_path):
    firmware_bytes = _firmware(tmp_path).read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://firmware.example/demo.tar.gz"
        return httpx.Response(200, content=firmware_bytes)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        envelope = scan_payload_to_envelope(
            '{"firmware_url":"https://firmware.example/demo.tar.gz"}',
            client=client,
        )
    assert envelope["errors"] == []
    assert envelope["findings"][0]["cve"] == "CVE-2018-19052"


def test_scan_rejects_private_firmware_url_gracefully():
    envelope = scan_payload_to_envelope(
        '{"firmware_url":"http://127.0.0.1/router.bin"}'
    )
    assert envelope["findings"] == []
    assert "public address" in envelope["errors"][0]


def test_firmware_adapter_subprocess_end_to_end(tmp_path):
    # Skip rather than fail without the sibling checkout, matching
    # tests/integration/test_firmware_adapter_e2e.py.
    FirmwareAdapter = pytest.importorskip(
        "shared_integration.adapters",
        reason="000shared-integration sibling checkout is required",
    ).FirmwareAdapter

    root = Path(__file__).parents[1]
    adapter = FirmwareAdapter(root)

    async def collect():
        return [
            finding
            async for finding in adapter.scan(
                {"firmware_path": str(_firmware(tmp_path))}
            )
        ]

    findings = asyncio.run(collect())
    assert len(findings) == 1
    assert findings[0].source.value == "006"
    assert findings[0].cve == "CVE-2018-19052"
    assert findings[0].metadata["prisk"] > 0
