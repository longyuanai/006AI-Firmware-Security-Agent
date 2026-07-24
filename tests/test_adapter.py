"""v0.5 §10 in-process adapter and CLI envelope tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner
from shared_llm_core.finding import Finding, FindingSeverity, FindingSource
from shared_llm_core.gateway import ProductAdapter

from ai_firmware_agent import FirmwareProductAdapter
from ai_firmware_agent.cli import cli

SAMPLE = Path(__file__).parent / "fixtures" / "sample.bin"


def _collect(payload: dict[str, Any]) -> list[Finding]:
    async def collect() -> list[Finding]:
        return [
            finding
            async for finding in FirmwareProductAdapter().scan(payload)
        ]

    return asyncio.run(collect())


def _cli_scan(path: Path):
    payload = json.dumps({"firmware_path": str(path.resolve())})
    return CliRunner().invoke(
        cli,
        ["scan", "--input", payload, "--json"],
    )


def test_adapter_source_is_firmware():
    assert FirmwareProductAdapter.source is FindingSource.FIRMWARE


def test_adapter_health_is_ok():
    assert FirmwareProductAdapter().health() == {
        "status": "ok",
        "product": "006-firmware",
        "version": "0.5.0",
    }


def test_adapter_is_product_adapter():
    assert isinstance(FirmwareProductAdapter(), ProductAdapter)


def test_scan_firmware_path_yields_one_finding():
    findings = _collect({"firmware_path": "C:/firmware/router.bin"})
    assert len(findings) == 1
    assert findings[0].title == "firmware scan of C:/firmware/router.bin"


def test_scan_firmware_url_yields_one_finding():
    findings = _collect({"firmware_url": "https://example.test/router.bin"})
    assert len(findings) == 1
    assert findings[0].title.endswith("https://example.test/router.bin")


def test_scan_without_firmware_yields_no_findings():
    assert _collect({}) == []


def test_scan_finding_severity_is_medium():
    finding = _collect({"firmware_path": "router.bin"})[0]
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.confidence == 0.7


def test_scan_finding_evidence_contains_path():
    finding = _collect({"firmware_path": "router.bin"})[0]
    assert finding.evidence == ("path=router.bin",)


def test_scan_prefers_firmware_path_when_both_are_present():
    finding = _collect(
        {
            "firmware_path": "local.bin",
            "firmware_url": "https://example.test/remote.bin",
        }
    )[0]
    assert finding.evidence == ("path=local.bin",)


def test_scan_assigns_generated_finding_id():
    finding = _collect({"firmware_path": "router.bin"})[0]
    assert finding.id


def test_cli_scan_sample_bin_returns_findings():
    result = _cli_scan(SAMPLE)
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.stdout)
    assert len(envelope["findings"]) >= 1
    assert envelope["errors"] == []


def test_cli_scan_missing_path_returns_empty_and_stderr_warning(tmp_path):
    result = _cli_scan(tmp_path / "missing.bin")
    assert result.exit_code == 0
    envelope = json.loads(result.stdout)
    assert envelope["findings"] == []
    assert envelope["errors"]
    assert "[006-firmware] WARNING:" in result.stderr


def test_cli_envelope_uses_object_form():
    result = _cli_scan(SAMPLE)
    envelope = json.loads(result.stdout)
    assert isinstance(envelope, dict)
    assert isinstance(envelope["findings"], list)
