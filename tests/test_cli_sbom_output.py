"""CLI CycloneDX output and §15 envelope compatibility."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_firmware_agent.cli import cli

SAMPLE = Path(__file__).parent / "fixtures" / "sample.bin"


def test_cli_sbom_output_path_is_created(tmp_path):
    output = tmp_path / "nested" / "sbom.json"
    payload = json.dumps({"firmware_path": str(SAMPLE.resolve())})
    result = CliRunner().invoke(
        cli,
        ["scan", "--input", payload, "--sbom", str(output)],
    )
    assert result.exit_code == 0, result.output
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8"))["bomFormat"] == (
        "CycloneDX"
    )


def test_cli_sbom_accepts_relative_payload_path(monkeypatch, tmp_path):
    monkeypatch.chdir(Path(__file__).parents[1])
    output = tmp_path / "sbom.json"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"firmware_path":"tests/fixtures/sample.bin"}',
            "--sbom",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text(encoding="utf-8"))["components"]


def test_cli_json_envelope_remains_object_with_summary():
    payload = json.dumps({"firmware_path": str(SAMPLE.resolve())})
    result = CliRunner().invoke(
        cli,
        ["scan", "--input", payload, "--json"],
    )
    envelope = json.loads(result.stdout)
    assert isinstance(envelope, dict)
    assert envelope["findings"][0]["source"] == "006"
    assert envelope["summary"]["finding_count"] >= 1
