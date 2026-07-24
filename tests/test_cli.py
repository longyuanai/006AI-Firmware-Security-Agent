"""Tests for the CLI."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from click.testing import CliRunner

from ai_firmware_agent.cli import cli
from ai_firmware_agent.cve_db import CveRecord


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "firmware" in res.output.lower()


def test_cli_scan_requires_input_or_demo():
    runner = CliRunner()
    res = runner.invoke(cli, ["scan"])
    assert res.exit_code != 0


def test_cli_scan_missing_file(tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", "--input", str(tmp_path / "missing.tar.gz")])
    assert res.exit_code != 0


def test_cli_routes_bin_input_to_unpack(monkeypatch, tmp_path):
    import ai_firmware_agent.cli as cli_module

    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"hsqs")
    calls = []

    def unpack_stub(path):
        calls.append(path)
        return []

    monkeypatch.setattr(cli_module, "unpack_firmware", unpack_stub)
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", "--input", str(firmware)])

    assert res.exit_code == 0
    assert calls == [str(firmware)]
    assert "No components parsed" in res.output


def test_cli_scan_help_lists_nvd_api_key():
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", "--help"])
    assert res.exit_code == 0
    assert "--nvd-api-key" in res.output
    assert "--use-epss" in res.output
    assert "--use-kev" in res.output


def test_cli_demo_applies_threat_intelligence_flags(monkeypatch, tmp_path):
    import ai_firmware_agent.cli as cli_module
    from shared_llm_core.router import LLMRouter

    calls = {"epss": 0, "kev": 0}

    def nvd_stub(component, api_key=None):
        if component.name != "xz":
            return []
        return [CveRecord("CVE-2024-3094", 10.0, "xz backdoor")]

    def epss_stub(records):
        calls["epss"] += 1
        return [replace(record, epss=0.9) for record in records]

    def kev_stub(records):
        calls["kev"] += 1
        return [replace(record, kev=True) for record in records]

    class StubRouter:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    monkeypatch.setattr(cli_module, "nvd_lookup", nvd_stub)
    monkeypatch.setattr(cli_module, "enrich_with_epss", epss_stub)
    monkeypatch.setattr(cli_module, "enrich_with_kev", kev_stub)
    monkeypatch.setattr(LLMRouter, "from_env", lambda: StubRouter())

    report_path = tmp_path / "report.md"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "scan",
            "--demo",
            "--top-n",
            "0",
            "--use-epss",
            "--use-kev",
            "--output",
            str(report_path),
        ],
    )

    assert res.exit_code == 0, res.output
    assert calls == {"epss": 1, "kev": 1}
    report = report_path.read_text(encoding="utf-8")
    chart_path = tmp_path / "report-vulnerability-distribution.png"
    assert chart_path.read_bytes().startswith(b"\x89PNG")
    assert "CISA KEV-listed CVEs: **1**" in report
    assert "Highest PRisk: **" in report
    assert "![Vulnerability distribution](report-vulnerability-distribution.png)" in report
    assert "| 0.9000 | yes | CVE-2024-3094 |" in report


def test_scan_real_firmware_sample():
    sample = (
        Path(__file__).parents[1]
        / "samples"
        / "openwrt-23.05.5-ath79-tiny-engenius-eap350-v1-initramfs-kernel.bin"
    )
    payload = json.dumps({"firmware_path": str(sample.resolve())})
    result = CliRunner().invoke(cli, ["scan", "--input", payload, "--json"])

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["errors"] == []
    assert envelope["findings"][0]["title"].startswith(
        "CVE-2023-39810 in busybox 1.36.1"
    )
    assert "PRisk " in envelope["findings"][0]["narrative"]
