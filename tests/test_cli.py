"""Tests for the CLI."""

from __future__ import annotations

from click.testing import CliRunner

from ai_firmware_agent.cli import cli


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


def test_cli_scan_help_lists_nvd_api_key():
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", "--help"])
    assert res.exit_code == 0
    assert "--nvd-api-key" in res.output
    assert "--use-epss" in res.output
