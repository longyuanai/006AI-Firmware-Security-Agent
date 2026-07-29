"""CLI capability reporting must not execute firmware or external tools."""

from __future__ import annotations

import json
import shutil

from click.testing import CliRunner

from ai_firmware_agent.cli import cli


def test_capabilities_json_is_object(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda command: rf"C:\Tools\{command}.exe"
        if command in {"binwalk", "syft"}
        else None,
    )
    result = CliRunner().invoke(cli, ["capabilities", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, dict)
    assert len(payload["tools"]) == 4


def test_capabilities_reports_available_tools(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda command: command if command == "binwalk" else None,
    )
    result = CliRunner().invoke(cli, ["capabilities", "--json"])
    tools = {item["name"]: item for item in json.loads(result.output)["tools"]}
    assert tools["binwalk"]["available"] is True
    assert tools["unblob"]["available"] is False


def test_capabilities_text_mode(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _command: None)
    result = CliRunner().invoke(cli, ["capabilities"])
    assert result.exit_code == 0
    assert "binwalk: unavailable" in result.output
    assert "cve-bin-tool: unavailable" in result.output
