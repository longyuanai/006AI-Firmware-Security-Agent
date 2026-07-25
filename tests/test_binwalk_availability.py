"""Availability checks never require a real binwalk installation."""

from __future__ import annotations

import asyncio
import shutil

from ai_firmware_agent.binwalk_runner import BinwalkRunner


def test_binwalk_unavailable(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _command: None)
    assert asyncio.run(BinwalkRunner().is_available()) is False


def test_binwalk_available_on_windows_path(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda _command: r"C:\Tools\binwalk.exe",
    )
    assert asyncio.run(BinwalkRunner().is_available()) is True
