"""Tests for static vulnerability-distribution charts."""

from __future__ import annotations

from ai_firmware_agent.analyzer import ComponentMatch
from ai_firmware_agent.charts import (
    render_vulnerability_pie,
    vulnerability_distribution,
)
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component


def _matches() -> list[ComponentMatch]:
    return [
        ComponentMatch(
            Component(name="router", version="1"),
            [
                CveRecord("CVE-C", 9.8, "critical"),
                CveRecord("CVE-H", 8.1, "high"),
                CveRecord("CVE-M", 5.0, "medium"),
                CveRecord("CVE-U", 0.0, "unscored"),
            ],
        )
    ]


def test_vulnerability_distribution_groups_cvss_severity():
    assert vulnerability_distribution(_matches()) == {
        "Critical": 1,
        "High": 1,
        "Medium": 1,
        "Unscored": 1,
    }


def test_render_vulnerability_pie_writes_png(tmp_path):
    target = tmp_path / "distribution.png"

    result = render_vulnerability_pie(_matches(), target)

    assert result == target
    assert target.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert target.stat().st_size > 1_000


def test_render_vulnerability_pie_creates_parent_directory(tmp_path):
    target = tmp_path / "assets" / "distribution.png"

    render_vulnerability_pie(_matches(), target)

    assert target.is_file()


def test_render_vulnerability_pie_skips_empty_findings(tmp_path):
    target = tmp_path / "distribution.png"

    result = render_vulnerability_pie([], target)

    assert result is None
    assert not target.exists()
