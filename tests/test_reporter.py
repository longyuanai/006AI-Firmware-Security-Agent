"""Tests for the Markdown reporter."""

from __future__ import annotations

from ai_firmware_agent.analyzer import ComponentMatch, ComponentNarrative
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component


def _c(name, version) -> Component:
    return Component(name=name, version=version, vendor="v")


def _b(c, cves):
    return ComponentMatch(component=c, cves=cves)


def _n(m):
    return ComponentNarrative(
        match=m,
        business_impact="BI",
        remediation_summary="RS",
        rationale="RT",
        raw_response={},
    )


def test_render_summary_counts_components():
    cs = [_c("a", "1.0"), _c("b", "2.0")]
    ms = [_b(cs[0], [CveRecord("CVE-X", 5.0, "x")])]
    md = _r(cs, ms, [])
    assert "Components inventoried: **2**" in md
    assert "Components with known CVEs: **1**" in md


def test_render_includes_worst_cvss():
    cs = [_c("a", "1.0")]
    ms = [_b(cs[0], [CveRecord("CVE-X", 9.8, "x")])]
    md = _r(cs, ms, [])
    assert "Worst CVSS in firmware: **9.8**" in md


def test_render_includes_max_epss():
    cs = [_c("a", "1.0")]
    ms = [_b(cs[0], [CveRecord("CVE-X", 9.8, "x", epss=0.8123)])]
    md = _r(cs, ms, [])
    assert "| 0.8123 | no | CVE-X |" in md


def test_render_includes_kev_count_and_marker():
    cs = [_c("a", "1.0")]
    ms = [_b(cs[0], [CveRecord("CVE-X", 9.8, "x", kev=True)])]
    md = _r(cs, ms, [])
    assert "CISA KEV-listed CVEs: **1**" in md
    assert "| yes | CVE-X |" in md


def test_render_includes_inventory_table():
    cs = [_c("a", "1.0"), _c("b", "2.0")]
    md = _r(cs, [], [])
    assert "| a | 1.0 |" in md
    assert "| b | 2.0 |" in md


def test_render_includes_narrative_section():
    cs = [_c("a", "1.0")]
    m = _b(cs[0], [CveRecord("CVE-X", 5.0, "x")])
    md = _r(cs, [m], [_n(m)])
    assert "Top Risks (LLM-enriched)" in md
    assert "CVE-X" in md


def _r(components, matches, narratives):
    from ai_firmware_agent.reporter import render_markdown
    return render_markdown(components, matches, narratives, source_path="test.tar.gz")
