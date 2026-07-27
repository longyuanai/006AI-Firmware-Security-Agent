"""HTML report rendering.

tech-spec section 3 lists HTML as a "Should" that was never built, while
jinja2 sat in pyproject as a dependency with zero references in the source
tree. Every value rendered here — component names, versions, CVE
descriptions — comes from untrusted firmware, so escaping is the load-bearing
requirement, not a nice-to-have.
"""

from __future__ import annotations

from click.testing import CliRunner

from ai_firmware_agent.analyzer import ComponentMatch, ComponentNarrative
from ai_firmware_agent.cli import cli
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.html_report import build_context, render_html
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware


def _component(name="lighttpd", version="1.4.50", **extra) -> Component:
    return Component(name=name, version=version, vendor="v", extra=extra)


def _match(component, cves) -> ComponentMatch:
    return ComponentMatch(component=component, cves=cves)


def _narrative(match) -> ComponentNarrative:
    return ComponentNarrative(
        match=match,
        business_impact="Attackers gain remote access.",
        remediation_summary="Upgrade to 1.4.56.",
        rationale="CVE is remotely exploitable.",
        raw_response={},
    )


def test_render_is_well_formed_html():
    html = render_html([], [], [])
    assert html.strip().startswith("<!DOCTYPE html>")
    assert html.strip().endswith("</html>")
    assert html.count("<table") == html.count("</table>")


def test_render_includes_summary_counts():
    component = _component()
    match = _match(component, [CveRecord(cve="CVE-2018-19052", cvss=9.8, summary="x")])
    html = render_html([component], [match], [])
    assert ">1<" in html  # component count and vulnerable count both render


def test_render_includes_inventory_table_row():
    component = _component()
    match = _match(component, [CveRecord(cve="CVE-2018-19052", cvss=9.8, summary="x")])
    html = render_html([component], [match], [])
    assert "lighttpd" in html
    assert "1.4.50" in html
    assert "CVE-2018-19052" in html


def test_render_includes_narrative_section():
    component = _component()
    match = _match(component, [CveRecord(cve="CVE-2018-19052", cvss=9.8, summary="x")])
    html = render_html([component], [match], [_narrative(match)])
    assert "Attackers gain remote access." in html
    assert "Upgrade to 1.4.56." in html


def test_render_without_narratives_says_so():
    html = render_html([], [], [])
    assert "No LLM enrichment produced." in html


def test_render_surfaces_detector_evidence():
    component = _component(detector="opkg", evidence="opkg:usr/lib/opkg/status")
    html = render_html([component], [], [])
    assert "opkg" in html
    assert "usr/lib/opkg/status" in html


def test_component_name_is_escaped():
    """A component name is attacker-influenced; it must never inject markup."""
    component = _component(name='<script>alert(1)</script>')
    html = render_html([component], [], [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_cve_summary_is_escaped_in_the_narrative_section():
    component = _component()
    record = CveRecord(cve="CVE-2025-0001", cvss=9.0, summary="<img src=x onerror=alert(1)>")
    match = _match(component, [record])
    narrative = ComponentNarrative(
        match=match,
        business_impact='<b onmouseover="steal()">bold</b>',
        remediation_summary="ok",
        rationale="ok",
        raw_response={},
    )
    html = render_html([component], [match], [narrative])
    assert "<b onmouseover=" not in html
    assert "&lt;b onmouseover=" in html


def test_component_version_attribute_breakout_is_escaped():
    """A version string cannot close an HTML attribute early."""
    component = _component(version='1.0"><svg onload=alert(1)>')
    html = render_html([component], [], [])
    assert "<svg onload=alert(1)>" not in html


def test_evidence_path_is_escaped():
    component = _component(evidence='<a href="javascript:alert(1)">x</a>')
    html = render_html([component], [], [])
    assert '<a href="javascript:alert(1)">' not in html


def test_build_context_matches_components_to_their_cves_by_identity_and_value():
    identity_match = _component(name="dropbear", version="2020.80")
    value_component = _component(name="dropbear", version="2020.80")
    match = _match(identity_match, [CveRecord(cve="CVE-2021-28041", cvss=6.8, summary="x")])

    context = build_context([identity_match, value_component], [match], [])
    rows = {row["name"]: row for row in context["rows"]}
    assert rows["dropbear"]["cve_count"] == 1


def test_kev_marker_renders_yes_and_no():
    kev_component = _component(name="a")
    other = _component(name="b")
    kev_match = _match(
        kev_component,
        [CveRecord(cve="CVE-2024-1", cvss=9.0, summary="x", kev=True)],
    )
    html = render_html([kev_component, other], [kev_match], [])
    assert ">yes<" in html
    assert ">no<" in html or ">-<" in html


def test_chart_is_inlined_as_a_data_uri(tmp_path):
    png = tmp_path / "chart.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 16)
    html = render_html([], [], [], chart_path=png)
    assert "data:image/png;base64," in html
    assert str(png) not in html


def test_missing_chart_path_does_not_crash():
    html = render_html([], [], [], chart_path=None)
    assert "data:image/png;base64," not in html


def _firmware(tmp_path):
    path = tmp_path / "firmware.tar.gz"
    path.write_bytes(make_demo_firmware([_component()]))
    return path


def test_cli_scan_writes_html_when_requested(tmp_path, stub_router_factory):
    stub_router_factory({})
    output = tmp_path / "report.html"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(_firmware(tmp_path)),
            "--output",
            str(output),
            "--format",
            "html",
            "--cve-source",
            "mock",
            "--top-n",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    content = output.read_text(encoding="utf-8")
    assert content.strip().startswith("<!DOCTYPE html>")
    assert "lighttpd" in content


def test_cli_default_format_is_still_markdown(tmp_path, stub_router_factory):
    stub_router_factory({})
    output = tmp_path / "report.md"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(_firmware(tmp_path)),
            "--output",
            str(output),
            "--cve-source",
            "mock",
            "--top-n",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert output.read_text(encoding="utf-8").startswith("# Firmware Security Report")


def test_scan_help_lists_format_option():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
