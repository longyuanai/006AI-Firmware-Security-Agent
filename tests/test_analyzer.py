"""Tests for the LLM enricher.

After the v0.1-contract §5 refactor, ``StubRouter`` lives in
``tests/conftest.py`` and is injected via the ``stub_router`` fixture.
"""

from __future__ import annotations

from ai_firmware_agent.analyzer import (
    ComponentMatch,
    ComponentNarrative,
    enrich_top_components,
    match_components,
)
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component


def test_match_finds_vulnerable_components_only():
    comps = [
        Component(name="busybox", version="1.36.1"),
        Component(name="unknown-thing", version="1.0.0"),  # no CVEs
    ]
    matches = match_components(comps)
    assert len(matches) == 1
    assert matches[0].component.name == "busybox"


def test_match_max_cvss_correct():
    comps = [Component(name="openssl", version="1.1.0")]
    matches = match_components(comps)
    assert matches[0].max_cvss >= 5.0


def test_match_accepts_injected_lookup():
    component = Component(name="custom", version="1.0")
    calls = []

    def lookup(candidate):
        calls.append(candidate)
        return [CveRecord("CVE-TEST-1", 4.2, "stub")]

    matches = match_components([component], lookup_fn=lookup)
    assert calls == [component]
    assert matches[0].cves[0].cve == "CVE-TEST-1"


def test_enrich_orders_by_max_cvss(stub_router_with):
    comps = [
        Component(name="xz", version="5.6.0"),       # 10.0
        Component(name="busybox", version="1.36.1"),  # 7.5
    ]
    matches = match_components(comps)
    router = stub_router_with({"business_impact": "x", "remediation_summary": "y", "rationale": "z"})
    out = enrich_top_components(matches, router, top_n=2)  # type: ignore[arg-type]
    assert len(out) == 2
    assert out[0].match.component.name == "xz"
    assert out[1].match.component.name == "busybox"


def test_enrich_orders_by_prisk_when_threat_intelligence_differs(stub_router_with):
    high_cvss = ComponentMatch(
        Component(name="high-cvss", version="1", category="compression"),
        [CveRecord("CVE-HIGH", 9.0, "high")],
    )
    active = ComponentMatch(
        Component(name="active", version="1", category="remote_access"),
        [CveRecord("CVE-ACTIVE", 7.0, "active", epss=0.9, kev=True)],
    )
    router = stub_router_with(
        {"business_impact": "x", "remediation_summary": "y", "rationale": "z"}
    )

    out = enrich_top_components([high_cvss, active], router, top_n=2)  # type: ignore[arg-type]

    assert out[0].match.component.name == "active"


def test_enrich_empty_returns_empty(stub_router_with):
    router = stub_router_with({})
    assert enrich_top_components([], router) == []  # type: ignore[arg-type]
    assert router.calls == []


def test_enrich_returns_narrative_objects(stub_router_with):
    comps = [Component(name="xz", version="5.6.0")]
    matches = match_components(comps)
    router = stub_router_with({"business_impact": "ssh backdoor", "remediation_summary": "downgrade", "rationale": "critical"})
    [n] = enrich_top_components(matches, router)  # type: ignore[arg-type]
    assert isinstance(n, ComponentNarrative)
    assert "ssh backdoor" in n.business_impact


def test_enrich_requests_json_object_format(stub_router_with):
    comps = [Component(name="xz", version="5.6.0")]
    matches = match_components(comps)
    router = stub_router_with({"business_impact": "x", "remediation_summary": "y", "rationale": "z"})
    enrich_top_components(matches, router)  # type: ignore[arg-type]
    req = router.calls[0]
    assert req.response_format == {"type": "json_object"}
