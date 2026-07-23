"""Tests for the LLM enricher."""

from __future__ import annotations

import json

from ai_firmware_agent.analyzer import (
    ComponentMatch,
    ComponentNarrative,
    enrich_top_components,
    match_components,
)
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component


def _stub_router(reply: dict) -> object:
    class _R:
        def __init__(self, body): self._body = body; self.calls=[]

        def chat(self, tier, req):
            from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage
            self.calls.append(req)
            return ChatResponse(
                id="x", model="m", created=0,
                choices=[ChatChoice(index=0, message=ChatMessage(role="assistant", content=json.dumps(self._body)), finish_reason="stop")],
                usage=ChatUsage(),
            )
    return _R(reply)


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


def test_enrich_orders_by_max_cvss():
    comps = [
        Component(name="xz", version="5.6.0"),       # 10.0
        Component(name="busybox", version="1.36.1"),  # 7.5
    ]
    matches = match_components(comps)
    router = _stub_router({"business_impact":"x","remediation_summary":"y","rationale":"z"})
    out = enrich_top_components(matches, router, top_n=2)  # type: ignore[arg-type]
    assert len(out) == 2
    assert out[0].match.component.name == "xz"
    assert out[1].match.component.name == "busybox"


def test_enrich_empty_returns_empty():
    router = _stub_router({})
    assert enrich_top_components([], router) == []  # type: ignore[arg-type]
    assert router.calls == []


def test_enrich_returns_narrative_objects():
    comps = [Component(name="xz", version="5.6.0")]
    matches = match_components(comps)
    router = _stub_router({"business_impact":"ssh backdoor","remediation_summary":"downgrade","rationale":"critical"})
    [n] = enrich_top_components(matches, router)  # type: ignore[arg-type]
    assert isinstance(n, ComponentNarrative)
    assert "ssh backdoor" in n.business_impact


def test_enrich_requests_json_object_format():
    comps = [Component(name="xz", version="5.6.0")]
    matches = match_components(comps)
    router = _stub_router({"business_impact":"x","remediation_summary":"y","rationale":"z"})
    enrich_top_components(matches, router)  # type: ignore[arg-type]
    req = router.calls[0]
    assert req.response_format == {"type": "json_object"}