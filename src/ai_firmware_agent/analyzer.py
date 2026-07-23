"""Stage-2 enricher: ask the LLM for a business narrative per vulnerable component."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from shared_llm_core import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    LLMRouter,
)
from shared_llm_core.router import TaskTier

from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component


@dataclass(frozen=True)
class ComponentMatch:
    component: Component
    cves: list[CveRecord]

    @property
    def max_cvss(self) -> float:
        return max((c.cvss for c in self.cves), default=0.0)

    @property
    def max_epss(self) -> float:
        return max((c.epss for c in self.cves), default=0.0)


@dataclass(frozen=True)
class ComponentNarrative:
    match: ComponentMatch
    business_impact: str
    remediation_summary: str
    rationale: str
    raw_response: dict[str, Any]

    def to_markdown(self) -> str:
        cves_md = ", ".join(
            f"`{c.cve}` (CVSS {c.cvss:.1f}, EPSS {c.epss:.4f})"
            for c in self.match.cves
        )
        return (
            f"### {self.match.component.name} {self.match.component.version}"
            f"  \n_vendor: {self.match.component.vendor or 'unknown'}_  \n"
            f"- **CVEs**: {cves_md}\n"
            f"- **Max CVSS**: {self.match.max_cvss:.1f}\n"
            f"- **Business impact**: {self.business_impact}\n"
            f"- **Remediation**: {self.remediation_summary}\n"
            f"- **Rationale**: {self.rationale}\n"
        )


_SYSTEM = """You are a firmware-security analyst assistant.
Given one vulnerable component (name + version + vendor) and its CVE list,
produce strict JSON:

{
  "business_impact": "1-2 sentence impact for a product manager (devices affected, attacker capability)",
  "remediation_summary": "1-2 sentence concrete remediation (upgrade target, vendor advisory, or workaround)",
  "rationale": "1 sentence tying impact to the listed CVEs"
}

Never invent CVEs. Only reference CVEs provided in the input. Output JSON only."""


_USER_TEMPLATE = """Component:
{component_json}

Known CVEs:
{cves_json}

Return JSON only."""


def _strip(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        return text.strip()
    return text


def match_components(
    components: list[Component],
    lookup_fn: Callable[[Component], list[CveRecord]] = mock_lookup,
) -> list[ComponentMatch]:
    """Look up components with the selected CVE provider."""
    matches: list[ComponentMatch] = []
    for component in components:
        cves = lookup_fn(component)
        if cves:
            matches.append(ComponentMatch(component, cves))
    return matches


def _parse(match: ComponentMatch, resp: ChatResponse) -> ComponentNarrative:
    data = json.loads(_strip(resp.choices[0].message.content))
    return ComponentNarrative(
        match=match,
        business_impact=str(data.get("business_impact", "")),
        remediation_summary=str(data.get("remediation_summary", "")),
        rationale=str(data.get("rationale", "")),
        raw_response=data,
    )


def enrich_top_components(
    matches: list[ComponentMatch],
    router: LLMRouter,
    *,
    top_n: int = 3,
) -> list[ComponentNarrative]:
    """Enrich the top-N matches (highest CVSS first) via the LLM."""
    if not matches:
        return []
    ordered = sorted(matches, key=lambda m: m.max_cvss, reverse=True)
    out: list[ComponentNarrative] = []
    for m in ordered[:top_n]:
        blob = {
            "component": m.component.to_prompt_dict(),
            "cves": [
                {
                    "cve": c.cve,
                    "cvss": c.cvss,
                    "epss": c.epss,
                    "summary": c.summary,
                }
                for c in m.cves
            ],
        }
        req = ChatRequest(
            messages=[
                ChatMessage(role="system", content=_SYSTEM),
                ChatMessage(
                    role="user",
                    content=_USER_TEMPLATE.format(
                        component_json=json.dumps(blob["component"], indent=2),
                        cves_json=json.dumps(blob["cves"], indent=2),
                    ),
                ),
            ],
            temperature=0.2,
            max_tokens=400,
            response_format={"type": "json_object"},
        )
        resp = router.chat(TaskTier.STANDARD, req)
        out.append(_parse(m, resp))
    return out
