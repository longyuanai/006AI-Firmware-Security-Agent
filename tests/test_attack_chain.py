"""Tests for v0.5 §7 firmware attack-chain reconstruction."""

from __future__ import annotations

import pytest
import shared_llm_core

from ai_firmware_agent.attack_chain import (
    reconstruct_attack_chain,
    reconstruct_attack_chain_with_router,
)
from ai_firmware_agent.v05_compat import (
    AgentResult,
    AgentRole,
    FindingSeverity,
    MissionContext,
    new_finding,
)


def _source(confidence: float = 0.9):
    return new_finding(
        severity=FindingSeverity.HIGH,
        confidence=confidence,
        title="lighttpd path traversal",
        host="lighttpd",
        cve="CVE-2018-19052",
        evidence=("listener:tcp:0.0.0.0:80",),
    )


class StubOrchestrator:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def run(self, mission, roles):
        self.calls.append((mission, tuple(roles)))
        return self.results


def _results(exploit: str = "Traversal reaches a root shell.", reviewer: str = "Root access impacts all device secrets."):
    return [
        AgentResult(
            role=AgentRole.SCOUT,
            output="lighttpd on TCP 80 is the evidence-backed entry point.",
        ),
        AgentResult(role=AgentRole.EXPLOITER, output=exploit),
        AgentResult(role=AgentRole.REVIEWER, output=reviewer),
    ]


def test_orchestrator_receives_frozen_roles_and_mission_context():
    orchestrator = StubOrchestrator(_results())
    source = _source()
    reconstruct_attack_chain([source], orchestrator, firmware_id="router-a")
    mission, roles = orchestrator.calls[0]
    assert isinstance(mission, MissionContext)
    assert roles == (
        AgentRole.SCOUT,
        AgentRole.EXPLOITER,
        AgentRole.REVIEWER,
    )
    assert mission.inputs["findings"][0]["id"] == source.id
    assert mission.metadata["mode"] == "authorized-defensive-simulation"


def test_narrative_has_background_attack_and_consequence_sections():
    chain = reconstruct_attack_chain([_source()], StubOrchestrator(_results()))
    assert "## 背景 / Background" in chain.narrative
    assert "## 攻击 / Attack" in chain.narrative
    assert "## 后果 / Consequences" in chain.narrative
    assert "lighttpd" in chain.background


def test_root_shell_signal_creates_critical_chain_finding():
    chain = reconstruct_attack_chain([_source()], StubOrchestrator(_results()))
    assert chain.root_shell_possible is True
    finding = chain.findings[-1]
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.metadata["simulation_only"] is True
    assert finding.metadata["roles"] == ("scout", "exploiter", "reviewer")


def test_negative_review_prevents_false_root_shell_signal():
    chain = reconstruct_attack_chain(
        [_source()],
        StubOrchestrator(
            _results(
                exploit="The path traversal reads a public file.",
                reviewer="No root shell is achievable from this evidence.",
            )
        ),
    )
    assert chain.root_shell_possible is False
    assert chain.findings[-1].severity == FindingSeverity.HIGH


def test_agent_failure_is_reported_without_raising():
    results = _results()
    results[1] = AgentResult(
        role=AgentRole.EXPLOITER,
        output="",
        error="provider timeout",
    )
    chain = reconstruct_attack_chain([_source()], StubOrchestrator(results))
    assert "failed safely: provider timeout" in chain.attack
    assert chain.findings[-1].metadata["agent_errors"] == (
        "exploiter:provider timeout",
    )
    assert chain.findings[-1].confidence == pytest.approx(0.81)


def test_agent_findings_are_aggregated_and_related():
    scout_finding = new_finding(
        severity=FindingSeverity.MEDIUM,
        confidence=0.7,
        title="port 80 exposed",
    )
    results = _results()
    results[0] = AgentResult(
        role=AgentRole.SCOUT,
        output="HTTP listener found.",
        findings=(scout_finding,),
    )
    source = _source()
    chain = reconstruct_attack_chain([source], StubOrchestrator(results))
    assert chain.findings[0] == scout_finding
    assert chain.findings[-1].related == (source.id, scout_finding.id)


def test_empty_source_findings_are_rejected_before_orchestration():
    orchestrator = StubOrchestrator(_results())
    with pytest.raises(ValueError, match="source_findings"):
        reconstruct_attack_chain([], orchestrator)
    assert orchestrator.calls == []


def test_router_helper_reports_missing_shared_v05_orchestrator(monkeypatch):
    monkeypatch.delattr(shared_llm_core, "MultiAgentOrchestrator", raising=False)
    with pytest.raises(RuntimeError, match="MultiAgentOrchestrator"):
        reconstruct_attack_chain_with_router([_source()], object())
