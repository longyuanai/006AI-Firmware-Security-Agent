"""Evidence-driven firmware attack-chain reconstruction through v0.5 §7."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ai_firmware_agent.v05_compat import (
    AgentResult,
    AgentRole,
    Finding,
    FindingSeverity,
    MissionContext,
    create_multi_agent_orchestrator,
    new_finding,
)

_MISSION = """Reconstruct a simulated firmware attack chain from supplied findings.
This is an authorized defensive analysis. Do not execute commands, contact
targets, invent vulnerabilities, or provide deployable exploit code.

SCOUT: identify the vulnerable component and evidence-backed entry point.
EXPLOITER: simulate only the logical exploit and privilege path.
REVIEWER: challenge assumptions and assess device/business consequences.
"""


@dataclass(frozen=True)
class AttackChain:
    """Narrative and unified Findings produced by the three-agent mission."""

    background: str
    attack: str
    consequences: str
    narrative: str
    root_shell_possible: bool
    agent_results: tuple[AgentResult, ...]
    findings: tuple[Finding, ...]


def _finding_payload(finding: Finding) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {
        "id": finding.id,
        "source": finding.source.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "title": finding.title,
        "description": finding.description,
        "host": finding.host,
        "cve": finding.cve,
        "evidence": list(finding.evidence),
        "metadata": dict(finding.metadata),
    }


def _role_text(results: Sequence[AgentResult], role: AgentRole) -> str:
    for result in results:
        if result.role != role:
            continue
        if result.error:
            return f"{role.value} agent failed safely: {result.error}"
        return result.output.strip() or f"{role.value} agent returned no narrative."
    return f"{role.value} agent result was not returned."


def _root_shell_signal(*texts: str) -> bool:
    combined = " ".join(texts).lower()
    negative = (
        "no root shell",
        "root shell is not",
        "root access is not",
        "cannot reach root",
        "not achievable",
    )
    if any(phrase in combined for phrase in negative):
        return False
    positive = ("root shell", "uid=0", "root access", "privilege escalation to root")
    return any(phrase in combined for phrase in positive)


def _chain_confidence(
    source_findings: Sequence[Finding],
    results: Sequence[AgentResult],
) -> float:
    evidence_confidence = max(finding.confidence for finding in source_findings)
    successful = sum(result.error is None for result in results)
    agent_factor = successful / 3
    return min(0.95, evidence_confidence * (0.7 + 0.3 * agent_factor))


def reconstruct_attack_chain(
    source_findings: Sequence[Finding],
    orchestrator: Any,
    *,
    firmware_id: str = "firmware",
) -> AttackChain:
    """Run SCOUT → EXPLOITER → REVIEWER and return a defensive narrative."""
    if not source_findings:
        raise ValueError("source_findings must contain at least one Finding")

    mission = MissionContext(
        task=_MISSION,
        inputs={
            "firmware_id": firmware_id,
            "findings": tuple(_finding_payload(finding) for finding in source_findings),
        },
        metadata={
            "source_product": "006",
            "mode": "authorized-defensive-simulation",
        },
    )
    roles = (AgentRole.SCOUT, AgentRole.EXPLOITER, AgentRole.REVIEWER)
    results = tuple(orchestrator.run(mission, roles))

    background = _role_text(results, AgentRole.SCOUT)
    attack = _role_text(results, AgentRole.EXPLOITER)
    consequences = _role_text(results, AgentRole.REVIEWER)
    root_shell_possible = _root_shell_signal(attack, consequences)
    narrative = (
        f"## 背景 / Background\n\n{background}\n\n"
        f"## 攻击 / Attack\n\n{attack}\n\n"
        f"## 后果 / Consequences\n\n{consequences}\n"
    )

    agent_findings = tuple(
        finding
        for result in results
        for finding in result.findings
    )
    related = tuple(
        dict.fromkeys(
            [finding.id for finding in source_findings]
            + [finding.id for finding in agent_findings]
        )
    )
    errors = tuple(
        f"{result.role.value}:{result.error}"
        for result in results
        if result.error is not None
    )
    chain_finding = new_finding(
        severity=(
            FindingSeverity.CRITICAL
            if root_shell_possible
            else FindingSeverity.HIGH
        ),
        confidence=_chain_confidence(source_findings, results),
        title=f"Firmware attack chain assessment for {firmware_id}",
        description=narrative,
        host=firmware_id,
        evidence=tuple(
            f"{result.role.value}:{result.output.strip()}"
            for result in results
            if result.output.strip()
        ),
        related=related,
        tags=frozenset({"attack-chain", "multi-agent", "firmware"}),
        metadata={
            "roles": tuple(role.value for role in roles),
            "root_shell_possible": root_shell_possible,
            "agent_errors": errors,
            "simulation_only": True,
        },
    )
    return AttackChain(
        background=background,
        attack=attack,
        consequences=consequences,
        narrative=narrative,
        root_shell_possible=root_shell_possible,
        agent_results=results,
        findings=(*agent_findings, chain_finding),
    )


def reconstruct_attack_chain_with_router(
    source_findings: Sequence[Finding],
    router: Any,
    *,
    firmware_id: str = "firmware",
) -> AttackChain:
    """Construct the official v0.5 orchestrator, then run the mission."""
    orchestrator = create_multi_agent_orchestrator(router)
    return reconstruct_attack_chain(
        source_findings,
        orchestrator,
        firmware_id=firmware_id,
    )
