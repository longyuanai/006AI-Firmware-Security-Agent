"""Compatibility boundary for additive shared-llm-core v0.5 types.

The checked-in sibling is still v0.1.0, while the v0.5 contract defines the
types consumed by this stage.  When those official exports are present this
module re-exports them.  Until then, the exact §9 schema is provided locally so
the firmware product remains testable without changing shared-llm-core.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import shared_llm_core

if TYPE_CHECKING:
    from shared_llm_core import (
        AgentResult,
        AgentRole,
        Finding,
        FindingSeverity,
        FindingSource,
        MissionContext,
    )

    V05_NATIVE: bool
    V05_AGENT_NATIVE: bool
else:
    try:
        from shared_llm_core import Finding, FindingSeverity, FindingSource

        V05_NATIVE = True
    except ImportError:
        V05_NATIVE = False

        class FindingSource(str, Enum):  # noqa: UP042
            """Frozen v0.5 §9.3 source values."""

            SOC = "001"
            VULN = "002"
            LAB = "003"
            CODE = "004"
            REVERSE = "005"
            FIRMWARE = "006"
            EXTERNAL = "external"


        class FindingSeverity(str, Enum):  # noqa: UP042
            """Frozen v0.5 §9.4 severity values."""

            INFO = "info"
            LOW = "low"
            MEDIUM = "medium"
            HIGH = "high"
            CRITICAL = "critical"


        @dataclass(frozen=True)
        class Finding:
            """Frozen v0.5 §9.5 schema used only until shared v0.5 is installed."""

            id: str
            source: FindingSource
            severity: FindingSeverity
            confidence: float
            title: str
            description: str = ""
            host: str | None = None
            cve: str | None = None
            ts: datetime | None = None
            evidence: tuple[str, ...] = ()
            related: tuple[str, ...] = ()
            tags: frozenset[str] = frozenset()
            metadata: Mapping[str, Any] = field(default_factory=dict)

            def __post_init__(self) -> None:
                if not 0.0 <= self.confidence <= 1.0:
                    raise ValueError("Finding.confidence must be between 0.0 and 1.0")

            def to_dict(self) -> dict[str, Any]:
                """Return stable, JSON-ready fields in dataclass declaration order."""
                data = asdict(self)
                data["source"] = self.source.value
                data["severity"] = self.severity.value
                data["ts"] = self.ts.isoformat() if self.ts is not None else None
                data["evidence"] = list(self.evidence)
                data["related"] = list(self.related)
                data["tags"] = sorted(self.tags)
                data["metadata"] = dict(self.metadata)
                return {item.name: data[item.name] for item in fields(self)}

            @classmethod
            def from_dict(cls, data: dict[str, Any]) -> Finding:
                """Ignore unknown fields as required by v0.5 §9.6."""
                known = {item.name for item in fields(cls)}
                clean = {key: value for key, value in data.items() if key in known}
                clean["source"] = FindingSource(clean["source"])
                clean["severity"] = FindingSeverity(clean["severity"])
                if clean.get("ts"):
                    clean["ts"] = datetime.fromisoformat(clean["ts"])
                for key in ("evidence", "related"):
                    if key in clean:
                        clean[key] = tuple(clean[key])
                if "tags" in clean:
                    clean["tags"] = frozenset(clean["tags"])
                return cls(**clean)


    try:
        from shared_llm_core import AgentResult, AgentRole, MissionContext

        V05_AGENT_NATIVE = True
    except ImportError:
        V05_AGENT_NATIVE = False

        class AgentRole(str, Enum):  # noqa: UP042
            """Frozen v0.5 §7.3 role values."""

            SCOUT = "scout"
            ANALYST = "analyst"
            EXPLOITER = "exploiter"
            SYNTHESIZER = "synthesizer"
            REVIEWER = "reviewer"


        @dataclass(frozen=True)
        class MissionContext:
            """Frozen v0.5 §7.5 mission schema."""

            task: str
            inputs: Mapping[str, Any]
            scratchpad: tuple[str, ...] = ()
            metadata: Mapping[str, Any] = field(default_factory=dict)


        @dataclass(frozen=True)
        class AgentResult:
            """Frozen v0.5 §7.6 result schema."""

            role: AgentRole
            output: str
            findings: tuple[Finding, ...] = ()
            latency_ms: int = 0
            error: str | None = None


def new_finding(
    *,
    severity: Any,
    confidence: float,
    title: str,
    description: str = "",
    host: str | None = None,
    cve: str | None = None,
    evidence: tuple[str, ...] = (),
    related: tuple[str, ...] = (),
    tags: frozenset[str] = frozenset(),
    metadata: Mapping[str, Any] | None = None,
) -> Any:
    """Construct a firmware Finding with a fresh UUID4."""
    return Finding(
        id=str(uuid4()),
        source=FindingSource.FIRMWARE,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        host=host,
        cve=cve,
        evidence=evidence,
        related=related,
        tags=tags,
        metadata=metadata or {},
    )


def is_uuid4(value: str) -> bool:
    """Return whether ``value`` is a canonical UUID4."""
    parsed = UUID(value)
    return parsed.version == 4 and str(parsed) == value


def create_multi_agent_orchestrator(
    router: Any,
    *,
    max_concurrency: int = 4,
    scratchpad_size: int = 4096,
) -> Any:
    """Instantiate the official §7 orchestrator or report the missing layer."""
    try:
        orchestrator_type = shared_llm_core.MultiAgentOrchestrator
    except AttributeError as exc:
        raise RuntimeError(
            "shared-llm-core v0.5 MultiAgentOrchestrator is not installed"
        ) from exc
    return orchestrator_type(
        router,
        max_concurrency=max_concurrency,
        scratchpad_size=scratchpad_size,
    )
