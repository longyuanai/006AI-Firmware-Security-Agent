"""Shared contracts for optional external firmware-analysis providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ai_firmware_agent.normalizer import Component


@dataclass(frozen=True)
class ToolCapability:
    """Describe one optional tool without making it a hard dependency."""

    name: str
    available: bool
    version: str = ""
    mode: str = "local"
    reason: str = ""
    features: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-ready representation."""
        return {
            "name": self.name,
            "available": self.available,
            "version": self.version,
            "mode": self.mode,
            "reason": self.reason,
            "features": list(self.features),
        }


@dataclass
class InventoryResult:
    """Normalized component inventory emitted by one provider."""

    provider: str
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class InventoryProvider(Protocol):
    """Structural contract implemented by optional inventory tools."""

    name: str

    async def capability(self) -> ToolCapability:
        """Report whether this provider can run."""

    async def inventory(self, root: Path) -> InventoryResult:
        """Inventory an extracted filesystem without executing its content."""


__all__ = ["InventoryProvider", "InventoryResult", "ToolCapability"]
