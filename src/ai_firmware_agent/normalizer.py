"""Component inventory entry. One per package / binary in the firmware."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    """A single software component inside the firmware."""

    name: str
    version: str
    vendor: str = ""
    category: str = ""  # e.g. "web_server", "crypto", "os_lib"
    path: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "vendor": self.vendor,
            "category": self.category,
        }