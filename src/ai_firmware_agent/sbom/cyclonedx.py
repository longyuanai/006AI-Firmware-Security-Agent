"""CycloneDX 1.5 JSON SBOM generation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ai_firmware_agent.normalizer import Component

TEMPLATE_PATH = Path(__file__).with_name("template.json")


def _component_entry(component: Component) -> dict[str, Any]:
    name = component.name.strip()
    version = component.version.strip()
    entry: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}",
    }
    license_name = str(component.extra.get("license", "")).strip()
    if license_name:
        entry["licenses"] = [{"license": {"name": license_name}}]
    return entry


def build_cyclonedx_bom(components: list[Component]) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.5 JSON object."""
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    bom: dict[str, Any] = deepcopy(template)
    bom["components"] = [
        _component_entry(component)
        for component in sorted(
            components,
            key=lambda item: (item.name.lower(), item.version),
        )
        if component.name.strip()
    ]
    return bom


def write_cyclonedx_bom(
    components: list[Component],
    output_path: str | Path,
) -> Path:
    """Write a CycloneDX document without including firmware contents."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            build_cyclonedx_bom(components),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination
