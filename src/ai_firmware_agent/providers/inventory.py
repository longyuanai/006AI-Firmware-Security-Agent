"""Optional component inventory providers and evidence-aware merging."""

from __future__ import annotations

import asyncio
import json
import shutil
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.providers.base import (
    InventoryProvider,
    InventoryResult,
    ToolCapability,
)


def _safe_diagnostic(raw: bytes, root: Path) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    return text.replace(str(root), "<rootfs>")[:2048]


def _location_path(artifact: dict[str, Any]) -> str:
    locations = artifact.get("locations")
    if not isinstance(locations, list):
        return ""
    for location in locations:
        if isinstance(location, dict):
            path = location.get("path")
            if isinstance(path, str):
                return path
    return ""


def _license_name(artifact: dict[str, Any]) -> str:
    licenses = artifact.get("licenses")
    if not isinstance(licenses, list):
        return ""
    for license_item in licenses:
        if isinstance(license_item, str):
            return license_item
        if isinstance(license_item, dict):
            for key in ("value", "spdxExpression", "name"):
                value = license_item.get(key)
                if isinstance(value, str) and value:
                    return value
    return ""


def parse_syft_inventory(payload: Any) -> list[Component]:
    """Translate Syft JSON artifacts into the project's Component model."""
    if not isinstance(payload, dict):
        return []
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return []

    components: list[Component] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name", "")).strip()
        version = str(artifact.get("version", "")).strip()
        if not name:
            continue
        extra: dict[str, Any] = {
            "detection_sources": ["syft"],
            "confidence": 0.9,
        }
        purl = str(artifact.get("purl", "")).strip()
        if purl:
            extra["purl"] = purl
        license_name = _license_name(artifact)
        if license_name:
            extra["license"] = license_name
        components.append(
            Component(
                name=name,
                version=version,
                category=str(artifact.get("type", "")).strip(),
                path=_location_path(artifact),
                extra=extra,
            )
        )
    return components


def _walk_cve_bin_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        product = value.get("product") or value.get("component")
        version = value.get("version")
        if isinstance(product, str) and isinstance(version, (str, int, float)):
            yield value
        for nested in value.values():
            yield from _walk_cve_bin_records(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_cve_bin_records(nested)


def parse_cve_bin_inventory(payload: Any) -> list[Component]:
    """Recover unique component identities from CVE Binary Tool JSON."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    for record in _walk_cve_bin_records(payload):
        name = str(record.get("product") or record.get("component") or "").strip()
        version = str(record.get("version", "")).strip()
        key = (name.casefold(), version)
        if not name or key in seen:
            continue
        seen.add(key)
        path = str(
            record.get("path")
            or record.get("filename")
            or record.get("evidence")
            or ""
        ).strip()
        components.append(
            Component(
                name=name,
                version=version,
                vendor=str(record.get("vendor", "")).strip(),
                category="binary",
                path=path,
                extra={
                    "detection_sources": ["cve-bin-tool"],
                    "confidence": 0.85,
                },
            )
        )
    return components


def _component_confidence(component: Component) -> float:
    try:
        value = float(component.extra.get("confidence", 0.5))
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, value))


class _JsonCliInventoryProvider:
    name = ""
    executable = ""
    features: tuple[str, ...] = ()

    def __init__(self, executable: str | None = None, *, timeout: int = 120) -> None:
        self._executable = executable or self.executable
        self._timeout = timeout

    async def capability(self) -> ToolCapability:
        available = shutil.which(self._executable) is not None
        return ToolCapability(
            name=self.name,
            available=available,
            reason="" if available else "executable not found on PATH",
            features=self.features,
        )

    def command(self, root: Path) -> tuple[str, ...]:
        raise NotImplementedError

    def parse(self, payload: Any) -> list[Component]:
        raise NotImplementedError

    async def inventory(self, root: Path) -> InventoryResult:
        resolved = root.resolve()
        if not resolved.is_dir():
            return InventoryResult(
                provider=self.name,
                warnings=["inventory root is not a directory"],
            )
        try:
            process = await asyncio.create_subprocess_exec(
                *self.command(resolved),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return InventoryResult(
                provider=self.name,
                warnings=[f"{self.name} unavailable: {type(exc).__name__}"],
            )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self._timeout,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return InventoryResult(
                provider=self.name,
                warnings=[f"{self.name} timed out after {self._timeout}s"],
            )
        if process.returncode:
            detail = _safe_diagnostic(stderr or stdout, resolved)
            warning = f"{self.name} exited with status {process.returncode}"
            if detail:
                warning = f"{warning}: {detail}"
            return InventoryResult(provider=self.name, warnings=[warning])
        try:
            payload: Any = json.loads(stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            return InventoryResult(
                provider=self.name,
                warnings=[f"{self.name} returned invalid JSON: {type(exc).__name__}"],
            )
        return InventoryResult(provider=self.name, components=self.parse(payload))


class SyftInventoryProvider(_JsonCliInventoryProvider):
    """Inventory package metadata in an extracted rootfs using Syft."""

    name = "syft"
    executable = "syft"
    features = ("filesystem-inventory", "purl", "licenses")

    def command(self, root: Path) -> tuple[str, ...]:
        return (self._executable, f"dir:{root}", "-o", "syft-json")

    def parse(self, payload: Any) -> list[Component]:
        return parse_syft_inventory(payload)


class CVEBinaryInventoryProvider(_JsonCliInventoryProvider):
    """Use CVE Binary Tool checkers in offline component-discovery mode."""

    name = "cve-bin-tool"
    executable = "cve-bin-tool"
    features = ("binary-version-checkers", "offline-cache")

    def command(self, root: Path) -> tuple[str, ...]:
        return (
            self._executable,
            "--offline",
            "--format",
            "json",
            str(root),
        )

    def parse(self, payload: Any) -> list[Component]:
        return parse_cve_bin_inventory(payload)


def merge_components(*inventories: Iterable[Component]) -> list[Component]:
    """Merge component evidence while keeping deterministic identities."""
    grouped: dict[tuple[str, str], list[Component]] = defaultdict(list)
    for inventory in inventories:
        for component in inventory:
            name = component.name.strip()
            version = component.version.strip()
            if name:
                grouped[(name.casefold(), version)].append(component)

    merged: list[Component] = []
    for key in sorted(grouped):
        candidates = grouped[key]
        primary = max(
            candidates,
            key=_component_confidence,
        )
        sources: set[str] = set()
        evidence_paths: set[str] = set()
        confidence = 0.0
        licenses: set[str] = set()
        purl = ""
        for candidate in candidates:
            raw_sources = candidate.extra.get("detection_sources", [])
            if isinstance(raw_sources, str):
                sources.add(raw_sources)
            elif isinstance(raw_sources, list):
                sources.update(str(item) for item in raw_sources if item)
            if candidate.path:
                evidence_paths.add(candidate.path)
            confidence = max(
                confidence,
                _component_confidence(candidate),
            )
            license_name = str(candidate.extra.get("license", "")).strip()
            if license_name:
                licenses.add(license_name)
            if not purl:
                purl = str(candidate.extra.get("purl", "")).strip()
        extra = dict(primary.extra)
        extra["detection_sources"] = sorted(sources)
        extra["evidence_paths"] = sorted(evidence_paths)
        extra["confidence"] = min(
            0.99,
            confidence + 0.03 * max(0, len(sources) - 1),
        )
        if licenses:
            extra["licenses"] = sorted(licenses)
            extra["license"] = sorted(licenses)[0]
        if purl:
            extra["purl"] = purl
        merged.append(
            Component(
                name=primary.name.strip(),
                version=primary.version.strip(),
                vendor=next(
                    (item.vendor for item in candidates if item.vendor),
                    "",
                ),
                category=next(
                    (item.category for item in candidates if item.category),
                    "",
                ),
                path=next(
                    (item.path for item in candidates if item.path),
                    "",
                ),
                extra=extra,
            )
        )
    return merged


async def collect_inventory(
    root: Path,
    providers: Iterable[InventoryProvider],
) -> InventoryResult:
    """Run available providers and merge their evidence without hard failure."""
    components: list[list[Component]] = []
    warnings: list[str] = []
    used: list[str] = []
    for provider in providers:
        try:
            capability = await provider.capability()
        except Exception as exc:  # third-party adapter isolation boundary
            warnings.append(
                f"{provider.name} capability failed: {type(exc).__name__}"
            )
            continue
        if not capability.available:
            continue
        try:
            result = await provider.inventory(root)
        except Exception as exc:  # third-party adapter isolation boundary
            warnings.append(
                f"{provider.name} inventory failed: {type(exc).__name__}"
            )
            continue
        used.append(result.provider)
        components.append(result.components)
        warnings.extend(result.warnings)
    return InventoryResult(
        provider="+".join(used) if used else "none",
        components=merge_components(*components),
        warnings=warnings,
    )


__all__ = [
    "CVEBinaryInventoryProvider",
    "SyftInventoryProvider",
    "collect_inventory",
    "merge_components",
    "parse_cve_bin_inventory",
    "parse_syft_inventory",
]
