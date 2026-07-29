"""Fail-open firmware scanner selecting binwalk or the mock parser."""

from __future__ import annotations

import tarfile
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ai_firmware_agent.binwalk_runner import BinwalkRunner, ExtractResult
from ai_firmware_agent.cve_db import CVEEntry, EmbeddedCVEDatabase
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers.binwalk import extract_components
from ai_firmware_agent.parsers.mock import parse_firmware_file
from ai_firmware_agent.providers import (
    CVEBinaryInventoryProvider,
    InventoryProvider,
    SyftInventoryProvider,
    UnblobRunner,
    collect_inventory,
    merge_components,
)
from ai_firmware_agent.v05_compat import Finding, FindingSeverity, new_finding


@dataclass
class ScanResult:
    firmware_path: Path
    components: list[Component]
    parser: str
    extraction: ExtractResult | None = None
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)


class FirmwareScanner:
    """Inventory firmware without executing any extracted content."""

    def __init__(
        self,
        runner: BinwalkRunner | None = None,
        database: EmbeddedCVEDatabase | None = None,
        secondary_runner: UnblobRunner | None = None,
        inventory_providers: Sequence[InventoryProvider] | None = None,
    ) -> None:
        self._runner = runner or BinwalkRunner()
        self._database = database or EmbeddedCVEDatabase()
        self._secondary_runner = secondary_runner or UnblobRunner()
        self._inventory_providers = tuple(
            inventory_providers
            if inventory_providers is not None
            else (
                SyftInventoryProvider(),
                CVEBinaryInventoryProvider(),
            )
        )

    @staticmethod
    def _severity(entry: CVEEntry) -> FindingSeverity:
        score = entry.cvss_v3 or 0.0
        if score >= 9.0:
            return FindingSeverity.CRITICAL
        if score >= 7.0:
            return FindingSeverity.HIGH
        if score >= 4.0:
            return FindingSeverity.MEDIUM
        if score > 0.0:
            return FindingSeverity.LOW
        return FindingSeverity.INFO

    async def _add_cve_findings(self, result: ScanResult) -> ScanResult:
        for component in result.components:
            try:
                entries = await self._database.lookup(
                    component.name,
                    component.version,
                )
            except Exception as exc:  # isolate a corrupt/unavailable local cache
                result.errors.append(
                    f"cve lookup failed for {component.name}: "
                    f"{type(exc).__name__}"
                )
                continue
            for entry in entries:
                score = entry.cvss_v3 or 0.0
                result.findings.append(
                    new_finding(
                        severity=self._severity(entry),
                        confidence=(
                            0.9 if entry.in_known_exploited else 0.75
                        ),
                        title=(
                            f"{entry.cve_id} in "
                            f"{component.name} {component.version}"
                        ),
                        description=entry.description,
                        host=str(result.firmware_path),
                        cve=entry.cve_id,
                        evidence=(
                            f"component={component.name}@{component.version}",
                            f"cpe={entry.cpe_id}",
                            f"cvss={score:.1f}",
                        ),
                        tags=frozenset({"firmware", "embedded-cve"}),
                        metadata={
                            "component": component.name,
                            "version": component.version,
                            "cvss_v3": entry.cvss_v3,
                            "in_known_exploited": (
                                entry.in_known_exploited
                            ),
                        },
                    )
                )
        return result

    async def _inventory_extraction(
        self,
        extraction: ExtractResult,
        manifest_components: list[Component],
    ) -> tuple[list[Component], list[str], list[str]]:
        inventory = await collect_inventory(
            extraction.output_dir,
            self._inventory_providers,
        )
        components = merge_components(
            manifest_components,
            inventory.components,
        )
        providers = [extraction.extractor]
        if inventory.provider != "none":
            providers.extend(inventory.provider.split("+"))
        return components, inventory.warnings, providers

    async def _extract_with(
        self,
        *,
        runner: BinwalkRunner | UnblobRunner,
        firmware: Path,
        output_dir: Path,
    ) -> tuple[ExtractResult, list[Component], list[str], list[str]]:
        extraction, manifest_components = await extract_components(
            firmware,
            output_dir=output_dir,
            runner=runner,
        )
        components, warnings, providers = await self._inventory_extraction(
            extraction,
            manifest_components,
        )
        warnings = [*extraction.warnings, *warnings]
        return extraction, components, warnings, providers

    async def scan(
        self,
        firmware_path: Path,
        *,
        output_dir: Path | None = None,
        dry_run: bool = False,
    ) -> ScanResult:
        firmware = firmware_path.resolve()
        errors: list[str] = []
        extraction: ExtractResult | None = None

        available = False
        if not dry_run:
            try:
                available = await self._runner.is_available()
            except Exception as exc:
                errors.append(
                    f"binwalk availability failed: {type(exc).__name__}"
                )
        if available:
            destination = output_dir or Path(
                tempfile.mkdtemp(prefix="firmware-binwalk-")
            )
            try:
                (
                    extraction,
                    components,
                    warnings,
                    providers,
                ) = await self._extract_with(
                    runner=self._runner,
                    firmware=firmware,
                    output_dir=destination,
                )
            except Exception as exc:
                errors.append(
                    f"binwalk extraction failed: {type(exc).__name__}"
                )
                components = []
                warnings = []
                providers = []
            errors.extend(warnings)
            if components:
                return await self._add_cve_findings(
                    ScanResult(
                        firmware_path=firmware,
                        components=components,
                        parser="+".join(providers),
                        extraction=extraction,
                        errors=errors,
                        providers=providers,
                    )
                )
            if extraction is not None and extraction.error:
                errors.append(extraction.error)
            elif extraction is not None:
                errors.append("binwalk found no component inventory")
        elif dry_run:
            errors.append("dry-run enabled; binwalk extraction skipped")
        else:
            errors.append("binwalk unavailable; using mock parser")

        secondary_available = False
        if not dry_run:
            try:
                secondary_available = (
                    await self._secondary_runner.is_available()
                )
            except Exception as exc:
                errors.append(
                    f"unblob availability failed: {type(exc).__name__}"
                )
        if secondary_available:
            if output_dir is None:
                secondary_destination = Path(
                    tempfile.mkdtemp(prefix="firmware-unblob-")
                )
            elif available:
                secondary_destination = output_dir / "unblob"
            else:
                secondary_destination = output_dir
            try:
                (
                    secondary_extraction,
                    components,
                    warnings,
                    providers,
                ) = await self._extract_with(
                    runner=self._secondary_runner,
                    firmware=firmware,
                    output_dir=secondary_destination,
                )
            except Exception as exc:
                errors.append(
                    f"unblob extraction failed: {type(exc).__name__}"
                )
                secondary_extraction = None
                components = []
                warnings = []
                providers = []
            errors.extend(warnings)
            if secondary_extraction is not None:
                extraction = secondary_extraction
            if components:
                return await self._add_cve_findings(
                    ScanResult(
                        firmware_path=firmware,
                        components=components,
                        parser="+".join(providers),
                        extraction=extraction,
                        errors=errors,
                        providers=providers,
                    )
                )
            if (
                secondary_extraction is not None
                and secondary_extraction.error
            ):
                errors.append(secondary_extraction.error)
            elif secondary_extraction is not None:
                errors.append("unblob found no component inventory")

        try:
            components = parse_firmware_file(firmware)
        except (
            OSError,
            tarfile.TarError,
            UnicodeError,
            ValueError,
            yaml.YAMLError,
        ) as exc:
            errors.append(f"mock parser failed: {type(exc).__name__}")
            components = []
        return await self._add_cve_findings(
            ScanResult(
                firmware_path=firmware,
                components=components,
                parser="mock",
                extraction=extraction,
                errors=errors,
                providers=["mock"],
            )
        )


async def scan_firmware(
    firmware_path: Path,
    *,
    output_dir: Path | None = None,
    dry_run: bool = False,
) -> ScanResult:
    """Convenience wrapper around :class:`FirmwareScanner`."""
    return await FirmwareScanner().scan(
        firmware_path,
        output_dir=output_dir,
        dry_run=dry_run,
    )
