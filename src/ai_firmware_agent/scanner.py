"""Fail-open firmware scanner selecting binwalk or the mock parser."""

from __future__ import annotations

import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ai_firmware_agent.binwalk_runner import BinwalkRunner, ExtractResult
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers.binwalk import extract_components
from ai_firmware_agent.parsers.mock import parse_firmware_file


@dataclass
class ScanResult:
    firmware_path: Path
    components: list[Component]
    parser: str
    extraction: ExtractResult | None = None
    errors: list[str] = field(default_factory=list)


class FirmwareScanner:
    """Inventory firmware without executing any extracted content."""

    def __init__(self, runner: BinwalkRunner | None = None) -> None:
        self._runner = runner or BinwalkRunner()

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

        available = False if dry_run else await self._runner.is_available()
        if available:
            destination = output_dir or Path(
                tempfile.mkdtemp(prefix="firmware-binwalk-")
            )
            extraction, components = await extract_components(
                firmware,
                output_dir=destination,
                runner=self._runner,
            )
            if components:
                return ScanResult(
                    firmware_path=firmware,
                    components=components,
                    parser="binwalk",
                    extraction=extraction,
                )
            if extraction.error:
                errors.append(extraction.error)
            else:
                errors.append("binwalk found no component manifest")
        elif dry_run:
            errors.append("dry-run enabled; binwalk extraction skipped")
        else:
            errors.append("binwalk unavailable; using mock parser")

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
        return ScanResult(
            firmware_path=firmware,
            components=components,
            parser="mock",
            extraction=extraction,
            errors=errors,
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
