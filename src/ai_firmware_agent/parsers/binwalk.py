"""Translate BinwalkRunner extraction metadata into component inventory."""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.binwalk_runner import BinwalkRunner, ExtractResult
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers.mock import components_from_manifest


def parse_binwalk_result(result: ExtractResult) -> list[Component]:
    """Read only extracted component manifests; never execute extracted files."""
    root = result.output_dir.resolve()
    manifests = sorted(
        (
            path
            for path in result.files
            if path.name in {"manifest.yml", "manifest.yaml"}
        ),
        key=str,
    )
    for manifest in manifests:
        try:
            resolved = manifest.resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_file() or not resolved.is_relative_to(root):
            continue
        components = components_from_manifest(
            resolved.read_text(encoding="utf-8", errors="replace")
        )
        if components:
            return components
    return []


async def extract_components(
    firmware_path: Path,
    *,
    output_dir: Path,
    runner: BinwalkRunner,
) -> tuple[ExtractResult, list[Component]]:
    """Run binwalk extraction and parse safe metadata manifests."""
    result = await runner.extract(firmware_path, output_dir=output_dir)
    if result.error:
        return result, []
    return result, parse_binwalk_result(result)


__all__ = ["ExtractResult", "extract_components", "parse_binwalk_result"]
