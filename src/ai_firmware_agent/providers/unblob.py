"""Optional unblob extraction provider.

The provider invokes the external CLI only.  It does not import unblob and
therefore does not add a production dependency to the firmware agent.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Any

from ai_firmware_agent.binwalk_runner import ExtractResult, collect_extracted_files
from ai_firmware_agent.providers.base import ToolCapability


def _safe_error(raw: bytes, firmware: Path) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    return text.replace(str(firmware), "<firmware>")[:2048]


def _signatures_from_report(report_path: Path) -> list[str]:
    try:
        payload: Any = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []

    signatures: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key in ("handler_name", "handler", "magic", "description"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    signatures.add(candidate.strip())
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    return sorted(signatures)


class UnblobRunner:
    """Run unblob with bounded recursion and normalize its extraction result."""

    def __init__(
        self,
        unblob_path: str = "unblob",
        *,
        timeout: int = 120,
        max_depth: int = 5,
        max_files: int = 20_000,
        max_total_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        self._unblob = unblob_path
        self._timeout = timeout
        self._max_depth = max_depth
        self._max_files = max_files
        self._max_total_bytes = max_total_bytes

    async def is_available(self) -> bool:
        return shutil.which(self._unblob) is not None

    async def capability(self) -> ToolCapability:
        available = await self.is_available()
        return ToolCapability(
            name="unblob",
            available=available,
            reason="" if available else "executable not found on PATH",
            features=("recursive-extraction", "chunk-carving", "json-report"),
        )

    async def extract(
        self,
        firmware_path: Path,
        *,
        output_dir: Path,
    ) -> ExtractResult:
        firmware = firmware_path.resolve()
        destination = output_dir.resolve()
        if not firmware.is_file():
            return ExtractResult(
                firmware_path=firmware,
                output_dir=destination,
                files=[],
                signatures=[],
                error="firmware path does not exist",
                extractor="unblob",
            )

        destination.mkdir(parents=True, exist_ok=True)
        report_path = destination / "unblob-report.json"
        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                self._unblob,
                "-e",
                str(destination),
                "--report",
                str(report_path),
                "-d",
                str(self._max_depth),
                str(firmware),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return ExtractResult(
                firmware_path=firmware,
                output_dir=destination,
                files=[],
                signatures=[],
                error=f"unblob unavailable: {type(exc).__name__}",
                extractor="unblob",
            )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self._timeout,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return ExtractResult(
                firmware_path=firmware,
                output_dir=destination,
                files=[],
                signatures=[],
                error=f"unblob timed out after {self._timeout}s",
                extractor="unblob",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        files, warnings, truncated = collect_extracted_files(
            destination,
            max_files=self._max_files,
            max_total_bytes=self._max_total_bytes,
        )
        error = None
        if process.returncode:
            detail = _safe_error(stderr or stdout, firmware)
            error = f"unblob exited with status {process.returncode}"
            if detail:
                error = f"{error}: {detail}"
        return ExtractResult(
            firmware_path=firmware,
            output_dir=destination,
            files=files,
            signatures=_signatures_from_report(report_path),
            error=error,
            extractor="unblob",
            warnings=warnings,
            truncated=truncated,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


__all__ = ["UnblobRunner"]
