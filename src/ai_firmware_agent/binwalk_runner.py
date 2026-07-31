"""Sandbox-friendly asynchronous wrapper around the binwalk CLI."""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractResult:
    """Metadata returned by a binwalk extraction without file contents."""

    firmware_path: Path
    output_dir: Path
    files: list[Path]
    signatures: list[str]
    error: str | None
    extractor: str = "binwalk"
    extractor_version: str = ""
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    duration_ms: int = 0


def collect_extracted_files(
    output_dir: Path,
    *,
    max_files: int,
    max_total_bytes: int,
) -> tuple[list[Path], list[str], bool]:
    """Collect safe regular files while enforcing extraction-bomb limits."""
    root = output_dir.resolve()
    files: list[Path] = []
    warnings: list[str] = []
    total_bytes = 0
    truncated = False
    for path in sorted(root.rglob("*"), key=str):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root):
                continue
            size = resolved.stat().st_size
        except OSError:
            continue
        if len(files) >= max_files:
            warnings.append(f"extracted file limit reached ({max_files})")
            truncated = True
            break
        if total_bytes + size > max_total_bytes:
            warnings.append(
                f"extracted byte limit reached ({max_total_bytes})"
            )
            truncated = True
            break
        files.append(resolved)
        total_bytes += size
    return files, warnings, truncated


def _signatures(stdout: bytes) -> list[str]:
    signatures: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        columns = line.strip().split(maxsplit=2)
        if len(columns) == 3 and columns[0].isdigit():
            signatures.append(columns[2])
    return signatures


def _diagnostic(raw: bytes, firmware_path: Path) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    return text.replace(str(firmware_path), "<firmware>")[:2048]


class BinwalkRunner:
    """Run extraction only; never execute files found inside firmware."""

    def __init__(
        self,
        binwalk_path: str = "binwalk",
        timeout: int = 120,
        *,
        max_files: int = 20_000,
        max_total_bytes: int = 512 * 1024 * 1024,
    ):
        self._binwalk = binwalk_path
        self._timeout = timeout
        self._max_files = max_files
        self._max_total_bytes = max_total_bytes

    async def is_available(self) -> bool:
        """Return whether the configured binwalk executable is on PATH."""
        return shutil.which(self._binwalk) is not None

    async def extract(
        self,
        firmware_path: Path,
        *,
        output_dir: Path,
    ) -> ExtractResult:
        """Extract with ``binwalk -e`` and return metadata only."""
        firmware = firmware_path.resolve()
        destination = output_dir.resolve()
        if not firmware.is_file():
            return ExtractResult(
                firmware_path=firmware,
                output_dir=destination,
                files=[],
                signatures=[],
                error="firmware path does not exist",
            )
        destination.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()

        try:
            process = await asyncio.create_subprocess_exec(
                self._binwalk,
                "-e",
                "--directory",
                str(destination),
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
                error=f"binwalk unavailable: {type(exc).__name__}",
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
                error=f"binwalk timed out after {self._timeout}s",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        files, warnings, truncated = collect_extracted_files(
            destination,
            max_files=self._max_files,
            max_total_bytes=self._max_total_bytes,
        )
        error = None
        if process.returncode:
            detail = _diagnostic(stderr or stdout, firmware)
            error = f"binwalk exited with status {process.returncode}"
            if detail:
                error = f"{error}: {detail}"
        return ExtractResult(
            firmware_path=firmware,
            output_dir=destination,
            files=files,
            signatures=_signatures(stdout),
            error=error,
            warnings=warnings,
            truncated=truncated,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


__all__ = ["BinwalkRunner", "ExtractResult", "collect_extracted_files"]
