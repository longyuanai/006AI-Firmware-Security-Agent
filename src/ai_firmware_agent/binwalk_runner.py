"""Sandbox-friendly asynchronous wrapper around the binwalk CLI."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExtractResult:
    """Metadata returned by a binwalk extraction without file contents."""

    firmware_path: Path
    output_dir: Path
    files: list[Path]
    signatures: list[str]
    error: str | None


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

    def __init__(self, binwalk_path: str = "binwalk", timeout: int = 120):
        self._binwalk = binwalk_path
        self._timeout = timeout

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
            )

        files = sorted(
            (
                path.resolve()
                for path in destination.rglob("*")
                if path.is_file()
            ),
            key=str,
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
        )
