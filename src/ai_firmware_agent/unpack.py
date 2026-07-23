"""Firmware extraction through binwalk and squashfs-tools."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import components_from_manifest

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
_SQUASHFS_MAGICS = {b"hsqs", b"sqsh", b"shsq", b"qshs"}


class FirmwareUnpackError(RuntimeError):
    """Raised when a firmware image cannot be safely extracted."""


def _run(
    command: Sequence[str],
    *,
    runner: CommandRunner,
    cwd: Path,
    timeout_s: float,
) -> None:
    try:
        result = runner(
            list(command),
            cwd=str(cwd),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        raise FirmwareUnpackError(f"Required tool is not installed: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirmwareUnpackError(f"{command[0]} timed out after {timeout_s:g}s") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise FirmwareUnpackError(
            f"{command[0]} exited with status {result.returncode}{suffix}"
        )


def _manifest_paths(root: Path) -> list[Path]:
    candidates = [*root.rglob("manifest.yml"), *root.rglob("manifest.yaml")]
    safe: list[Path] = []
    resolved_root = root.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and resolved.is_relative_to(resolved_root):
            safe.append(resolved)
    return sorted(set(safe), key=lambda path: (len(path.parts), str(path)))


def _components_from_tree(root: Path) -> list[Component] | None:
    paths = _manifest_paths(root)
    if not paths:
        return None
    raw = paths[0].read_text(encoding="utf-8", errors="replace")
    return components_from_manifest(raw)


def _is_squashfs(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) in _SQUASHFS_MAGICS
    except OSError:
        return False


def _squashfs_candidates(firmware: Path, extracted: Path) -> list[Path]:
    candidates = [firmware] if _is_squashfs(firmware) else []
    for path in extracted.rglob("*"):
        if path.is_file() and _is_squashfs(path):
            candidates.append(path)
    return list(dict.fromkeys(path.resolve() for path in candidates))


def unpack_firmware(
    bin_path: str | Path,
    *,
    runner: CommandRunner = subprocess.run,
    binwalk_command: str = "binwalk",
    unsquashfs_command: str = "unsquashfs",
    timeout_s: float = 120.0,
) -> list[Component]:
    """Extract a ``.bin`` image and return components from its manifest.

    Binwalk is attempted first. If the input or a carved file is a SquashFS
    image, ``unsquashfs`` is invoked explicitly as a deterministic fallback.
    """
    firmware = Path(bin_path).resolve(strict=True)
    if not firmware.is_file():
        raise FirmwareUnpackError(f"Firmware path is not a file: {firmware}")

    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="firmware-agent-") as temp_dir:
        extracted = Path(temp_dir)
        binwalk_commands = [
            [
                binwalk_command,
                "-Me",
                "--directory",
                str(extracted),
                str(firmware),
            ],
            [binwalk_command, "-Me", str(firmware)],
        ]
        for command in binwalk_commands:
            try:
                _run(command, runner=runner, cwd=extracted, timeout_s=timeout_s)
                break
            except FirmwareUnpackError as exc:
                errors.append(str(exc))

        components = _components_from_tree(extracted)
        if components is not None:
            return components

        for index, squashfs_image in enumerate(
            _squashfs_candidates(firmware, extracted),
            start=1,
        ):
            destination = extracted / f"squashfs-root-{index}"
            try:
                _run(
                    [
                        unsquashfs_command,
                        "-no-progress",
                        "-d",
                        str(destination),
                        str(squashfs_image),
                    ],
                    runner=runner,
                    cwd=extracted,
                    timeout_s=timeout_s,
                )
            except FirmwareUnpackError as exc:
                errors.append(str(exc))
                continue
            components = _components_from_tree(destination)
            if components is not None:
                return components

    detail = "; ".join(dict.fromkeys(errors))
    if detail:
        raise FirmwareUnpackError(f"No firmware manifest could be extracted ({detail})")
    raise FirmwareUnpackError("No firmware manifest could be extracted")
