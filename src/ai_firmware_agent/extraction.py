"""Shared limits for extracting untrusted firmware.

Both extraction paths (:mod:`ai_firmware_agent.unpack` and the async
:mod:`ai_firmware_agent.parsers.binwalk`) handle the same untrusted images, so
the caps live here rather than in either one. Keeping them in a leaf module
also avoids an import cycle, since ``unpack`` imports the parsers package and
the parsers package imports back.
"""

from __future__ import annotations

from pathlib import Path

# binwalk -Me extracts recursively, so a crafted image can expand without
# bound. These caps are checked after each extraction step and abort before
# the expanded tree is walked or parsed. They bound what this process does
# with the result; they are not a substitute for running extraction under a
# disk quota or inside a container.
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXTRACTED_FILES = 200_000


class FirmwareUnpackError(RuntimeError):
    """Raised when a firmware image cannot be safely extracted."""


def check_extraction_size(
    root: Path,
    *,
    max_bytes: int = MAX_EXTRACTED_BYTES,
    max_files: int = MAX_EXTRACTED_FILES,
) -> None:
    """Abort when an extracted tree exceeds the configured caps."""
    total_bytes = 0
    total_files = 0
    for path in root.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            total_bytes += path.stat().st_size
        except OSError:
            continue
        total_files += 1
        if total_files > max_files:
            raise FirmwareUnpackError(
                f"Extraction produced more than {max_files} files; "
                "refusing to continue"
            )
        if total_bytes > max_bytes:
            raise FirmwareUnpackError(
                f"Extraction exceeded {max_bytes} bytes; refusing to continue"
            )
