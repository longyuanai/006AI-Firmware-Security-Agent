"""Component detection from installed Python package metadata.

Embedded Linux images increasingly ship a Python runtime (management agents,
cloud connectors, ML inference). ``*.dist-info/METADATA`` (PEP 566) and the
older ``*.egg-info/PKG-INFO`` use the same RFC 822 header format pip and
setuptools have written for years, so one parser covers both.
"""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.normalizer import Component

MAX_METADATA_BYTES = 1024 * 1024
MAX_SCAN_FILES = 5_000


def _read_bounded(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES)
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def _header_fields(text: str) -> dict[str, str]:
    """Parse the RFC 822 header block, stopping at the first blank line.

    METADATA files may carry a long description after a blank line; that
    body is not header data and must not be scanned for fields.
    """
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line.strip():
            break
        if raw_line[0] in " \t":  # continuation of the previous field
            continue
        key, separator, value = raw_line.partition(":")
        if separator:
            fields.setdefault(key.strip(), value.strip())
    return fields


def _metadata_files(rootfs: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in ("*.dist-info/METADATA", "*.egg-info/PKG-INFO"):
        for path in rootfs.rglob(pattern):
            if len(found) >= MAX_SCAN_FILES:
                return found
            found.append(path)
    return found


def detect(rootfs: Path) -> list[Component]:
    """Read every installed Python package's metadata in the rootfs."""
    components: list[Component] = []
    for path in _metadata_files(rootfs):
        text = _read_bounded(path)
        if text is None:
            continue
        fields = _header_fields(text)
        name = fields.get("Name", "").strip()
        version = fields.get("Version", "").strip()
        if not name or not version:
            continue
        try:
            evidence = path.relative_to(rootfs).as_posix()
        except ValueError:
            evidence = path.name
        components.append(
            Component(
                name=name.lower(),
                version=version,
                vendor=fields.get("Home-page", "").strip(),
                category="python-package",
                path=evidence,
                extra={
                    "detector": "python-dist-info",
                    "evidence": f"python-dist-info:{evidence}",
                },
            )
        )
    return components
