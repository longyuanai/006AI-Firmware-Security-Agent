"""Component detection from on-device package databases.

opkg (OpenWrt) and dpkg (Debian-derived) both store their status file in the
Debian control stanza format, so one parser serves both. This is the strongest
evidence available in an extracted rootfs: the device itself recorded what was
installed, with exact versions.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ai_firmware_agent.normalizer import Component

# Relative to the rootfs. Ordered most to least common.
OPKG_STATUS_PATHS = (
    "usr/lib/opkg/status",
    "var/lib/opkg/status",
    "usr/lib/ipkg/status",
)
DPKG_STATUS_PATHS = ("var/lib/dpkg/status",)

# A status file is text written by the build system, but it arrives inside
# untrusted firmware, so reads are bounded.
MAX_STATUS_BYTES = 16 * 1024 * 1024

_NOT_INSTALLED = ("not-installed", "deinstall", "config-files")


def _stanzas(text: str) -> Iterator[dict[str, str]]:
    """Yield each blank-line-separated control stanza as a field mapping."""
    current: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line.strip():
            if current:
                yield current
                current = {}
            continue
        if raw_line[0] in " \t":  # continuation of the previous field
            continue
        key, separator, value = raw_line.partition(":")
        if separator:
            current[key.strip().lower()] = value.strip()
    if current:
        yield current


def upstream_version(version: str) -> str:
    """Strip packaging decoration so the version can match a CPE.

    ``1:1.36.1-r1`` is the same upstream release as ``1.36.1``; leaving the
    epoch and revision attached makes every CVE lookup miss.
    """
    value = version.strip()
    _, _, after_epoch = value.partition(":")
    if after_epoch:
        value = after_epoch
    base, separator, _revision = value.rpartition("-")
    if separator and base:
        value = base
    return value.strip()


def _read_bounded(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as stream:
            raw = stream.read(MAX_STATUS_BYTES)
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def _components_from_status(
    path: Path,
    *,
    detector: str,
    rootfs: Path,
) -> list[Component]:
    text = _read_bounded(path)
    if text is None:
        return []
    components: list[Component] = []
    for stanza in _stanzas(text):
        name = stanza.get("package", "").strip()
        raw_version = stanza.get("version", "").strip()
        status = stanza.get("status", "").lower()
        if not name or not raw_version:
            continue
        if any(marker in status for marker in _NOT_INSTALLED):
            continue
        try:
            evidence = str(path.relative_to(rootfs))
        except ValueError:
            evidence = path.name
        components.append(
            Component(
                name=name.lower(),
                version=upstream_version(raw_version),
                category=stanza.get("section", "").strip().lower(),
                path=evidence,
                extra={
                    "detector": detector,
                    "evidence": f"{detector}:{evidence}",
                    "package_version": raw_version,
                },
            )
        )
    return components


def detect(rootfs: Path) -> list[Component]:
    """Read every package database present in the rootfs."""
    found: list[Component] = []
    for detector, candidates in (
        ("opkg", OPKG_STATUS_PATHS),
        ("dpkg", DPKG_STATUS_PATHS),
    ):
        for relative in candidates:
            found.extend(
                _components_from_status(
                    rootfs / relative,
                    detector=detector,
                    rootfs=rootfs,
                )
            )
    return found
