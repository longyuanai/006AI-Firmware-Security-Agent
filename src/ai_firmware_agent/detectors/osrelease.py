"""Distribution identification from /etc/os-release.

This does not enumerate packages; it records which base system the firmware
was built from, which is what a reader needs to interpret everything else.
"""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.normalizer import Component

OS_RELEASE_PATHS = (
    "etc/os-release",
    "usr/lib/os-release",
    "etc/openwrt_release",
)
MAX_OS_RELEASE_BYTES = 64 * 1024


def _parse(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            continue
        fields[key.strip().upper()] = value.strip().strip('"').strip("'")
    return fields


def _read_bounded(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as stream:
            raw = stream.read(MAX_OS_RELEASE_BYTES)
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def detect(rootfs: Path) -> list[Component]:
    """Return at most one Component describing the base distribution."""
    for relative in OS_RELEASE_PATHS:
        path = rootfs / relative
        text = _read_bounded(path)
        if text is None:
            continue
        fields = _parse(text)
        # DISTRIB_* are the OpenWrt release-file spellings.
        name = (
            fields.get("ID")
            or fields.get("DISTRIB_ID")
            or fields.get("NAME")
            or ""
        ).strip().lower()
        version = (
            fields.get("VERSION_ID")
            or fields.get("DISTRIB_RELEASE")
            or fields.get("VERSION")
            or ""
        ).strip()
        if not name or not version:
            continue
        return [
            Component(
                name=name,
                version=version,
                vendor=fields.get("HOME_URL", "").strip(),
                category="os",
                path=relative,
                extra={
                    "detector": "os-release",
                    "evidence": f"os-release:{relative}",
                },
            )
        ]
    return []
