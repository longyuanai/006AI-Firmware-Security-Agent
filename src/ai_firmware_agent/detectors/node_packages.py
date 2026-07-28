"""Component detection from installed Node.js package manifests.

Router and IoT management UIs are frequently built on an embedded Node.js
runtime. Every installed package — the application itself and everything
under ``node_modules/`` — carries a ``package.json`` with an exact
``name``/``version`` pair, so this is structured evidence, not a heuristic.
"""

from __future__ import annotations

import json
from pathlib import Path

from ai_firmware_agent.normalizer import Component

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SCAN_FILES = 20_000


def _read_bounded(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES)
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def detect(rootfs: Path) -> list[Component]:
    """Read every ``package.json`` in the rootfs, including dependencies."""
    components: list[Component] = []
    for path in rootfs.rglob("package.json"):
        if len(components) >= MAX_SCAN_FILES:
            break
        text = _read_bounded(path)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        name = str(data.get("name", "")).strip()
        version = str(data.get("version", "")).strip()
        if not name or not version:
            continue
        try:
            evidence = str(path.relative_to(rootfs))
        except ValueError:
            evidence = path.name
        components.append(
            Component(
                name=name.lower(),
                version=version,
                category="node-package",
                path=evidence,
                extra={
                    "detector": "node-package-json",
                    "evidence": f"node-package-json:{evidence}",
                },
            )
        )
    return components
