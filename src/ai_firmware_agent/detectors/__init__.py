"""Component detection for extracted firmware filesystems.

Real firmware ships no ``manifest.yml``; that file is a test fixture. These
detectors read what an actual rootfs does contain, in descending order of
evidence strength:

1. ``packages`` — the device's own opkg/dpkg database (exact, authoritative)
2. ``osrelease`` — the base distribution and its release
3. ``binary`` — version banners compiled into executables (heuristic)

Nothing here executes anything found in the firmware, and every read is
bounded, because the input is untrusted.
"""

from __future__ import annotations

from pathlib import Path

from ai_firmware_agent.detectors import (
    binary,
    node_packages,
    osrelease,
    packages,
    python_packages,
)
from ai_firmware_agent.normalizer import Component

#: Higher wins when two detectors disagree about the same component.
DETECTOR_PRIORITY = {
    "manifest": 4,
    "opkg": 3,
    "dpkg": 3,
    "python-dist-info": 3,
    "node-package-json": 3,
    "os-release": 2,
    "binary": 1,
}


def _priority(component: Component) -> int:
    return DETECTOR_PRIORITY.get(str(component.extra.get("detector", "")), 0)


def merge_components(components: list[Component]) -> list[Component]:
    """Collapse detections of the same component to the strongest evidence.

    A component seen by several detectors keeps the highest-priority record
    and accumulates the others under ``extra["also_detected_by"]``, so a
    disagreement stays visible in the report instead of being silently
    resolved.
    """
    best: dict[str, Component] = {}
    others: dict[str, list[str]] = {}
    for component in components:
        key = component.name.strip().lower()
        if not key:
            continue
        current = best.get(key)
        if current is None:
            best[key] = component
            others[key] = []
            continue
        loser, winner = (
            (current, component)
            if _priority(component) > _priority(current)
            else (component, current)
        )
        best[key] = winner
        evidence = str(loser.extra.get("evidence", "")) or str(
            loser.extra.get("detector", "")
        )
        if evidence and loser.version != winner.version:
            others[key].append(f"{evidence}={loser.version}")

    merged: list[Component] = []
    for key in sorted(best):
        component = best[key]
        conflicts = others.get(key, [])
        if conflicts:
            extra = dict(component.extra)
            extra["also_detected_by"] = sorted(set(conflicts))
            component = Component(
                name=component.name,
                version=component.version,
                vendor=component.vendor,
                category=component.category,
                path=component.path,
                extra=extra,
            )
        merged.append(component)
    return merged


#: A directory looks like a root filesystem if it holds one of these.
_ROOTFS_MARKERS = (
    ("etc", "os-release"),
    ("usr", "lib", "opkg"),
    ("var", "lib", "dpkg"),
    ("bin",),
    ("etc",),
)
MAX_ROOTFS_DEPTH = 6
MAX_ROOTFS_CANDIDATES = 16


def _looks_like_rootfs(directory: Path) -> bool:
    for marker in _ROOTFS_MARKERS:
        if directory.joinpath(*marker).exists():
            return True
    return False


def iter_rootfs_candidates(root: Path) -> list[Path]:
    """Find the filesystem roots inside an extraction tree.

    binwalk nests what it carves (``_image.bin.extracted/squashfs-root/``),
    so the extraction directory itself is rarely the rootfs.
    """
    candidates: list[Path] = []
    if _looks_like_rootfs(root):
        candidates.append(root)
    queue = [(root, 0)]
    while queue and len(candidates) < MAX_ROOTFS_CANDIDATES:
        directory, depth = queue.pop(0)
        if depth >= MAX_ROOTFS_DEPTH:
            continue
        try:
            children = sorted(
                (child for child in directory.iterdir() if child.is_dir()),
                key=str,
            )
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if _looks_like_rootfs(child):
                candidates.append(child)
                if len(candidates) >= MAX_ROOTFS_CANDIDATES:
                    break
            else:
                queue.append((child, depth + 1))
    return candidates


def _detect_all(root: Path) -> list[Component]:
    return [
        *packages.detect(root),
        *python_packages.detect(root),
        *node_packages.detect(root),
        *osrelease.detect(root),
        *binary.detect(root),
    ]


def detect_components(rootfs: str | Path) -> list[Component]:
    """Inventory one extracted filesystem, strongest evidence first."""
    root = Path(rootfs)
    if not root.is_dir():
        return []
    return merge_components(_detect_all(root))


def detect_in_tree(root: str | Path) -> list[Component]:
    """Inventory every filesystem root found inside an extraction tree."""
    tree = Path(root)
    if not tree.is_dir():
        return []
    found: list[Component] = []
    for candidate in iter_rootfs_candidates(tree):
        found.extend(_detect_all(candidate))
    return merge_components(found)


__all__ = [
    "DETECTOR_PRIORITY",
    "binary",
    "detect_components",
    "detect_in_tree",
    "iter_rootfs_candidates",
    "merge_components",
    "node_packages",
    "osrelease",
    "packages",
    "python_packages",
]
