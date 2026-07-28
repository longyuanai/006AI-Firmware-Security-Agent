"""Firmware-to-firmware component diffing.

Compares two component inventories — typically the same device's firmware
before and after an update — and classifies every component as added,
removed, upgraded, downgraded, or unchanged. It also flags CVEs that
persisted across the change: an upgrade that bumped the version string but
left a component inside the same vulnerable range is the case a changelog
will not tell you about.

This module only diffs structures the caller already built (component
lists, CVE matches); it does no extraction, detection or CVE lookup of its
own, matching how scoring.py and reporter.py stay separate from analyzer.py.

Version ordering reuses ``cve_db.version.version_key``, which is a pragmatic
comparator for embedded package versions, not a full semver/PEP 440
implementation (see its docstring). Many OpenWrt-style packages version
themselves with a build-date-plus-git-hash string
(``2023-09-01-598d9fbb``) rather than a semantic version; two such strings
still produce *some* ordering under this comparator, but that ordering does
not reliably correspond to which one is chronologically newer. Treat
"upgraded"/"downgraded" as a best-effort label for that case, not a
guarantee — the on-disk build date embedded in the string is the more
trustworthy signal if you need to be sure.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ai_firmware_agent.cve_db.version import version_key
from ai_firmware_agent.normalizer import Component

if TYPE_CHECKING:
    from ai_firmware_agent.analyzer import ComponentMatch

Direction = Literal["added", "removed", "upgraded", "downgraded", "changed", "unchanged"]


@dataclass(frozen=True)
class ComponentChange:
    """One component's status between two firmware inventories."""

    name: str
    old_version: str | None
    new_version: str | None
    direction: Direction


@dataclass(frozen=True)
class PersistentVulnerability:
    """A CVE that matched the component in both the old and new inventory.

    This does not mean the upgrade "did nothing" — the CVE record may cover
    a version range wide enough to span both releases. It means the upgrade
    did not move the component out of that range, which a version-number
    changelog would not surface.
    """

    component: str
    cve: str
    old_version: str
    new_version: str


@dataclass(frozen=True)
class FirmwareDiff:
    """The full comparison between two component inventories."""

    added: tuple[ComponentChange, ...]
    removed: tuple[ComponentChange, ...]
    upgraded: tuple[ComponentChange, ...]
    downgraded: tuple[ComponentChange, ...]
    changed: tuple[ComponentChange, ...]
    unchanged: tuple[ComponentChange, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.upgraded or self.downgraded or self.changed)


def _direction(old_version: str, new_version: str) -> Direction:
    if old_version == new_version:
        return "unchanged"
    old_key = version_key(old_version)
    new_key = version_key(new_version)
    if not old_key or not new_key:
        # At least one side has no recognizable version digits at all
        # (e.g. a git-hash-only build string); ordering it as up or down
        # would be a guess, so it is reported as merely "changed".
        return "changed"
    if new_key > old_key:
        return "upgraded"
    if new_key < old_key:
        return "downgraded"
    return "changed"


def diff_components(
    old: Iterable[Component],
    new: Iterable[Component],
) -> FirmwareDiff:
    """Classify every component between two inventories.

    Components are matched by name (case-insensitive, first entry wins on a
    duplicate name within one side — the same convention
    ``reporter.py``/``html_report.py`` use for a value-equal fallback match).
    """
    old_by_name: dict[str, Component] = {}
    for component in old:
        old_by_name.setdefault(component.name.strip().lower(), component)
    new_by_name: dict[str, Component] = {}
    for component in new:
        new_by_name.setdefault(component.name.strip().lower(), component)

    old_names = set(old_by_name)
    new_names = set(new_by_name)

    added = tuple(
        ComponentChange(
            name=new_by_name[name].name,
            old_version=None,
            new_version=new_by_name[name].version,
            direction="added",
        )
        for name in sorted(new_names - old_names)
    )
    removed = tuple(
        ComponentChange(
            name=old_by_name[name].name,
            old_version=old_by_name[name].version,
            new_version=None,
            direction="removed",
        )
        for name in sorted(old_names - new_names)
    )

    upgraded: list[ComponentChange] = []
    downgraded: list[ComponentChange] = []
    changed: list[ComponentChange] = []
    unchanged: list[ComponentChange] = []
    for name in sorted(old_names & new_names):
        old_component = old_by_name[name]
        new_component = new_by_name[name]
        direction = _direction(old_component.version, new_component.version)
        change = ComponentChange(
            name=new_component.name,
            old_version=old_component.version,
            new_version=new_component.version,
            direction=direction,
        )
        {
            "upgraded": upgraded,
            "downgraded": downgraded,
            "changed": changed,
            "unchanged": unchanged,
        }[direction].append(change)

    return FirmwareDiff(
        added=added,
        removed=removed,
        upgraded=tuple(upgraded),
        downgraded=tuple(downgraded),
        changed=tuple(changed),
        unchanged=tuple(unchanged),
    )


def diff_vulnerabilities(
    old_matches: Iterable[ComponentMatch],
    new_matches: Iterable[ComponentMatch],
) -> tuple[PersistentVulnerability, ...]:
    """Return CVEs that matched a component in both inventories.

    Requires the caller to have already run the same CVE source against
    both inventories (``match_components`` with one ``lookup_fn``); this
    function only compares the results, it does not perform lookups.
    """
    old_by_name = {match.component.name.strip().lower(): match for match in old_matches}
    new_by_name = {match.component.name.strip().lower(): match for match in new_matches}

    persistent: list[PersistentVulnerability] = []
    for name in sorted(set(old_by_name) & set(new_by_name)):
        old_match = old_by_name[name]
        new_match = new_by_name[name]
        old_cves = {record.cve for record in old_match.cves}
        new_cves = {record.cve for record in new_match.cves}
        for cve in sorted(old_cves & new_cves):
            persistent.append(
                PersistentVulnerability(
                    component=new_match.component.name,
                    cve=cve,
                    old_version=old_match.component.version,
                    new_version=new_match.component.version,
                )
            )
    return tuple(persistent)
