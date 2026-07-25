"""CPE 2.3 field parsing and version-range comparison.

NVD expresses "affected" in two different ways for the same component:

* a literal CPE version (``cpe:2.3:a:busybox:busybox:1.36.1:*:...``)
* a wildcard CPE plus a range (``...:*:...`` with ``versionEndExcluding``)

Matching only the literal form silently drops the majority of real records,
so both are normalized here and compared with one ordering helper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CHUNK_RE = re.compile(r"\d+|[a-z]+")

# CPE 2.3 formatted-string field order (see NISTIR 7695 section 6.2).
_PART_INDEX = 2
_VENDOR_INDEX = 3
_PRODUCT_INDEX = 4
_VERSION_INDEX = 5
_MIN_FIELDS = _VERSION_INDEX + 1


@dataclass(frozen=True)
class CpeName:
    """The subset of CPE 2.3 fields used for component matching."""

    part: str
    vendor: str
    product: str
    version: str


def split_cpe_fields(cpe: str) -> list[str]:
    """Split a CPE 2.3 formatted string, honouring backslash escapes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in cpe:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
            current.append(character)
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    fields.append("".join(current))
    return fields


def parse_cpe(cpe: str) -> CpeName | None:
    """Return the matched CPE fields, or ``None`` when the string is not CPE 2.3."""
    fields = split_cpe_fields(cpe.strip())
    if len(fields) < _MIN_FIELDS or fields[0].lower() != "cpe" or fields[1] != "2.3":
        return None
    return CpeName(
        part=fields[_PART_INDEX].lower(),
        vendor=fields[_VENDOR_INDEX].lower(),
        product=fields[_PRODUCT_INDEX].lower(),
        version=fields[_VERSION_INDEX].lower(),
    )


def version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Return a sortable key for a firmware component version string.

    Numeric and alphabetic runs are compared separately so that ``1.36.10``
    sorts above ``1.36.9`` and ``8.5p1`` sorts above ``8.5``. This is a
    pragmatic ordering for embedded package versions, not a full PEP 440 or
    RPM implementation.
    """
    chunks = _CHUNK_RE.findall(version.strip().lower())
    return tuple(
        (0, int(chunk)) if chunk.isdigit() else (1, chunk) for chunk in chunks
    )


def _compare(left: str, right: str) -> int:
    left_key = version_key(left)
    right_key = version_key(right)
    if left_key == right_key:
        return 0
    return -1 if left_key < right_key else 1


@dataclass(frozen=True)
class VersionRange:
    """An NVD ``cpeMatch`` version range. All bounds are optional."""

    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @property
    def is_bounded(self) -> bool:
        return any(
            bound is not None
            for bound in (
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
            )
        )

    def contains(self, version: str) -> bool:
        """Return whether ``version`` falls inside every configured bound."""
        if not self.is_bounded or not version.strip():
            return False
        if self.start_including is not None and _compare(version, self.start_including) < 0:
            return False
        if self.start_excluding is not None and _compare(version, self.start_excluding) <= 0:
            return False
        if self.end_including is not None and _compare(version, self.end_including) > 0:
            return False
        if self.end_excluding is not None and _compare(version, self.end_excluding) >= 0:
            return False
        return True


def matches_version(
    cpe_version: str,
    wanted: str,
    version_range: VersionRange | None = None,
) -> bool:
    """Return whether a stored CPE entry covers the inventoried version.

    A literal CPE version must compare equal. A wildcard CPE version (``*``
    or ``-``) is only a match when an accompanying range contains the version,
    which keeps "affects every version ever released" entries out of reports.
    """
    wanted = wanted.strip().lower()
    if not wanted:
        return False
    stored = cpe_version.strip().lower()
    if stored in {"*", "-", ""}:
        return version_range is not None and version_range.contains(wanted)
    if _compare(stored, wanted) == 0:
        return True
    return version_range is not None and version_range.contains(wanted)
