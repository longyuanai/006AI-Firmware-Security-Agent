"""Heuristic 0-day candidates from component versions and known CVE patterns."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.v05_compat import Finding, FindingSeverity, new_finding

if TYPE_CHECKING:
    from ai_firmware_agent.analyzer import ComponentMatch

_VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,3}(?:[A-Za-z0-9._-]*))")
_WEAKNESS_TERMS = (
    "auth bypass",
    "backdoor",
    "buffer overflow",
    "command injection",
    "crash",
    "double-free",
    "heap",
    "oob",
    "out-of-bounds",
    "path traversal",
    "rce",
    "side-channel",
    "timing",
    "use-after-free",
)


@dataclass(frozen=True)
class KnownCvePattern:
    """One known vulnerable version used as an analogue, not a new CVE claim."""

    component: str
    known_version: str
    cve: str
    cvss: float
    summary: str


def grep_version_strings(text: str) -> tuple[str, ...]:
    """Return stable, de-duplicated version-like strings from free text."""
    return tuple(dict.fromkeys(match.group(1).rstrip(".,;:)") for match in _VERSION_RE.finditer(text)))


def patterns_from_matches(matches: Iterable[ComponentMatch]) -> tuple[KnownCvePattern, ...]:
    """Convert known component/CVE matches into reusable analogue patterns."""
    patterns = [
        KnownCvePattern(
            component=match.component.name.strip().lower(),
            known_version=match.component.version.strip(),
            cve=record.cve,
            cvss=record.cvss,
            summary=record.summary,
        )
        for match in matches
        for record in match.cves
    ]
    return tuple(patterns)


def _version_parts(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:4])


def _version_similarity(candidate: str, known: str) -> float:
    left = _version_parts(candidate)
    right = _version_parts(known)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if len(left) >= 2 and len(right) >= 2 and left[:2] == right[:2]:
        return 0.78
    if left[0] == right[0]:
        return 0.58
    return 0.0


def _weakness_terms(patterns: Iterable[KnownCvePattern]) -> tuple[str, ...]:
    counts: Counter[str] = Counter()
    for pattern in patterns:
        lowered = pattern.summary.lower()
        counts.update(term for term in _WEAKNESS_TERMS if term in lowered)
    return tuple(term for term, _ in counts.most_common())


def _severity(max_cvss: float) -> FindingSeverity:
    if max_cvss >= 9.0:
        return FindingSeverity.CRITICAL
    if max_cvss >= 7.0:
        return FindingSeverity.HIGH
    if max_cvss >= 4.0:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


def _candidate_finding(
    component: Component,
    analogues: list[tuple[KnownCvePattern, float]],
) -> Finding:
    patterns = [item[0] for item in analogues]
    base_confidence = max(item[1] for item in analogues)
    confidence = min(0.95, base_confidence + min(0.12, 0.04 * (len(patterns) - 1)))
    known_versions = tuple(dict.fromkeys(pattern.known_version for pattern in patterns))
    analog_cves = tuple(dict.fromkeys(pattern.cve for pattern in patterns))
    weakness_terms = _weakness_terms(patterns)
    reason = (
        f"{component.name} {component.version} is adjacent to known vulnerable "
        f"release line(s) {', '.join(known_versions)}. "
        f"Analog CVEs: {', '.join(analog_cves)}."
    )
    if weakness_terms:
        reason += f" Repeated weakness signals: {', '.join(weakness_terms)}."
    evidence = tuple(
        f"analogue:{pattern.cve}:{pattern.component}@{pattern.known_version}"
        for pattern in patterns
    )
    return new_finding(
        severity=_severity(max(pattern.cvss for pattern in patterns)),
        confidence=confidence,
        title=f"Potential 0-day candidate in {component.name} {component.version}",
        description=reason,
        host=component.name,
        evidence=evidence,
        tags=frozenset({"zero-day-candidate", "version-pattern", component.name.lower()}),
        metadata={
            "candidate_version": component.version,
            "known_versions": known_versions,
            "analog_cves": analog_cves,
            "weakness_terms": weakness_terms,
            "reason": reason,
            "heuristic": "adjacent-component-release-line",
        },
    )


def predict_zero_days(
    components: Iterable[Component],
    patterns: Iterable[KnownCvePattern],
    *,
    min_confidence: float = 0.55,
) -> list[Finding]:
    """Return ranked §9 Findings for adjacent, not already-known versions.

    This is a prioritization heuristic only. It does not claim exploitability
    and never assigns a new CVE identifier.
    """
    if not 0.0 <= min_confidence <= 1.0:
        raise ValueError("min_confidence must be between 0.0 and 1.0")

    indexed: defaultdict[str, list[KnownCvePattern]] = defaultdict(list)
    for pattern in patterns:
        indexed[pattern.component.strip().lower()].append(pattern)

    findings: list[Finding] = []
    for component in components:
        name = component.name.strip().lower()
        version = component.version.strip()
        relevant = indexed.get(name, [])
        explicitly_known = any(
            version == pattern.known_version
            or version in grep_version_strings(pattern.summary)
            for pattern in relevant
        )
        if explicitly_known:
            continue

        analogues: list[tuple[KnownCvePattern, float]] = []
        for pattern in relevant:
            candidate_versions = (
                pattern.known_version,
                *grep_version_strings(pattern.summary),
            )
            similarity = max(
                (_version_similarity(version, known) for known in candidate_versions),
                default=0.0,
            )
            if similarity >= min_confidence:
                analogues.append((pattern, similarity))
        if analogues:
            findings.append(_candidate_finding(component, analogues))

    return sorted(
        findings,
        key=lambda finding: (-finding.confidence, finding.host or "", finding.title),
    )
