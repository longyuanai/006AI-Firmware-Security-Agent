"""Tests for version/CVE-pattern 0-day candidate prioritization."""

from __future__ import annotations

import pytest

from ai_firmware_agent.analyzer import ComponentMatch
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.v05_compat import FindingSource, is_uuid4
from ai_firmware_agent.zeroday import (
    KnownCvePattern,
    grep_version_strings,
    patterns_from_matches,
    predict_zero_days,
)


def _pattern(
    version: str = "1.4.50",
    *,
    cve: str = "CVE-2018-19052",
    summary: str = "lighttpd 1.4.50 path traversal RCE.",
    cvss: float = 9.8,
) -> KnownCvePattern:
    return KnownCvePattern(
        component="lighttpd",
        known_version=version,
        cve=cve,
        cvss=cvss,
        summary=summary,
    )


def test_grep_version_strings_extracts_and_deduplicates_versions():
    assert grep_version_strings("Affected v1.4.50, 1.4.51 and 1.4.50.") == (
        "1.4.50",
        "1.4.51",
    )


def test_patterns_from_matches_preserves_component_and_cve_evidence():
    matches = [
        ComponentMatch(
            component=Component(name="lighttpd", version="1.4.50"),
            cves=[CveRecord("CVE-X", 8.1, "lighttpd 1.4.50 overflow")],
        )
    ]
    [pattern] = patterns_from_matches(matches)
    assert pattern.component == "lighttpd"
    assert pattern.known_version == "1.4.50"
    assert pattern.cve == "CVE-X"


def test_adjacent_release_generates_ranked_firmware_finding():
    [finding] = predict_zero_days(
        [Component(name="lighttpd", version="1.4.52")],
        [_pattern()],
    )
    assert finding.source == FindingSource.FIRMWARE
    assert finding.cve is None
    assert finding.confidence == pytest.approx(0.78)
    assert finding.metadata["analog_cves"] == ("CVE-2018-19052",)
    assert "adjacent" in finding.description
    assert is_uuid4(finding.id)


def test_explicitly_known_version_is_not_labeled_zero_day():
    findings = predict_zero_days(
        [Component(name="lighttpd", version="1.4.51")],
        [_pattern(summary="Affected lighttpd 1.4.50 and 1.4.51 RCE.")],
    )
    assert findings == []


def test_unrelated_major_version_is_not_a_candidate():
    findings = predict_zero_days(
        [Component(name="lighttpd", version="2.0.0")],
        [_pattern()],
    )
    assert findings == []


def test_multiple_analogues_raise_confidence_and_capture_weaknesses():
    [finding] = predict_zero_days(
        [Component(name="lighttpd", version="1.4.60")],
        [
            _pattern(),
            _pattern(
                version="1.4.48",
                cve="CVE-OTHER",
                summary="lighttpd 1.4.48 path traversal and command injection.",
                cvss=8.8,
            ),
        ],
    )
    assert finding.confidence == pytest.approx(0.82)
    assert finding.severity.value == "critical"
    assert finding.metadata["analog_cves"] == ("CVE-2018-19052", "CVE-OTHER")
    assert "path traversal" in finding.metadata["weakness_terms"]


def test_min_confidence_is_validated_and_filters_major_only_matches():
    component = Component(name="lighttpd", version="1.9.0")
    assert predict_zero_days([component], [_pattern()], min_confidence=0.6) == []
    with pytest.raises(ValueError, match="min_confidence"):
        predict_zero_days([component], [_pattern()], min_confidence=1.1)
