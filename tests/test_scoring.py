"""Tests for the PRisk v0.1 weighted score."""

from __future__ import annotations

from ai_firmware_agent.analyzer import ComponentMatch
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.scoring import rank_matches, score_component


def _match(
    *,
    name="component",
    category="userspace",
    cvss=0.0,
    epss=0.0,
    kev=False,
    extra=None,
):
    return ComponentMatch(
        component=Component(
            name=name,
            version="1.0",
            category=category,
            extra=extra or {},
        ),
        cves=[CveRecord("CVE-TEST", cvss, "test", epss=epss, kev=kev)],
    )


def test_prisk_maximum_is_one():
    result = score_component(
        _match(
            category="network",
            cvss=10.0,
            epss=1.0,
            kev=True,
            extra={"exploit": 1.0, "exposure": 1.0},
        )
    )

    assert result.score == 1.0
    assert result.cvss_term == 0.25
    assert result.epss_term == 0.25
    assert result.kev_term == 0.20
    assert result.exploit_term == 0.15
    assert result.exposure_term == 0.15


def test_prisk_clamps_out_of_range_inputs():
    result = score_component(
        _match(
            cvss=20.0,
            epss=-2.0,
            extra={"exploit": 2.0, "exposure": -1.0},
        )
    )

    assert result.cvss_term == 0.25
    assert result.epss_term == 0.0
    assert result.exploit_term == 0.15
    assert result.exposure_term == 0.0


def test_prisk_kev_implies_known_exploitation_by_default():
    result = score_component(_match(cvss=5.0, kev=True, category="compression"))

    assert result.kev_term == 0.20
    assert result.exploit_term == 0.15
    assert result.exposure_term == 0.0375


def test_prisk_uses_category_exposure_when_not_explicit():
    remote = score_component(_match(category="remote_access"))
    compression = score_component(_match(category="compression"))

    assert remote.exposure_term == 0.15
    assert compression.exposure_term == 0.0375


def test_rank_matches_orders_by_prisk_not_cvss_alone():
    high_cvss = _match(name="high-cvss", cvss=9.0, category="compression")
    active = _match(
        name="active",
        cvss=7.0,
        epss=0.9,
        kev=True,
        category="remote_access",
    )

    ranked = rank_matches([high_cvss, active])

    assert ranked[0].component.component.name == "active"
    assert ranked[0].score > ranked[1].score
