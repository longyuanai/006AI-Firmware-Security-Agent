"""PRisk v0.1 scoring for vulnerable firmware components."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_firmware_agent.analyzer import ComponentMatch

_EXPOSURE_BY_CATEGORY = {
    "network": 1.0,
    "remote_access": 1.0,
    "web_server": 1.0,
    "os": 0.75,
    "kernel": 0.75,
    "crypto": 0.5,
    "userspace": 0.4,
    "compression": 0.25,
}


@dataclass(frozen=True)
class PRiskScore:
    """Weighted PRisk terms on a normalized 0.0-1.0 scale."""

    component: ComponentMatch
    score: float
    cvss_term: float
    epss_term: float
    kev_term: float
    exploit_term: float
    exposure_term: float


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _extra_factor(component: ComponentMatch, key: str) -> float | None:
    value = component.component.extra.get(key)
    if value is None:
        return None
    try:
        return _clamp(float(value))
    except (TypeError, ValueError):
        return None


def _exploit_factor(component: ComponentMatch) -> float:
    explicit = _extra_factor(component, "exploit")
    if explicit is not None:
        return explicit
    return 1.0 if component.has_kev else 0.0


def _exposure_factor(component: ComponentMatch) -> float:
    explicit = _extra_factor(component, "exposure")
    if explicit is not None:
        return explicit
    category = component.component.category.strip().lower()
    return _EXPOSURE_BY_CATEGORY.get(category, 0.3)


def score_component(component: ComponentMatch) -> PRiskScore:
    """Calculate PRisk using normalized CVSS, EPSS, KEV and context factors."""
    cvss_term = 0.25 * _clamp(component.max_cvss / 10.0)
    epss_term = 0.25 * _clamp(component.max_epss)
    kev_term = 0.20 * float(component.has_kev)
    exploit_term = 0.15 * _exploit_factor(component)
    exposure_term = 0.15 * _exposure_factor(component)
    score = cvss_term + epss_term + kev_term + exploit_term + exposure_term
    return PRiskScore(
        component=component,
        score=round(score, 6),
        cvss_term=round(cvss_term, 6),
        epss_term=round(epss_term, 6),
        kev_term=round(kev_term, 6),
        exploit_term=round(exploit_term, 6),
        exposure_term=round(exposure_term, 6),
    )


def rank_matches(matches: list[ComponentMatch]) -> list[PRiskScore]:
    """Return component scores ordered from highest to lowest PRisk."""
    scores = [score_component(match) for match in matches]
    return sorted(
        scores,
        key=lambda item: (
            item.score,
            item.component.max_cvss,
            item.component.component.name.lower(),
        ),
        reverse=True,
    )
