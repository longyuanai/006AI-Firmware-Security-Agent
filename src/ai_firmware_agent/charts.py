"""Static report charts rendered with Matplotlib's headless Agg backend."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure

from ai_firmware_agent.analyzer import ComponentMatch

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Unscored")
_SEVERITY_COLORS = {
    "Critical": "#991B1B",
    "High": "#DC2626",
    "Medium": "#F59E0B",
    "Low": "#3B82F6",
    "Unscored": "#94A3B8",
}


def _severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Unscored"


def vulnerability_distribution(matches: list[ComponentMatch]) -> dict[str, int]:
    """Count CVE findings by CVSS severity in stable display order."""
    counts = Counter(
        _severity(cve.cvss)
        for match in matches
        for cve in match.cves
    )
    return {
        severity: counts[severity]
        for severity in _SEVERITY_ORDER
        if counts[severity]
    }


def render_vulnerability_pie(
    matches: list[ComponentMatch],
    output_path: str | Path,
) -> Path | None:
    """Write a vulnerability-distribution PNG, or ``None`` for no findings."""
    distribution = vulnerability_distribution(matches)
    if not distribution:
        return None

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    labels = [f"{severity} ({count})" for severity, count in distribution.items()]
    values = list(distribution.values())
    colors = [_SEVERITY_COLORS[severity] for severity in distribution]

    figure = Figure(figsize=(7.2, 4.8), dpi=120, facecolor="white")
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    axis.pie(
        values,
        labels=labels,
        colors=colors,
        autopct=lambda percent: f"{percent:.0f}%",
        startangle=90,
        counterclock=False,
        wedgeprops={"edgecolor": "white", "linewidth": 1.0},
        textprops={"fontsize": 10},
    )
    axis.set_title("Vulnerability Distribution by CVSS Severity", fontsize=13)
    axis.axis("equal")
    figure.savefig(target, format="png", bbox_inches="tight")
    return target
