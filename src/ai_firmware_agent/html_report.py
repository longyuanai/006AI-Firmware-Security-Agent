"""Self-contained HTML report rendering.

Named ``html_report`` rather than living under a ``report`` package so it is
not confused with the existing ``reporter`` module, which owns the Markdown
output and stays unchanged.

Every value rendered here — component names, versions, CVE descriptions —
originates in untrusted firmware, so the environment enables autoescaping and
the template must never use the ``safe`` filter on scan data.
"""

from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ai_firmware_agent._version import __version__
from ai_firmware_agent.analyzer import ComponentMatch, ComponentNarrative
from ai_firmware_agent.charts import vulnerability_distribution
from ai_firmware_agent.normalizer import Component

TEMPLATE_DIR = Path(__file__).with_name("templates")
TEMPLATE_NAME = "report.html.j2"

_SEVERITY_BY_CVSS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0001, "low"),
)


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2"),
            default_for_string=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _severity(cvss: float) -> str:
    for threshold, label in _SEVERITY_BY_CVSS:
        if cvss >= threshold:
            return label
    return "unscored"


def _chart_data_uri(chart_path: str | Path | None) -> str:
    """Inline the PNG so the report stays a single distributable file."""
    if not chart_path:
        return ""
    path = Path(chart_path)
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    encoded = base64.b64encode(raw).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _match_index(
    matches: list[ComponentMatch],
) -> tuple[dict[int, ComponentMatch], dict[tuple[str, str], ComponentMatch]]:
    by_identity = {id(item.component): item for item in matches}
    by_key: dict[tuple[str, str], ComponentMatch] = {}
    for item in matches:
        by_key.setdefault((item.component.name, item.component.version), item)
    return by_identity, by_key


def build_context(
    components: list[Component],
    matches: list[ComponentMatch],
    narratives: list[ComponentNarrative],
    *,
    source_path: str = "",
    chart_path: str | Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Assemble every value the template renders, already resolved."""
    by_identity, by_key = _match_index(matches)

    rows: list[dict[str, Any]] = []
    for component in components:
        match = by_identity.get(id(component)) or by_key.get(
            (component.name, component.version)
        )
        cves = list(match.cves) if match else []
        rows.append(
            {
                "name": component.name,
                "version": component.version,
                "vendor": component.vendor or "-",
                "detector": str(component.extra.get("detector", "")) or "-",
                "evidence": str(component.extra.get("evidence", "")) or "-",
                "cve_count": len(cves),
                "prisk": match.prisk if match and cves else 0.0,
                "worst_cvss": match.max_cvss if match and cves else 0.0,
                "max_epss": match.max_epss if match and cves else 0.0,
                "kev": bool(match.has_kev) if match else False,
                "severity": _severity(match.max_cvss if match and cves else 0.0),
                "cves": [record.cve for record in cves],
            }
        )

    return {
        "generated_at": generated_at
        or datetime.now().isoformat(timespec="seconds"),
        "tool_version": __version__,
        "source_path": source_path,
        "component_count": len(components),
        "vulnerable_count": len(matches),
        "worst_cvss": max((m.max_cvss for m in matches), default=0.0),
        "highest_prisk": max((m.prisk for m in matches), default=0.0),
        "kev_count": sum(
            1 for match in matches for record in match.cves if record.kev
        ),
        "distribution": vulnerability_distribution(matches),
        "chart_data_uri": _chart_data_uri(chart_path),
        "narratives": [
            {
                "name": narrative.match.component.name,
                "version": narrative.match.component.version,
                "vendor": narrative.match.component.vendor or "unknown",
                "prisk": narrative.match.prisk,
                "business_impact": narrative.business_impact,
                "remediation_summary": narrative.remediation_summary,
                "rationale": narrative.rationale,
                "cves": [
                    {
                        "cve": record.cve,
                        "cvss": record.cvss,
                        "epss": record.epss,
                        "kev": record.kev,
                        "severity": _severity(record.cvss),
                    }
                    for record in narrative.match.cves
                ],
            }
            for narrative in narratives
        ],
        "rows": rows,
    }


def render_html(
    components: list[Component],
    matches: list[ComponentMatch],
    narratives: list[ComponentNarrative],
    *,
    source_path: str = "",
    chart_path: str | Path | None = None,
    generated_at: str | None = None,
) -> str:
    """Render the firmware analysis report as one self-contained HTML file."""
    context = build_context(
        components,
        matches,
        narratives,
        source_path=source_path,
        chart_path=chart_path,
        generated_at=generated_at,
    )
    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(**context) + "\n"
