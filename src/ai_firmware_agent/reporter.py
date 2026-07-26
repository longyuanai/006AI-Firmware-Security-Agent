"""Markdown report renderer for firmware analysis."""

from __future__ import annotations

from datetime import datetime

from ai_firmware_agent.analyzer import ComponentMatch, ComponentNarrative


def render_markdown(
    components: list,  # list[Component]
    matches: list[ComponentMatch],
    narratives: list[ComponentNarrative],
    *,
    source_path: str = "",
    chart_path: str = "",
) -> str:
    """Render the firmware analysis Markdown report."""
    lines: list[str] = []
    lines.append("# Firmware Security Report")
    lines.append("")
    lines.append(f"_Generated at {datetime.now().isoformat(timespec='seconds')}_")
    if source_path:
        lines.append(f"_Source: `{source_path}`_")
    lines.append("")

    # Summary.
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Components inventoried: **{len(components)}**")
    lines.append(f"- Components with known CVEs: **{len(matches)}**")
    if matches:
        max_cvss = max(m.max_cvss for m in matches)
        lines.append(f"- Worst CVSS in firmware: **{max_cvss:.1f}**")
        kev_count = sum(cve.kev for match in matches for cve in match.cves)
        lines.append(f"- CISA KEV-listed CVEs: **{kev_count}**")
        lines.append(f"- Highest PRisk: **{max(match.prisk for match in matches):.3f}**")
    lines.append("")

    if chart_path:
        lines.append("## Vulnerability Distribution")
        lines.append("")
        lines.append(f"![Vulnerability distribution]({chart_path})")
        lines.append("")

    # Top-N LLM-enriched.
    lines.append("## Top Risks (LLM-enriched)")
    lines.append("")
    if not narratives:
        lines.append("_No LLM enrichment produced._")
        lines.append("")
    else:
        for n in narratives:
            lines.append(n.to_markdown())

    # Full SBOM/CVE table.
    lines.append("## Full Component Inventory")
    lines.append("")
    lines.append(
        "| Component | Version | Vendor | CVE Count | PRisk | Worst CVSS | "
        "Max EPSS | KEV | CVEs |"
    )
    lines.append(
        "|-----------|---------|--------|-----------|-------|------------|"
        "----------|-----|------|"
    )
    # Identity first, so a match always lands on the exact component it was
    # built from; then fall back to name@version, so a component that is only
    # value-equal (a duplicate entry, or an inventory rebuilt by the caller)
    # still reports its CVEs instead of rendering an empty row. Building both
    # maps once also drops the per-row linear scan this used to do.
    by_identity = {id(item.component): item for item in matches}
    by_key: dict[tuple[str, str], ComponentMatch] = {}
    for item in matches:
        by_key.setdefault((item.component.name, item.component.version), item)

    for c in components:
        match = by_identity.get(id(c)) or by_key.get((c.name, c.version))
        if match and match.cves:
            worst = match.max_cvss
            prisk = match.prisk
            max_epss = match.max_epss
            kev = "yes" if match.has_kev else "no"
            cves = ", ".join(cve.cve for cve in match.cves)
        else:
            worst = 0.0
            prisk = 0.0
            max_epss = 0.0
            kev = "no"
            cves = "-"
        lines.append(
            f"| {c.name} | {c.version} | {c.vendor or '-'} | "
            f"{len(match.cves) if match else 0} | {prisk:.3f} | {worst:.1f} | "
            f"{max_epss:.4f} | {kev} | {cves} |"
        )
    lines.append("")

    return "\n".join(lines)
