"""CycloneDX 1.5 JSON SBOM generation."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ai_firmware_agent._version import __version__
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component

TEMPLATE_PATH = Path(__file__).with_name("template.json")
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
PROPERTY_NAMESPACE = "ai-firmware-agent"

#: One (component, CVE) pair, as produced by the analyzer's matches.
VulnerabilityPair = tuple[Component, CveRecord]


def _purl(component: Component) -> str:
    provided = str(component.extra.get("purl", "")).strip()
    if provided:
        return provided
    name = quote(component.name.strip(), safe="")
    version = quote(component.version.strip(), safe="")
    return f"pkg:generic/{name}@{version}"


def _component_entry(component: Component) -> dict[str, Any]:
    purl = _purl(component)
    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "name": component.name.strip(),
        "version": component.version.strip(),
        "purl": purl,
    }
    raw_licenses = component.extra.get("licenses")
    if isinstance(raw_licenses, list):
        licenses = sorted(
            {str(item).strip() for item in raw_licenses if str(item).strip()}
        )
    else:
        license_name = str(component.extra.get("license", "")).strip()
        licenses = [license_name] if license_name else []
    if licenses:
        entry["licenses"] = [
            {"license": {"name": license_name}}
            for license_name in licenses
        ]

    evidence_paths = component.extra.get("evidence_paths")
    if not isinstance(evidence_paths, list):
        evidence_paths = [component.path] if component.path else []
    occurrences = [
        {"location": str(path)}
        for path in sorted({str(path) for path in evidence_paths if path})
    ]
    if occurrences:
        entry["evidence"] = {"occurrences": occurrences}

    properties: list[dict[str, str]] = []
    detection_sources = component.extra.get("detection_sources")
    if isinstance(detection_sources, list) and detection_sources:
        properties.append(
            {
                "name": "ai-firmware-agent:detection-sources",
                "value": ",".join(sorted(str(item) for item in detection_sources)),
            }
        )
    confidence = component.extra.get("confidence")
    if isinstance(confidence, (int, float)):
        properties.append(
            {
                "name": "ai-firmware-agent:confidence",
                "value": f"{float(confidence):.2f}",
            }
        )
    if properties:
        entry["properties"] = properties
    return entry


def _severity(cvss: float) -> str:
    """Map a CVSS base score onto the CycloneDX severity enumeration."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "unknown"


def _properties(record: CveRecord) -> list[dict[str, str]]:
    """Carry EPSS and KEV, which CycloneDX has no first-class field for."""
    properties = [
        {"name": f"{PROPERTY_NAMESPACE}:epss", "value": f"{record.epss:.6f}"},
        {
            "name": f"{PROPERTY_NAMESPACE}:kev",
            "value": "true" if record.kev else "false",
        },
    ]
    return properties


def _vulnerability_entry(
    record: CveRecord,
    refs: list[str],
) -> dict[str, Any]:
    rating: dict[str, Any] = {
        "source": {"name": "NVD"},
        "severity": _severity(record.cvss),
        "method": "CVSSv3",
    }
    if record.cvss > 0.0:
        rating["score"] = record.cvss
    entry: dict[str, Any] = {
        "bom-ref": f"vuln:{record.cve}",
        "id": record.cve,
        "source": {"name": "NVD", "url": f"{NVD_DETAIL_URL}{record.cve}"},
        "ratings": [rating],
        "affects": [{"ref": ref} for ref in refs],
        "properties": _properties(record),
    }
    if record.summary.strip():
        entry["description"] = record.summary.strip()
    return entry


def _vulnerabilities(
    pairs: Iterable[VulnerabilityPair],
) -> list[dict[str, Any]]:
    """Group pairs by CVE so one entry lists every component it affects."""
    grouped: dict[str, tuple[CveRecord, list[str]]] = {}
    for component, record in pairs:
        cve = record.cve.strip().upper()
        if not cve:
            continue
        ref = _purl(component)
        if cve not in grouped:
            grouped[cve] = (record, [])
        refs = grouped[cve][1]
        if ref not in refs:
            refs.append(ref)
    return [
        _vulnerability_entry(record, sorted(refs))
        for cve, (record, refs) in sorted(grouped.items())
    ]


def build_cyclonedx_bom(
    components: list[Component],
    vulnerabilities: Iterable[VulnerabilityPair] = (),
) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.5 JSON object.

    ``vulnerabilities`` accepts (component, CVE) pairs and is rendered as a
    CycloneDX ``vulnerabilities`` array. The scan already computes this, and
    an SBOM that omits it forces consumers to re-derive what is known.
    """
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    bom: dict[str, Any] = deepcopy(template)
    bom["metadata"] = {
        "tools": [
            {
                "vendor": "longyuanai",
                "name": "ai-firmware-agent",
                "version": __version__,
            }
        ]
    }
    bom["components"] = [
        _component_entry(component)
        for component in sorted(
            components,
            key=lambda item: (item.name.lower(), item.version),
        )
        if component.name.strip()
    ]
    entries = _vulnerabilities(vulnerabilities)
    if entries:
        bom["vulnerabilities"] = entries
    return bom


def write_cyclonedx_bom(
    components: list[Component],
    output_path: str | Path,
    vulnerabilities: Iterable[VulnerabilityPair] = (),
) -> Path:
    """Write a CycloneDX document without including firmware contents."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = (
        json.dumps(
            build_cyclonedx_bom(components, vulnerabilities),
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            stream.write(content)
            temporary = Path(stream.name)
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
