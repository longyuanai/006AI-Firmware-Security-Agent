"""Strict, import-only adapter for EMBA's F15 CycloneDX JSON output.

The adapter never invokes EMBA.  It accepts the versioned JSON artifact that
EMBA's official F15 module writes and deliberately rejects other report shapes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_firmware_agent.analyzer import match_components, score_and_rank_matches
from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.v05_compat import FindingSeverity, new_finding

EMBA_CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
EMBA_CYCLONEDX_VERSION = "1.5"
EMBA_TOOL_NAME = "EMBA binary analysis environment"


class EmbaImportError(ValueError):
    """Base class for rejected EMBA report input."""


class EmbaParseError(EmbaImportError):
    """The report is not valid UTF-8 JSON."""


class EmbaMissingFieldError(EmbaImportError):
    """A field required by the supported EMBA output is absent."""


class EmbaUnsupportedVersionError(EmbaImportError):
    """The report uses a CycloneDX version this adapter has not verified."""


class EmbaSchemaError(EmbaImportError):
    """The JSON is valid but is not the supported EMBA F15 shape."""


@dataclass(frozen=True)
class EmbaReport:
    """Validated EMBA inventory ready for the existing firmware pipeline."""

    components: tuple[Component, ...]
    tool_version: str


def _required(mapping: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in mapping:
        raise EmbaMissingFieldError(f"missing required field: {path}.{key}")
    return mapping[key]


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EmbaSchemaError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise EmbaSchemaError(f"{path} must be an array")
    return value


def _text(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise EmbaSchemaError(f"{path} must be a string")
    if not allow_empty and not value.strip():
        raise EmbaMissingFieldError(f"missing required field: {path}")
    return value.strip()


def _optional_text(mapping: Mapping[str, Any], key: str, path: str) -> str:
    if key not in mapping:
        return ""
    return _text(mapping[key], f"{path}.{key}", allow_empty=True)


def _tool_version(metadata: Mapping[str, Any]) -> str:
    tools = _mapping(_required(metadata, "tools", "$.metadata"), "$.metadata.tools")
    tool_components = _array(
        _required(tools, "components", "$.metadata.tools"),
        "$.metadata.tools.components",
    )
    for index, raw_tool in enumerate(tool_components):
        tool = _mapping(raw_tool, f"$.metadata.tools.components[{index}]")
        name = _optional_text(tool, "name", f"$.metadata.tools.components[{index}]")
        if name != EMBA_TOOL_NAME:
            continue
        author = _text(
            _required(tool, "author", f"$.metadata.tools.components[{index}]"),
            f"$.metadata.tools.components[{index}].author",
        )
        if author != "EMBA community":
            raise EmbaSchemaError("EMBA tool author marker is invalid")
        return _text(
            _required(tool, "version", f"$.metadata.tools.components[{index}]"),
            f"$.metadata.tools.components[{index}].version",
        )
    raise EmbaSchemaError(f"metadata does not identify {EMBA_TOOL_NAME}")


def _component(raw: Any, index: int, seen_refs: set[str]) -> Component:
    path = f"$.components[{index}]"
    item = _mapping(raw, path)
    bom_ref = _text(_required(item, "bom-ref", path), f"{path}.bom-ref")
    if bom_ref in seen_refs:
        raise EmbaSchemaError(f"duplicate component bom-ref: {bom_ref}")
    seen_refs.add(bom_ref)

    name = _text(_required(item, "name", path), f"{path}.name")
    category = _text(_required(item, "type", path), f"{path}.type")
    version = _optional_text(item, "version", path)
    vendor = _optional_text(item, "publisher", path)
    supplier = item.get("supplier")
    if not vendor and supplier is not None:
        supplier_mapping = _mapping(supplier, f"{path}.supplier")
        vendor = _optional_text(supplier_mapping, "name", f"{path}.supplier")

    extra: dict[str, Any] = {
        "detection_sources": ["emba"],
        "confidence": 0.9,
        "emba_bom_ref": bom_ref,
    }
    purl = _optional_text(item, "purl", path)
    if purl:
        extra["purl"] = purl
    return Component(
        name=name,
        version=version,
        vendor=vendor,
        category=category,
        # EMBA component properties can contain customer filesystem paths.
        # They are intentionally not copied into the internal model.
        path="",
        extra=extra,
    )


def parse_emba_report(payload: Any) -> EmbaReport:
    """Validate and parse one EMBA F15 CycloneDX 1.5 JSON document."""
    if isinstance(payload, (str, bytes, bytearray)):
        try:
            payload = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EmbaParseError(f"invalid EMBA JSON: {type(exc).__name__}") from exc

    root = _mapping(payload, "$")
    schema = _text(_required(root, "$schema", "$"), "$.$schema")
    if schema != EMBA_CYCLONEDX_SCHEMA:
        raise EmbaSchemaError("unsupported EMBA report schema")
    bom_format = _text(_required(root, "bomFormat", "$"), "$.bomFormat")
    if bom_format != "CycloneDX":
        raise EmbaSchemaError("EMBA report bomFormat must be CycloneDX")
    spec_version = _text(_required(root, "specVersion", "$"), "$.specVersion")
    if spec_version != EMBA_CYCLONEDX_VERSION:
        raise EmbaUnsupportedVersionError(
            f"unsupported EMBA CycloneDX version: {spec_version}"
        )
    document_version = _required(root, "version", "$")
    if type(document_version) is not int or document_version != 1:
        raise EmbaUnsupportedVersionError(
            f"unsupported EMBA document version: {document_version!r}"
        )
    _text(_required(root, "serialNumber", "$"), "$.serialNumber")

    metadata = _mapping(_required(root, "metadata", "$"), "$.metadata")
    _text(_required(metadata, "timestamp", "$.metadata"), "$.metadata.timestamp")
    tool_version = _tool_version(metadata)

    dependencies = _array(_required(root, "dependencies", "$"), "$.dependencies")
    for index, dependency in enumerate(dependencies):
        _mapping(dependency, f"$.dependencies[{index}]")

    vulnerabilities = _array(
        _required(root, "vulnerabilities", "$"),
        "$.vulnerabilities",
    )
    # The verified F15 generator currently writes this array as [].  Accepting
    # guessed vulnerability records would claim support for an output EMBA does
    # not produce and would weaken the fail-closed contract.
    if vulnerabilities:
        raise EmbaSchemaError(
            "unsupported EMBA F15 shape: vulnerabilities must be empty"
        )

    raw_components = _array(_required(root, "components", "$"), "$.components")
    seen_refs: set[str] = set()
    components = tuple(
        _component(raw_component, index, seen_refs)
        for index, raw_component in enumerate(raw_components)
    )
    return EmbaReport(components=components, tool_version=tool_version)


def load_emba_report(path: Path) -> EmbaReport:
    """Read an existing EMBA report; no subprocess or network is used."""
    try:
        raw = path.read_bytes().decode("utf-8-sig")
    except UnicodeError as exc:
        raise EmbaParseError("EMBA report must be UTF-8 JSON") from exc
    return parse_emba_report(raw)


def _severity(cvss: float) -> FindingSeverity:
    if cvss >= 9.0:
        return FindingSeverity.CRITICAL
    if cvss >= 7.0:
        return FindingSeverity.HIGH
    if cvss >= 4.0:
        return FindingSeverity.MEDIUM
    if cvss > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _finding(component: Component, cve: CveRecord, prisk: float) -> dict[str, Any]:
    kev_text = "KEV listed" if cve.kev else "not KEV listed"
    narrative = (
        f"PRisk {prisk:.3f}; EPSS {cve.epss:.4f}; {kev_text}. "
        f"{cve.summary}"
    )
    finding = new_finding(
        severity=_severity(cve.cvss),
        confidence=min(0.99, 0.70 + 0.03 * max(0.0, min(10.0, cve.cvss))),
        title=f"{cve.cve} in {component.name} {component.version}",
        description=narrative,
        cve=cve.cve,
        evidence=(
            f"component:{component.name}@{component.version}",
            f"cvss:{cve.cvss:.1f}",
            f"prisk:{prisk:.6f}",
        ),
        tags=frozenset({"firmware", "cve", "prisk"}),
        metadata={
            "finding_origin": "emba_import",
            "component": component.name,
            "component_version": component.version,
            "cvss": cve.cvss,
            "epss": cve.epss,
            "kev": cve.kev,
            "prisk": prisk,
        },
    )
    result = finding.to_dict()
    result["narrative"] = narrative
    return result


def emba_report_to_envelope(report: EmbaReport) -> dict[str, Any]:
    """Run imported components through the existing offline CVE matcher."""
    matches = match_components(list(report.components), lookup_fn=mock_lookup)
    scored = score_and_rank_matches(matches)
    score_by_component = {
        (item.component.component.name, item.component.component.version): item.score
        for item in scored
    }
    findings = [
        _finding(
            match.component,
            cve,
            score_by_component[(match.component.name, match.component.version)],
        )
        for match in matches
        for cve in match.cves
    ]
    return {
        "findings": findings,
        "errors": [],
        "summary": {
            "component_count": len(report.components),
            "finding_count": len(findings),
            "status": "ok",
        },
    }


def import_emba_path_to_envelope(path: Path) -> dict[str, Any]:
    """Return a stable envelope, reporting typed import failures as errors."""
    try:
        return emba_report_to_envelope(load_emba_report(path))
    except (EmbaImportError, OSError) as exc:
        return {
            "findings": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "summary": {
                "component_count": 0,
                "finding_count": 0,
                "status": "warning",
            },
        }


__all__ = [
    "EMBA_CYCLONEDX_SCHEMA",
    "EMBA_CYCLONEDX_VERSION",
    "EMBA_TOOL_NAME",
    "EmbaImportError",
    "EmbaMissingFieldError",
    "EmbaParseError",
    "EmbaReport",
    "EmbaSchemaError",
    "EmbaUnsupportedVersionError",
    "emba_report_to_envelope",
    "import_emba_path_to_envelope",
    "load_emba_report",
    "parse_emba_report",
]
