"""CycloneDX vulnerabilities (VEX) section.

The scan already resolves CVEs for every component; an SBOM that drops them
forces every consumer to re-derive what this tool already knows.
"""

from __future__ import annotations

import json

from click.testing import CliRunner
from jsonschema import validate

from ai_firmware_agent._version import __version__
from ai_firmware_agent.cli import cli
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware
from ai_firmware_agent.sbom import build_cyclonedx_bom

VEX_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["bom-ref", "id", "source", "ratings", "affects"],
                "properties": {
                    "id": {"type": "string", "pattern": "^CVE-"},
                    "ratings": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["severity", "method"],
                            "properties": {
                                "severity": {
                                    "enum": [
                                        "critical",
                                        "high",
                                        "medium",
                                        "low",
                                        "info",
                                        "none",
                                        "unknown",
                                    ]
                                },
                                "score": {"type": "number"},
                            },
                        },
                    },
                    "affects": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["ref"],
                        },
                    },
                },
            },
        }
    },
}

LIGHTTPD = Component(name="lighttpd", version="1.4.50", category="web_server")
BUSYBOX = Component(name="busybox", version="1.36.1")
RECORD = CveRecord(
    cve="CVE-2018-19052",
    cvss=9.8,
    summary="lighttpd path traversal",
    epss=0.42,
    kev=True,
)


def test_bom_without_vulnerabilities_omits_the_section():
    bom = build_cyclonedx_bom([LIGHTTPD])
    assert "vulnerabilities" not in bom


def test_vulnerability_entry_validates_and_links_to_its_component():
    bom = build_cyclonedx_bom([LIGHTTPD], [(LIGHTTPD, RECORD)])
    validate(instance=bom, schema=VEX_SCHEMA)

    entry = bom["vulnerabilities"][0]
    assert entry["id"] == "CVE-2018-19052"
    assert entry["ratings"][0]["score"] == 9.8
    assert entry["ratings"][0]["severity"] == "critical"
    assert entry["affects"] == [{"ref": "pkg:generic/lighttpd@1.4.50"}]
    assert entry["affects"][0]["ref"] == bom["components"][0]["bom-ref"]


def test_epss_and_kev_survive_the_export():
    bom = build_cyclonedx_bom([LIGHTTPD], [(LIGHTTPD, RECORD)])
    properties = {
        item["name"]: item["value"]
        for item in bom["vulnerabilities"][0]["properties"]
    }
    assert properties["ai-firmware-agent:epss"] == "0.420000"
    assert properties["ai-firmware-agent:kev"] == "true"


def test_one_cve_affecting_two_components_is_a_single_entry():
    bom = build_cyclonedx_bom(
        [LIGHTTPD, BUSYBOX],
        [(LIGHTTPD, RECORD), (BUSYBOX, RECORD)],
    )
    assert len(bom["vulnerabilities"]) == 1
    assert bom["vulnerabilities"][0]["affects"] == [
        {"ref": "pkg:generic/busybox@1.36.1"},
        {"ref": "pkg:generic/lighttpd@1.4.50"},
    ]


def test_unscored_cve_is_reported_as_unknown_without_a_score():
    unscored = CveRecord(cve="CVE-2025-0000", cvss=0.0, summary="")
    entry = build_cyclonedx_bom([BUSYBOX], [(BUSYBOX, unscored)])[
        "vulnerabilities"
    ][0]
    assert entry["ratings"][0]["severity"] == "unknown"
    assert "score" not in entry["ratings"][0]
    assert "description" not in entry


def test_export_is_deterministic():
    first = build_cyclonedx_bom([BUSYBOX, LIGHTTPD], [(LIGHTTPD, RECORD)])
    second = build_cyclonedx_bom([LIGHTTPD, BUSYBOX], [(LIGHTTPD, RECORD)])
    assert first == second


def test_metadata_records_the_producing_tool():
    tool = build_cyclonedx_bom([])["metadata"]["tools"][0]
    assert tool["name"] == "ai-firmware-agent"
    assert tool["version"] == __version__


def _firmware(tmp_path):
    path = tmp_path / "firmware.tar.gz"
    path.write_bytes(make_demo_firmware([LIGHTTPD]))
    return path


def test_cli_sbom_includes_vulnerabilities(tmp_path):
    output = tmp_path / "sbom.json"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(_firmware(tmp_path)),
            "--sbom",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    bom = json.loads(output.read_text(encoding="utf-8"))
    assert [item["id"] for item in bom["vulnerabilities"]] == [
        "CVE-2018-19052"
    ]


def test_cli_sbom_does_not_reach_nvd_by_default(monkeypatch, tmp_path):
    """Bulk export must not fan out one rate-limited request per component."""
    import ai_firmware_agent.cli as cli_module

    def fail(*_args, **_kwargs):
        raise AssertionError("SBOM export must stay offline by default")

    monkeypatch.setattr(cli_module, "nvd_lookup", fail)
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(_firmware(tmp_path)),
            "--sbom",
            str(tmp_path / "sbom.json"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_sbom_honours_an_explicit_cve_source(monkeypatch, tmp_path):
    import ai_firmware_agent.cli as cli_module

    calls: list[str] = []

    def fake_nvd(component, api_key=None, **_kwargs):
        calls.append(component.name)
        return [RECORD]

    monkeypatch.setattr(cli_module, "nvd_lookup", fake_nvd)
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(_firmware(tmp_path)),
            "--sbom",
            str(tmp_path / "sbom.json"),
            "--cve-source",
            "nvd",
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == ["lighttpd"]
