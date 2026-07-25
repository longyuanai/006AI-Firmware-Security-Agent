"""CycloneDX 1.5 output schema tests."""

from __future__ import annotations

from jsonschema import validate

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.sbom import build_cyclonedx_bom

CYCLONEDX_SCHEMA = {
    "type": "object",
    "required": ["bomFormat", "specVersion", "version", "components"],
    "properties": {
        "bomFormat": {"const": "CycloneDX"},
        "specVersion": {"const": "1.5"},
        "version": {"type": "integer", "minimum": 1},
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "name", "version", "purl"],
                "properties": {
                    "type": {"const": "library"},
                    "name": {"type": "string", "minLength": 1},
                    "version": {"type": "string"},
                    "purl": {
                        "type": "string",
                        "pattern": "^pkg:generic/",
                    },
                    "licenses": {"type": "array"},
                },
            },
        },
    },
}


def test_cyclonedx_bom_validates_with_jsonschema():
    bom = build_cyclonedx_bom(
        [Component(name="openssh", version="8.5p1")]
    )
    validate(instance=bom, schema=CYCLONEDX_SCHEMA)


def test_cyclonedx_bom_contains_license():
    bom = build_cyclonedx_bom(
        [
            Component(
                name="openssh",
                version="8.5p1",
                extra={"license": "BSD-2-Clause"},
            )
        ]
    )
    assert bom["components"][0]["licenses"] == [
        {"license": {"name": "BSD-2-Clause"}}
    ]


def test_cyclonedx_components_are_sorted():
    bom = build_cyclonedx_bom(
        [
            Component(name="zlib", version="1.3"),
            Component(name="busybox", version="1.36.1"),
        ]
    )
    assert [item["name"] for item in bom["components"]] == [
        "busybox",
        "zlib",
    ]
