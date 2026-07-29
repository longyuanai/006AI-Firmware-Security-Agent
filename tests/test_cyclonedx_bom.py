"""CycloneDX 1.5 output schema tests."""

from __future__ import annotations

from jsonschema import validate

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.sbom import build_cyclonedx_bom, write_cyclonedx_bom

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


def test_cyclonedx_preserves_provider_evidence():
    bom = build_cyclonedx_bom(
        [
            Component(
                name="busybox",
                version="1.36.1",
                path="/bin/busybox",
                extra={
                    "purl": "pkg:apk/busybox@1.36.1",
                    "detection_sources": ["syft", "cve-bin-tool"],
                    "confidence": 0.93,
                },
            )
        ]
    )
    component = bom["components"][0]
    assert component["purl"] == "pkg:apk/busybox@1.36.1"
    assert component["evidence"]["occurrences"] == [
        {"location": "/bin/busybox"}
    ]
    assert component["properties"][1]["value"] == "0.93"


def test_cyclonedx_write_replaces_destination_atomically(tmp_path):
    destination = tmp_path / "sbom.json"
    destination.write_text("old", encoding="utf-8")
    written = write_cyclonedx_bom(
        [Component(name="zlib", version="1.3")],
        destination,
    )
    assert written == destination
    assert validate(
        instance=__import__("json").loads(
            destination.read_text(encoding="utf-8")
        ),
        schema=CYCLONEDX_SCHEMA,
    ) is None
    assert list(tmp_path.glob("*.tmp")) == []
