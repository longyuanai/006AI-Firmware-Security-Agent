"""Deterministic manifest-backed firmware parser used as fail-open fallback."""

from __future__ import annotations

import tarfile
from io import BytesIO
from pathlib import Path
from typing import IO

import yaml

from ai_firmware_agent.normalizer import Component


def components_from_manifest(raw: str) -> list[Component]:
    """Normalize a YAML component manifest into inventory records."""
    data = yaml.safe_load(raw) or {}
    items = data.get("components") or []
    out: list[Component] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        license_name = str(item.get("license", "")).strip()
        extra = {
            "detection_sources": ["manifest"],
            "confidence": 0.95,
        }
        if license_name:
            extra["license"] = license_name
        out.append(
            Component(
                name=str(item.get("name", "")).strip(),
                version=str(item.get("version", "")).strip(),
                vendor=str(item.get("vendor", "")).strip(),
                category=str(item.get("category", "")).strip(),
                path=str(item.get("path", "")).strip(),
                extra=extra,
            )
        )
    return [component for component in out if component.name]


def parse_firmware(stream: IO[bytes]) -> list[Component]:
    """Parse a tar.gz firmware fixture and return its component inventory."""
    with tarfile.open(fileobj=stream, mode="r:gz") as archive:
        manifest_member = None
        for member in archive.getmembers():
            if member.name == "manifest.yml" or member.name.endswith(
                "/manifest.yml"
            ):
                manifest_member = member
                break
        if manifest_member is None:
            return []
        extracted = archive.extractfile(manifest_member)
        if extracted is None:
            return []
        raw = extracted.read().decode("utf-8", errors="replace")
    return components_from_manifest(raw)


def parse_firmware_file(path: str | Path) -> list[Component]:
    """Parse a manifest-backed fixture from disk without executing it."""
    with Path(path).open("rb") as stream:
        return parse_firmware(stream)


def make_demo_firmware(components: list[Component]) -> bytes:
    """Build an in-memory demo firmware tar.gz for tests and CLI demos."""
    manifest = {
        "vendor": "longyuanai-demo",
        "model": "demo-router-v1",
        "components": [
            {
                "name": component.name,
                "version": component.version,
                "vendor": component.vendor,
                "category": component.category,
                "license": component.extra.get("license", ""),
            }
            for component in components
        ],
    }
    manifest_bytes = yaml.safe_dump(manifest).encode("utf-8")
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name="manifest.yml")
        info.size = len(manifest_bytes)
        archive.addfile(info, BytesIO(manifest_bytes))
        fake = b"#!/bin/sh\necho hello\n"
        info = tarfile.TarInfo(name="rootfs/usr/bin/hello")
        info.size = len(fake)
        info.mode = 0o755
        archive.addfile(info, BytesIO(fake))
    return buffer.getvalue()
