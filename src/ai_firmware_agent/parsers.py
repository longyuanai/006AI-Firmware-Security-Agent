"""Firmware parser.

PoC format: a tar.gz containing:
  manifest.yml  – a YAML file with the list of components
  rootfs/...    – simulated filesystem layout (files ignored for PoC)

Real firmware is opaque (binwalk → squashfs → package list). We punt on
that for the PoC by accepting a structured manifest alongside the blob.
This lets the entire pipeline (parser → SBOM → CVE → LLM) work without
needing real device dumps.
"""

from __future__ import annotations

import tarfile
from io import BytesIO
from pathlib import Path
from typing import IO

import yaml

from ai_firmware_agent.normalizer import Component


def _manifest_to_components(raw: str) -> list[Component]:
    data = yaml.safe_load(raw) or {}
    items = data.get("components") or []
    out: list[Component] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(
            Component(
                name=str(it.get("name", "")).strip(),
                version=str(it.get("version", "")).strip(),
                vendor=str(it.get("vendor", "")).strip(),
                category=str(it.get("category", "")).strip(),
                path=str(it.get("path", "")).strip(),
            )
        )
    return [c for c in out if c.name]


def parse_firmware(stream: IO[bytes]) -> list[Component]:
    """Parse a tar.gz firmware blob; return the component inventory."""
    with tarfile.open(fileobj=stream, mode="r:gz") as tf:
        manifest_member = None
        for m in tf.getmembers():
            if m.name == "manifest.yml" or m.name.endswith("/manifest.yml"):
                manifest_member = m
                break
        if manifest_member is None:
            return []
        f = tf.extractfile(manifest_member)
        if f is None:
            return []
        raw = f.read().decode("utf-8", errors="replace")
    return _manifest_to_components(raw)


def parse_firmware_file(path: str | Path) -> list[Component]:
    """Parse a firmware file from disk."""
    with open(path, "rb") as f:
        return parse_firmware(f)


def make_demo_firmware(components: list[Component]) -> bytes:
    """Build an in-memory demo firmware tar.gz (used by tests + CLI demo)."""
    manifest = {
        "vendor": "longyuanai-demo",
        "model": "demo-router-v1",
        "components": [
            {"name": c.name, "version": c.version, "vendor": c.vendor, "category": c.category}
            for c in components
        ],
    }
    manifest_bytes = yaml.safe_dump(manifest).encode("utf-8")
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="manifest.yml")
        info.size = len(manifest_bytes)
        tf.addfile(info, BytesIO(manifest_bytes))
        # Add a fake rootfs file so the archive looks real.
        fake = b"#!/bin/sh\necho hello\n"
        info = tarfile.TarInfo(name="rootfs/usr/bin/hello")
        info.size = len(fake)
        info.mode = 0o755
        tf.addfile(info, BytesIO(fake))
    return buf.getvalue()