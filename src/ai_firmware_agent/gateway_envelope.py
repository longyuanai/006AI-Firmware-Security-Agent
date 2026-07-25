"""Offline JSON envelope used by shared-integration's firmware adapter."""

from __future__ import annotations

import ipaddress
import json
import tarfile
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from ai_firmware_agent.analyzer import match_components, score_and_rank_matches
from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import parse_firmware_file
from ai_firmware_agent.unpack import FirmwareUnpackError, unpack_firmware
from ai_firmware_agent.v05_compat import FindingSeverity, new_finding

MAX_FIRMWARE_BYTES = 10 * 1024 * 1024


class GatewayPayloadError(ValueError):
    """Raised when the adapter JSON payload violates the firmware contract."""


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


def _validate_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise GatewayPayloadError("firmware_url must use http or https")
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise GatewayPayloadError("firmware_url must not target localhost")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return raw_url
    if not address.is_global:
        raise GatewayPayloadError("firmware_url must use a public address")
    return raw_url


def _parse_payload(raw: str) -> dict[str, str]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GatewayPayloadError("input must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise GatewayPayloadError("input must be a JSON object")

    firmware_path = payload.get("firmware_path")
    firmware_url = payload.get("firmware_url")
    if bool(firmware_path) == bool(firmware_url):
        raise GatewayPayloadError(
            "provide exactly one of firmware_path or firmware_url"
        )
    if firmware_path:
        if not isinstance(firmware_path, str):
            raise GatewayPayloadError("firmware_path must be a string")
        path = Path(firmware_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        return {"firmware_path": str(path.resolve())}
    if not isinstance(firmware_url, str):
        raise GatewayPayloadError("firmware_url must be a string")
    return {"firmware_url": _validate_url(firmware_url)}


def _download_firmware(
    url: str,
    destination: Path,
    *,
    client: httpx.Client | None = None,
) -> None:
    owns_client = client is None
    active_client = client or httpx.Client(follow_redirects=True, timeout=30.0)
    total = 0
    try:
        with active_client.stream("GET", url) as response:
            response.raise_for_status()
            with destination.open("wb") as stream:
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_FIRMWARE_BYTES:
                        raise GatewayPayloadError(
                            "downloaded firmware exceeds 10 MiB limit"
                        )
                    stream.write(chunk)
    except httpx.HTTPError as exc:
        raise GatewayPayloadError(f"firmware download failed: {exc}") from exc
    finally:
        if owns_client:
            active_client.close()


@contextmanager
def materialize_firmware(
    raw_payload: str,
    *,
    client: httpx.Client | None = None,
) -> Iterator[Path]:
    """Resolve a path or bounded public HTTP(S) download for one scan."""
    payload = _parse_payload(raw_payload)
    if "firmware_path" in payload:
        path = Path(payload["firmware_path"]).resolve(strict=True)
        if not path.is_file():
            raise GatewayPayloadError(f"firmware_path is not a file: {path}")
        if path.stat().st_size > MAX_FIRMWARE_BYTES:
            raise GatewayPayloadError("firmware_path exceeds 10 MiB limit")
        yield path
        return

    with tempfile.TemporaryDirectory(prefix="firmware-gateway-") as temp_dir:
        url = payload["firmware_url"]
        suffixes = Path(urlparse(url).path).suffixes
        suffix = "".join(suffixes[-2:]) if suffixes else ".bin"
        if suffix.lower() not in {".bin", ".tar.gz", ".tgz"}:
            suffix = ".bin"
        downloaded = Path(temp_dir) / f"downloaded-firmware{suffix}"
        _download_firmware(url, downloaded, client=client)
        yield downloaded


def _parse_components(path: Path) -> list[Component]:
    if path.suffix.lower() == ".bin":
        try:
            return unpack_firmware(path)
        except FirmwareUnpackError as unpack_error:
            manifest = _matching_openwrt_manifest(path)
            if manifest is not None:
                components = _components_from_openwrt_manifest(manifest)
                if components:
                    return components
            try:
                return parse_firmware_file(path)
            except (
                OSError,
                tarfile.TarError,
                UnicodeError,
                ValueError,
                yaml.YAMLError,
            ):
                raise unpack_error from None
    return parse_firmware_file(path)


def _matching_openwrt_manifest(firmware: Path) -> Path | None:
    """Find the official target manifest shipped beside an OpenWrt image."""
    matches: list[Path] = []
    for candidate in firmware.parent.glob("*.manifest"):
        prefix = candidate.name.removesuffix(".manifest")
        if firmware.name.startswith(f"{prefix}-"):
            matches.append(candidate)
    if not matches:
        return None
    return max(matches, key=lambda candidate: len(candidate.name))


def _components_from_openwrt_manifest(manifest: Path) -> list[Component]:
    """Parse OpenWrt's ``package - version`` release manifest format."""
    components: list[Component] = []
    for raw_line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        name, separator, version = raw_line.partition(" - ")
        name = name.strip()
        version = version.strip()
        if not separator or not name or not version:
            continue
        components.append(
            Component(
                name=name,
                version=version,
                vendor="OpenWrt",
                category="package",
                path=str(manifest),
            )
        )
    return components


def _finding_payload(
    *,
    path: Path,
    component_name: str,
    component_version: str,
    cve: CveRecord,
    prisk: float,
) -> dict[str, Any]:
    kev_text = "KEV listed" if cve.kev else "not KEV listed"
    narrative = (
        f"PRisk {prisk:.3f}; EPSS {cve.epss:.4f}; {kev_text}. "
        f"{cve.summary}"
    )
    confidence = min(0.99, 0.70 + 0.03 * max(0.0, min(10.0, cve.cvss)))
    finding = new_finding(
        severity=_severity(cve.cvss),
        confidence=confidence,
        title=f"{cve.cve} in {component_name} {component_version}",
        description=narrative,
        host=str(path),
        cve=cve.cve,
        evidence=(
            f"component:{component_name}@{component_version}",
            f"cvss:{cve.cvss:.1f}",
            f"prisk:{prisk:.6f}",
        ),
        tags=frozenset({"firmware", "cve", "prisk"}),
        metadata={
            "component": component_name,
            "component_version": component_version,
            "cvss": cve.cvss,
            "epss": cve.epss,
            "kev": cve.kev,
            "prisk": prisk,
        },
    )
    payload = finding.to_dict()
    payload["narrative"] = narrative
    return payload


def scan_path_to_envelope(path: Path) -> dict[str, Any]:
    """Scan one local firmware path without network or LLM calls."""
    try:
        components = _parse_components(path)
    except (
        FirmwareUnpackError,
        OSError,
        tarfile.TarError,
        UnicodeError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        return {
            "findings": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "summary": {
                "component_count": 0,
                "finding_count": 0,
                "status": "warning",
            },
        }

    matches = match_components(components, lookup_fn=mock_lookup)
    scored = score_and_rank_matches(matches)
    score_by_component = {
        (
            item.component.component.name,
            item.component.component.version,
        ): item.score
        for item in scored
    }
    findings = [
        _finding_payload(
            path=path,
            component_name=match.component.name,
            component_version=match.component.version,
            cve=cve,
            prisk=score_by_component[
                (match.component.name, match.component.version)
            ],
        )
        for match in matches
        for cve in match.cves
    ]
    return {
        "findings": findings,
        "errors": [],
        "summary": {
            "component_count": len(components),
            "finding_count": len(findings),
            "status": "ok",
        },
    }


def components_from_payload(
    raw_payload: str,
    *,
    client: httpx.Client | None = None,
) -> tuple[list[Component], list[str]]:
    """Resolve an envelope payload and return inventory for SBOM export."""
    try:
        with materialize_firmware(raw_payload, client=client) as path:
            return _parse_components(path), []
    except (
        FirmwareUnpackError,
        GatewayPayloadError,
        OSError,
        tarfile.TarError,
        UnicodeError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        return [], [f"{type(exc).__name__}: {exc}"]


def scan_payload_to_envelope(
    raw_payload: str,
    *,
    client: httpx.Client | None = None,
) -> Mapping[str, Any]:
    """Materialize an adapter payload and return a JSON-ready envelope."""
    try:
        with materialize_firmware(raw_payload, client=client) as path:
            return scan_path_to_envelope(path)
    except (GatewayPayloadError, OSError) as exc:
        return {
            "findings": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "summary": {
                "component_count": 0,
                "finding_count": 0,
                "status": "warning",
            },
        }
