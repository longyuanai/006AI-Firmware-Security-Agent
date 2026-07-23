"""NVD CVE API 2.0 client with a deterministic local fallback."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

import httpx

from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT_S = 15.0
_LOG = logging.getLogger(__name__)


def _description(cve: Mapping[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, Mapping) and item.get("lang") == "en":
            return str(item.get("value", ""))
    for item in descriptions:
        if isinstance(item, Mapping):
            return str(item.get("value", ""))
    return ""


def _cvss_score(cve: Mapping[str, Any]) -> float:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, Mapping):
        return 0.0
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        candidates = metrics.get(metric_name, [])
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            cvss_data = candidate.get("cvssData", {})
            if not isinstance(cvss_data, Mapping):
                continue
            try:
                return float(cvss_data["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return 0.0


def _parse_vulnerabilities(payload: Any) -> list[CveRecord]:
    if not isinstance(payload, Mapping):
        raise ValueError("NVD response must be a JSON object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response is missing vulnerabilities")

    records: list[CveRecord] = []
    seen: set[str] = set()
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue
        cve_id = str(cve.get("id", "")).strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        records.append(
            CveRecord(
                cve=cve_id,
                cvss=_cvss_score(cve),
                summary=_description(cve),
            )
        )
    return records


def nvd_lookup(
    component: Component,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
) -> list[CveRecord]:
    """Query NVD for a component and fall back to ``mock_lookup`` on failure."""
    headers = {
        "User-Agent": "ai-firmware-security-agent/0.1",
    }
    resolved_api_key = api_key or os.getenv("NVD_API_KEY")
    if resolved_api_key:
        headers["apiKey"] = resolved_api_key

    owns_client = client is None
    http = client or httpx.Client(timeout=_DEFAULT_TIMEOUT_S)
    try:
        response = http.get(
            NVD_API_URL,
            params={"keywordSearch": f"{component.name} {component.version}"},
            headers=headers,
        )
        response.raise_for_status()
        return _parse_vulnerabilities(response.json())
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        _LOG.warning(
            "NVD lookup failed for %s %s; using local mock data: %s",
            component.name,
            component.version,
            exc,
        )
        return mock_lookup(component)
    finally:
        if owns_client:
            http.close()
