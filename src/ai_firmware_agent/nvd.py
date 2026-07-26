"""NVD CVE API 2.0 client with a deterministic local fallback."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from ai_firmware_agent._version import USER_AGENT
from ai_firmware_agent.cve_db import CveRecord, mock_lookup
from ai_firmware_agent.normalizer import Component

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT_S = 15.0
_RESULTS_PER_PAGE = 50
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


class NvdClient:
    """Rate-limited, caching NVD client meant to live for a whole scan.

    A scan looks up every inventoried component. The OpenWrt sample in this
    repository carries 135 packages, and NVD allows 5 requests per 30 seconds
    without an API key, so issuing them back to back earns HTTP 403s and
    silently degrades every component to the local mock data.

    This client therefore paces requests to the documented limit, caches by
    (name, version) so a repeated component costs nothing, and reuses one
    connection instead of completing a TLS handshake per component.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api_key = api_key or os.getenv("NVD_API_KEY")
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep
        self._monotonic = monotonic
        self._cache: dict[tuple[str, str], list[CveRecord]] = {}
        self._last_request: float | None = None
        # NVD documents 5 requests per rolling 30 seconds without a key and
        # 50 with one. cve_db.sync applies the same policy.
        self._min_interval = 30.0 / (50 if self._api_key else 5)

    @property
    def min_interval_s(self) -> float:
        return self._min_interval

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=_DEFAULT_TIMEOUT_S)
        return self._client

    def _throttle(self) -> None:
        if self._last_request is None:
            return
        elapsed = self._monotonic() - self._last_request
        remaining = self._min_interval - elapsed
        if remaining > 0:
            self._sleep(remaining)

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def lookup(self, component: Component) -> list[CveRecord]:
        """Query NVD, falling back to ``mock_lookup`` on any failure."""
        key = (component.name.strip().lower(), component.version.strip())
        cached = self._cache.get(key)
        if cached is not None:
            return list(cached)

        self._throttle()
        try:
            response = self._http().get(
                NVD_API_URL,
                params={
                    "keywordSearch": f"{component.name} {component.version}",
                    "resultsPerPage": _RESULTS_PER_PAGE,
                },
                headers=self._headers(),
            )
            response.raise_for_status()
            records = _parse_vulnerabilities(response.json())
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            _LOG.warning(
                "NVD lookup failed for %s %s; using local mock data: %s",
                component.name,
                component.version,
                exc,
            )
            records = mock_lookup(component)
        finally:
            self._last_request = self._monotonic()

        self._cache[key] = records
        return list(records)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> NvdClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def nvd_lookup(
    component: Component,
    api_key: str | None = None,
    *,
    client: httpx.Client | None = None,
) -> list[CveRecord]:
    """Query NVD for one component and fall back to ``mock_lookup``.

    Single-shot convenience wrapper. Prefer :class:`NvdClient` when scanning a
    full inventory, so that pacing, caching and the connection are shared.
    """
    with NvdClient(api_key=api_key, client=client) as nvd:
        return nvd.lookup(component)
