"""FIRST EPSS API client for exploit-probability enrichment."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

import httpx

from ai_firmware_agent.cve_db import CveRecord

EPSS_API_URL = "https://api.first.org/data/v1/epss"
_DEFAULT_TIMEOUT_S = 15.0
_MAX_CVE_QUERY_CHARS = 2000
_LOG = logging.getLogger(__name__)


def _normalized_cves(cves: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(cve.strip().upper() for cve in cves if cve.strip()))


def _query_chunks(cves: list[str]) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    current_length = 0
    for cve in cves:
        added_length = len(cve) + (1 if current else 0)
        if current and current_length + added_length > _MAX_CVE_QUERY_CHARS:
            chunks.append(current)
            current = []
            current_length = 0
            added_length = len(cve)
        current.append(cve)
        current_length += added_length
    if current:
        chunks.append(current)
    return chunks


def _parse_scores(payload: Any) -> dict[str, float]:
    if not isinstance(payload, Mapping):
        raise ValueError("EPSS response must be a JSON object")
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("EPSS response is missing data")

    scores: dict[str, float] = {}
    for item in data:
        if not isinstance(item, Mapping):
            continue
        cve = str(item.get("cve", "")).strip().upper()
        try:
            score = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        if cve and 0.0 <= score <= 1.0:
            scores[cve] = score
    return scores


def epss_scores(
    cves: Iterable[str],
    *,
    client: httpx.Client | None = None,
) -> dict[str, float]:
    """Return EPSS scores; failed or missing entries are omitted."""
    normalized = _normalized_cves(cves)
    if not normalized:
        return {}

    owns_client = client is None
    http = client or httpx.Client(timeout=_DEFAULT_TIMEOUT_S)
    scores: dict[str, float] = {}
    try:
        for chunk in _query_chunks(normalized):
            try:
                response = http.get(EPSS_API_URL, params={"cve": ",".join(chunk)})
                response.raise_for_status()
                scores.update(_parse_scores(response.json()))
            except (httpx.HTTPError, TypeError, ValueError) as exc:
                _LOG.warning(
                    "EPSS lookup failed for %d CVE(s); using 0.0: %s",
                    len(chunk),
                    exc,
                )
        return scores
    finally:
        if owns_client:
            http.close()


def epss_lookup(cve: str, *, client: httpx.Client | None = None) -> float:
    """Return one EPSS score, defaulting to 0.0 on API failure or no match."""
    normalized = cve.strip().upper()
    if not normalized:
        return 0.0
    return epss_scores([normalized], client=client).get(normalized, 0.0)


def enrich_with_epss(
    records: Iterable[CveRecord],
    *,
    client: httpx.Client | None = None,
) -> list[CveRecord]:
    """Return copies of CVE records enriched in one batched EPSS lookup."""
    source = list(records)
    scores = epss_scores((record.cve for record in source), client=client)
    return [
        replace(record, epss=scores.get(record.cve.strip().upper(), 0.0))
        for record in source
    ]
