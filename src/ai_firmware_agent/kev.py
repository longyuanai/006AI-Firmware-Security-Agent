"""CISA Known Exploited Vulnerabilities catalog client."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Set
from dataclasses import replace
from typing import Any

import httpx

from ai_firmware_agent._version import USER_AGENT
from ai_firmware_agent.cve_db import CveRecord

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_DEFAULT_TIMEOUT_S = 15.0
_LOG = logging.getLogger(__name__)


def _parse_catalog(payload: Any) -> frozenset[str]:
    if not isinstance(payload, Mapping):
        raise ValueError("CISA KEV response must be a JSON object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV response is missing vulnerabilities")

    cves = {
        str(item.get("cveID", "")).strip().upper()
        for item in vulnerabilities
        if isinstance(item, Mapping)
    }
    cves.discard("")
    return frozenset(cves)


def fetch_kev_catalog(
    *,
    client: httpx.Client | None = None,
) -> frozenset[str]:
    """Fetch the CISA KEV catalog, returning an empty set on failure."""
    owns_client = client is None
    http = client or httpx.Client(timeout=_DEFAULT_TIMEOUT_S)
    try:
        response = http.get(
            KEV_CATALOG_URL,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        return _parse_catalog(response.json())
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        _LOG.warning("CISA KEV lookup failed; using no KEV matches: %s", exc)
        return frozenset()
    finally:
        if owns_client:
            http.close()


def kev_lookup(
    cve: str,
    *,
    client: httpx.Client | None = None,
    catalog: Set[str] | None = None,
) -> bool:
    """Return whether a CVE is in CISA KEV; failures safely return ``False``."""
    normalized = cve.strip().upper()
    if not normalized:
        return False
    resolved_catalog = catalog if catalog is not None else fetch_kev_catalog(client=client)
    return normalized in resolved_catalog


def enrich_with_kev(
    records: Iterable[CveRecord],
    *,
    client: httpx.Client | None = None,
) -> list[CveRecord]:
    """Return CVE record copies marked from one CISA catalog download."""
    source = list(records)
    if not source:
        return []
    catalog = fetch_kev_catalog(client=client)
    return [
        replace(record, kev=record.cve.strip().upper() in catalog)
        for record in source
    ]
