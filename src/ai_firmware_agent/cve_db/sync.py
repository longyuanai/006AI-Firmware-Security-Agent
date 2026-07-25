"""NVD synchronization for the embedded SQLite CVE cache."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import closing
from dataclasses import astuple, dataclass
from pathlib import Path
from typing import Any

import httpx

from ai_firmware_agent.cve_db.query import PACKAGE_DIR, EmbeddedCVEDatabase
from ai_firmware_agent.cve_db.version import parse_cpe

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COMPONENTS_PATH = PACKAGE_DIR / "embedded_components.json"

# NVD caps resultsPerPage at 2000; MAX_PAGES bounds a single component sync so
# a surprising totalResults cannot turn into an unbounded request loop.
PAGE_SIZE = 2000
MAX_PAGES = 20

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SyncRecord:
    """One (CVE, CPE) pair as stored by :func:`_upsert`.

    Field order matches the INSERT column order.
    """

    cve_id: str
    cpe_id: str
    cvss_v3: float | None
    description: str
    in_known_exploited: bool
    product: str | None
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None


def _component_names(path: Path = COMPONENTS_PATH) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("components", [])
    return [
        str(item["name"]).strip().lower()
        for item in items
        if isinstance(item, Mapping) and str(item.get("name", "")).strip()
    ]


def _description(cve: Mapping[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, Mapping) and item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _cvss(cve: Mapping[str, Any]) -> float | None:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, Mapping):
        return None
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(name, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, Mapping):
                continue
            data = value.get("cvssData", {})
            if not isinstance(data, Mapping):
                continue
            try:
                return float(data["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def _cpe_matches(value: Any) -> list[Mapping[str, Any]]:
    """Collect every vulnerable ``cpeMatch`` object, at any nesting depth."""
    matches: list[Mapping[str, Any]] = []
    if isinstance(value, Mapping):
        entries = value.get("cpeMatch", [])
        if isinstance(entries, list):
            for entry in entries:
                if (
                    isinstance(entry, Mapping)
                    and entry.get("vulnerable", True)
                    and isinstance(entry.get("criteria"), str)
                ):
                    matches.append(entry)
        for child_name in ("nodes", "children"):
            matches.extend(_cpe_matches(value.get(child_name, [])))
    elif isinstance(value, list):
        for item in value:
            matches.extend(_cpe_matches(item))
    return matches


def _optional_text(match: Mapping[str, Any], key: str) -> str | None:
    value = match.get(key)
    return str(value) if isinstance(value, str) and value.strip() else None


def _is_component(criteria: str, component: str) -> tuple[bool, str | None]:
    """Return whether a CPE names ``component``, plus its parsed product."""
    parsed = parse_cpe(criteria)
    if parsed is not None:
        return parsed.product == component, parsed.product
    return f":{component}:" in criteria.lower(), None


def _records(payload: Any, component: str) -> list[SyncRecord]:
    if not isinstance(payload, Mapping):
        raise ValueError("NVD response must be an object")
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD vulnerabilities must be a list")

    records: list[SyncRecord] = []
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue
        cve_id = str(cve.get("id", "")).strip().upper()
        if not cve_id:
            continue
        cvss = _cvss(cve)
        description = _description(cve)
        exploited = bool(cve.get("cisaExploitAdd") or cve.get("cisaActionDue"))
        for match in _cpe_matches(cve.get("configurations", [])):
            criteria = str(match["criteria"])
            belongs, product = _is_component(criteria, component)
            if not belongs:
                continue
            records.append(
                SyncRecord(
                    cve_id=cve_id,
                    cpe_id=criteria,
                    cvss_v3=cvss,
                    description=description,
                    in_known_exploited=exploited,
                    product=product,
                    version_start_including=_optional_text(
                        match, "versionStartIncluding"
                    ),
                    version_start_excluding=_optional_text(
                        match, "versionStartExcluding"
                    ),
                    version_end_including=_optional_text(
                        match, "versionEndIncluding"
                    ),
                    version_end_excluding=_optional_text(
                        match, "versionEndExcluding"
                    ),
                )
            )
    return records


def _upsert(db_path: Path, records: Iterable[SyncRecord]) -> int:
    """Write records and return how many rows the database actually changed."""
    rows = [astuple(record) for record in records]
    if not rows:
        return 0
    with closing(sqlite3.connect(db_path)) as connection, connection:
        before = connection.total_changes
        connection.executemany(
            """
            INSERT INTO cve_entries
                (cve_id, cpe_id, cvss_v3, description, in_known_exploited,
                 product, version_start_including, version_start_excluding,
                 version_end_including, version_end_excluding, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id, cpe_id) DO UPDATE SET
                cvss_v3 = excluded.cvss_v3,
                description = excluded.description,
                in_known_exploited = excluded.in_known_exploited,
                product = excluded.product,
                version_start_including = excluded.version_start_including,
                version_start_excluding = excluded.version_start_excluding,
                version_end_including = excluded.version_end_including,
                version_end_excluding = excluded.version_end_excluding,
                synced_at = CURRENT_TIMESTAMP
            """,
            rows,
        )
        return connection.total_changes - before


async def _sync_component(
    client: httpx.AsyncClient,
    db_path: Path,
    component: str,
    *,
    headers: Mapping[str, str],
    sleep: Callable[[float], Awaitable[None]],
    delay: float,
) -> int:
    """Page through one component's CVEs, failing open on any API error."""
    written = 0
    start_index = 0
    for page in range(MAX_PAGES):
        if page:
            await sleep(delay)
        try:
            response = await client.get(
                NVD_CVE_API,
                params={
                    "keywordSearch": component,
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex": start_index,
                },
                headers=dict(headers),
            )
            response.raise_for_status()
            payload = response.json()
            records = _records(payload, component)
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            _LOG.warning("NVD sync failed for %s: %s", component, exc)
            return written
        written += await asyncio.to_thread(_upsert, db_path, records)

        total = payload.get("totalResults") if isinstance(payload, Mapping) else None
        start_index += PAGE_SIZE
        if not isinstance(total, int) or start_index >= total:
            return written
    _LOG.warning("NVD sync for %s stopped at the %d page cap", component, MAX_PAGES)
    return written


async def sync_database(
    database: EmbeddedCVEDatabase,
    *,
    client: httpx.AsyncClient | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    components: Iterable[str] | None = None,
) -> int:
    """Fetch NVD CVEs with API-key-aware rate limiting and fail-open errors."""
    await database.initialize()
    names = list(components) if components is not None else _component_names()
    api_key = os.getenv("NVD_API_KEY")
    limit = 50 if api_key else 5
    delay = 30.0 / limit
    headers = {"User-Agent": "ai-firmware-security-agent/0.7"}
    if api_key:
        headers["apiKey"] = api_key

    owns_client = client is None
    active = client or httpx.AsyncClient(timeout=30.0)
    written = 0
    try:
        for index, component in enumerate(names):
            if index:
                await sleep(delay)
            written += await _sync_component(
                active,
                database.path,
                component,
                headers=headers,
                sleep=sleep,
                delay=delay,
            )
    finally:
        if owns_client:
            await active.aclose()
    return written
