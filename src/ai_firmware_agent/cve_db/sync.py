"""NVD synchronization for the embedded SQLite CVE cache."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from collections.abc import Awaitable, Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import httpx

from ai_firmware_agent.cve_db.query import EmbeddedCVEDatabase, PACKAGE_DIR

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COMPONENTS_PATH = PACKAGE_DIR / "embedded_components.json"


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


def _cpe_criteria(value: Any) -> list[str]:
    criteria: list[str] = []
    if isinstance(value, Mapping):
        matches = value.get("cpeMatch", [])
        if isinstance(matches, list):
            for match in matches:
                if (
                    isinstance(match, Mapping)
                    and match.get("vulnerable", True)
                    and isinstance(match.get("criteria"), str)
                ):
                    criteria.append(str(match["criteria"]))
        for child_name in ("nodes", "children"):
            criteria.extend(_cpe_criteria(value.get(child_name, [])))
    elif isinstance(value, list):
        for item in value:
            criteria.extend(_cpe_criteria(item))
    return criteria


def _records(
    payload: Any,
    component: str,
) -> list[tuple[str, str, float | None, str, bool]]:
    if not isinstance(payload, Mapping):
        raise ValueError("NVD response must be an object")
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD vulnerabilities must be a list")
    records: list[tuple[str, str, float | None, str, bool]] = []
    component_marker = f":{component.lower()}:"
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue
        cve_id = str(cve.get("id", "")).strip().upper()
        if not cve_id:
            continue
        criteria = [
            cpe
            for cpe in _cpe_criteria(cve.get("configurations", []))
            if component_marker in cpe.lower()
        ]
        for cpe in criteria:
            records.append(
                (
                    cve_id,
                    cpe,
                    _cvss(cve),
                    _description(cve),
                    bool(
                        cve.get("cisaExploitAdd")
                        or cve.get("cisaActionDue")
                    ),
                )
            )
    return records


def _upsert(
    db_path: Path,
    records: Iterable[tuple[str, str, float | None, str, bool]],
) -> int:
    rows = list(records)
    if not rows:
        return 0
    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            """
            INSERT INTO cve_entries
                (cve_id, cpe_id, cvss_v3, description,
                 in_known_exploited, synced_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id) DO UPDATE SET
                cpe_id = excluded.cpe_id,
                cvss_v3 = excluded.cvss_v3,
                description = excluded.description,
                in_known_exploited = excluded.in_known_exploited,
                synced_at = CURRENT_TIMESTAMP
            """,
            rows,
        )
    return len(rows)


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
            try:
                response = await active.get(
                    NVD_CVE_API,
                    params={
                        "keywordSearch": component,
                        "resultsPerPage": 2000,
                    },
                    headers=headers,
                )
                response.raise_for_status()
                records = _records(response.json(), component)
            except (httpx.HTTPError, TypeError, ValueError):
                continue
            written += await asyncio.to_thread(
                _upsert,
                database.path,
                records,
            )
    finally:
        if owns_client:
            await active.aclose()
    return written
