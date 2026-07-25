"""SQLite-backed embedded component CVE queries."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PACKAGE_DIR / "data" / "cve_cache.db"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"


@dataclass(frozen=True)
class CVEEntry:
    cve_id: str
    cpe_id: str
    cvss_v3: float | None
    description: str
    in_known_exploited: bool
    synced_at: str


def _like_fragment(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class EmbeddedCVEDatabase:
    """Small local CVE cache for frequently embedded components."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self._db = Path(db_path)

    @property
    def path(self) -> Path:
        return self._db

    def _initialize_sync(self) -> None:
        self._db.parent.mkdir(parents=True, exist_ok=True)
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with sqlite3.connect(self._db) as connection:
            connection.executescript(schema)

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _lookup_sync(self, component: str, version: str) -> list[CVEEntry]:
        self._initialize_sync()
        component_pattern = f"%:{_like_fragment(component)}:%"
        version_pattern = f"%:{_like_fragment(version)}:%"
        with sqlite3.connect(self._db) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT cve_id, cpe_id, cvss_v3, description,
                       in_known_exploited, synced_at
                FROM cve_entries
                WHERE lower(cpe_id) LIKE ? ESCAPE '\\'
                  AND lower(cpe_id) LIKE ? ESCAPE '\\'
                ORDER BY cve_id
                """,
                (component_pattern, version_pattern),
            ).fetchall()
        return [
            CVEEntry(
                cve_id=str(row["cve_id"]),
                cpe_id=str(row["cpe_id"]),
                cvss_v3=(
                    float(row["cvss_v3"])
                    if row["cvss_v3"] is not None
                    else None
                ),
                description=str(row["description"] or ""),
                in_known_exploited=bool(row["in_known_exploited"]),
                synced_at=str(row["synced_at"]),
            )
            for row in rows
        ]

    async def lookup(self, component: str, version: str) -> list[CVEEntry]:
        """Look up exact component and version fields inside CPE 2.3 IDs."""
        if not component.strip() or not version.strip():
            return []
        return await asyncio.to_thread(
            self._lookup_sync,
            component,
            version,
        )

    async def sync(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        sleep: Any = asyncio.sleep,
    ) -> int:
        """Download and upsert NVD records through the sync backend."""
        from ai_firmware_agent.cve_db.sync import sync_database

        return await sync_database(self, client=client, sleep=sleep)
