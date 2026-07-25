"""SQLite-backed embedded component CVE queries."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ai_firmware_agent.cve_db.mock import CveRecord
from ai_firmware_agent.cve_db.version import VersionRange, matches_version, parse_cpe
from ai_firmware_agent.normalizer import Component

if TYPE_CHECKING:
    import httpx

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PACKAGE_DIR / "data" / "cve_cache.db"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"
DB_PATH_ENV = "AI_FIRMWARE_CVE_DB"


def default_db_path() -> Path:
    """Return the cache location, overridable for containers and tests.

    Writing inside the installed package is not always possible, so
    ``AI_FIRMWARE_CVE_DB`` takes precedence when set.
    """
    override = os.getenv(DB_PATH_ENV, "").strip()
    return Path(override) if override else DEFAULT_DB_PATH

# Bumped whenever schema.sql changes shape. The database is a regenerable
# cache, so a stale layout is rebuilt rather than migrated in place.
SCHEMA_VERSION = 2


@dataclass(frozen=True)
class CVEEntry:
    cve_id: str
    cpe_id: str
    cvss_v3: float | None
    description: str
    in_known_exploited: bool
    synced_at: str
    product: str | None = None
    version_range: VersionRange | None = None


def _like_fragment(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _row_range(row: sqlite3.Row) -> VersionRange | None:
    version_range = VersionRange(
        start_including=row["version_start_including"],
        start_excluding=row["version_start_excluding"],
        end_including=row["version_end_including"],
        end_excluding=row["version_end_excluding"],
    )
    return version_range if version_range.is_bounded else None


def _row_matches(row: sqlite3.Row, product: str, version: str) -> bool:
    parsed = parse_cpe(str(row["cpe_id"]))
    stored_product = row["product"] or (parsed.product if parsed else None)
    if stored_product is None or stored_product.strip().lower() != product:
        return False
    cpe_version = parsed.version if parsed else ""
    return matches_version(cpe_version, version, _row_range(row))


class EmbeddedCVEDatabase:
    """Small local CVE cache for frequently embedded components."""

    def __init__(self, db_path: Path | None = None):
        self._db = Path(db_path) if db_path is not None else default_db_path()
        self._initialized = False

    @property
    def path(self) -> Path:
        return self._db

    def _initialize_sync(self) -> None:
        self._db.parent.mkdir(parents=True, exist_ok=True)
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with closing(sqlite3.connect(self._db)) as connection, connection:
            stored = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if stored != SCHEMA_VERSION:
                # Databases written before user_version was tracked report 0
                # and still carry the old single-column primary key, so any
                # mismatch rebuilds. Dropping is a no-op on a fresh file.
                connection.execute("DROP TABLE IF EXISTS cve_entries")
            connection.executescript(schema)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION:d}")
        self._initialized = True

    def _ensure_initialized(self) -> None:
        """Create the schema once per instance, not once per query."""
        if not self._initialized:
            self._initialize_sync()

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def lookup_sync(self, component: str, version: str) -> list[CVEEntry]:
        """Blocking lookup used by synchronous callers such as the CLI."""
        if not component.strip() or not version.strip():
            return []
        self._ensure_initialized()
        product = component.strip().lower()
        wanted = version.strip()
        with closing(sqlite3.connect(self._db)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT cve_id, cpe_id, cvss_v3, description,
                       in_known_exploited, synced_at, product,
                       version_start_including, version_start_excluding,
                       version_end_including, version_end_excluding
                FROM cve_entries
                WHERE product = ?
                   OR (product IS NULL AND lower(cpe_id) LIKE ? ESCAPE '\\')
                ORDER BY cve_id, cpe_id
                """,
                (product, f"%:{_like_fragment(component)}:%"),
            ).fetchall()

        # A CVE can now legitimately hold several CPE rows, so collapse to the
        # first matching row per CVE and keep the caller's existing contract
        # of one entry per vulnerability.
        entries: dict[str, CVEEntry] = {}
        for row in rows:
            cve_id = str(row["cve_id"])
            if cve_id in entries or not _row_matches(row, product, wanted):
                continue
            entries[cve_id] = CVEEntry(
                cve_id=cve_id,
                cpe_id=str(row["cpe_id"]),
                cvss_v3=(
                    float(row["cvss_v3"])
                    if row["cvss_v3"] is not None
                    else None
                ),
                description=str(row["description"] or ""),
                in_known_exploited=bool(row["in_known_exploited"]),
                synced_at=str(row["synced_at"]),
                product=row["product"],
                version_range=_row_range(row),
            )
        return list(entries.values())

    async def lookup(self, component: str, version: str) -> list[CVEEntry]:
        """Look up a component version against literal and ranged CPE records."""
        if not component.strip() or not version.strip():
            return []
        return await asyncio.to_thread(self.lookup_sync, component, version)

    def _stats_sync(self) -> dict[str, int]:
        self._ensure_initialized()
        with closing(sqlite3.connect(self._db)) as connection:
            rows, cves, products = connection.execute(
                """
                SELECT COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT product)
                FROM cve_entries
                """
            ).fetchone()
        return {"rows": int(rows), "cves": int(cves), "products": int(products)}

    async def stats(self) -> dict[str, int]:
        """Return row, CVE and product counts for operator-facing output."""
        return await asyncio.to_thread(self._stats_sync)

    async def sync(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        sleep: Any = asyncio.sleep,
    ) -> int:
        """Download and upsert NVD records through the sync backend."""
        from ai_firmware_agent.cve_db.sync import sync_database

        return await sync_database(self, client=client, sleep=sleep)


def local_db_lookup(
    database: EmbeddedCVEDatabase | None = None,
    *,
    db_path: Path | None = None,
) -> Callable[[Component], list[CveRecord]]:
    """Adapt the embedded database to the analyzer's lookup callable.

    This is the bridge that puts the offline SQLite cache onto the same
    scan pipeline the NVD and mock providers already use.
    """
    resolved = database or EmbeddedCVEDatabase(db_path)

    def lookup(component: Component) -> list[CveRecord]:
        return [
            CveRecord(
                cve=entry.cve_id,
                cvss=entry.cvss_v3 or 0.0,
                summary=entry.description,
                kev=entry.in_known_exploited,
            )
            for entry in resolved.lookup_sync(component.name, component.version)
        ]

    return lookup
