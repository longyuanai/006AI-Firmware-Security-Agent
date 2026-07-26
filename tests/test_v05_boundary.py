"""Every firmware Finding is built through the one v05_compat boundary.

scanner.py and adapter.py used to import shared_llm_core.finding directly,
so the product had two Finding identities depending on which module built
the object, and both passed id="" instead of a generated identifier.
"""

from __future__ import annotations

import ast
import asyncio
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import ai_firmware_agent
from ai_firmware_agent import v05_compat
from ai_firmware_agent.cve_db import EmbeddedCVEDatabase
from ai_firmware_agent.scanner import FirmwareScanner

SRC = Path(__file__).parents[1] / "src" / "ai_firmware_agent"

# adapter.py legitimately needs the section 10 gateway base class; nothing
# else in the product may reach into shared_llm_core on its own.
ALLOWED_DIRECT_IMPORTS = {
    "adapter.py": {"shared_llm_core.gateway"},
    "analyzer.py": {"shared_llm_core", "shared_llm_core.router"},
    "cli.py": {"shared_llm_core.router"},
    "v05_compat.py": {"shared_llm_core", "shared_llm_core.finding"},
}


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return {name for name in modules if name.split(".")[0] == "shared_llm_core"}


@pytest.mark.parametrize(
    "source",
    sorted(SRC.rglob("*.py")),
    ids=lambda path: str(path.name),
)
def test_shared_types_are_reached_through_the_compat_boundary(source):
    allowed = ALLOWED_DIRECT_IMPORTS.get(source.name, set())
    assert _imported_modules(source) <= allowed, (
        f"{source.name} imports shared_llm_core directly; "
        "use ai_firmware_agent.v05_compat instead"
    )


class _UnavailableRunner:
    async def is_available(self) -> bool:
        return False


def _database(tmp_path):
    database = EmbeddedCVEDatabase(tmp_path / "cache.db")
    asyncio.run(database.initialize())
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            """
            INSERT INTO cve_entries
                (cve_id, cpe_id, cvss_v3, description, in_known_exploited,
                 product)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "CVE-2025-6006",
                "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
                9.4,
                "fixture",
                0,
                "busybox",
            ),
        )
    return database


def test_scanner_findings_carry_a_generated_id(tmp_path):
    """Findings used to be built with id="" and relied on the shared type."""
    sample = Path(__file__).parent / "fixtures" / "sample.bin"
    result = asyncio.run(
        FirmwareScanner(_UnavailableRunner(), _database(tmp_path)).scan(sample)
    )
    assert result.findings
    assert v05_compat.is_uuid4(result.findings[0].id)


def test_adapter_findings_carry_a_generated_id():
    async def collect():
        return [
            finding
            async for finding in ai_firmware_agent.FirmwareProductAdapter().scan(
                {"firmware_path": "router.bin"}
            )
        ]

    finding = asyncio.run(collect())[0]
    assert v05_compat.is_uuid4(finding.id)


def test_importing_the_package_does_not_pull_in_the_gateway_layer():
    """The section 10 adapter must stay off the package import path."""
    probe = (
        "import sys; import ai_firmware_agent; "
        "assert 'ai_firmware_agent.adapter' not in sys.modules, 'adapter imported eagerly'; "
        "assert ai_firmware_agent.FirmwareProductAdapter.__name__ == 'FirmwareProductAdapter'; "
        "assert 'ai_firmware_agent.adapter' in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_the_product_version_has_a_single_source():
    """User-Agent strings and the SBOM tool block used to drift apart."""
    import tomllib

    from ai_firmware_agent._version import USER_AGENT, __version__

    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert pyproject["tool"]["poetry"]["version"] == __version__
    assert USER_AGENT.endswith(__version__)
    assert ai_firmware_agent.__version__ == __version__

    hardcoded = [
        source.name
        for source in SRC.rglob("*.py")
        if "ai-firmware-security-agent/" in source.read_text(encoding="utf-8")
        and source.name != "_version.py"
    ]
    assert hardcoded == [], f"hardcoded user agent in {hardcoded}"
