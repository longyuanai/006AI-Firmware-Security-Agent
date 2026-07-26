"""CLI: `firmware-agent scan --input FILE --output FILE`.

Supports two input modes:
  - .bin file extracted by binwalk / unsquashfs
  - .tar.gz file containing manifest.yml (legacy PoC path)
  - --demo flag: build a tiny synthetic firmware in-memory (zero-config)
"""

from __future__ import annotations

import asyncio
import os
import json
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

import click
from click.core import ParameterSource
from rich.console import Console

from ai_firmware_agent import __version__
from ai_firmware_agent.analyzer import (
    ComponentMatch,
    enrich_top_components,
    match_components,
    score_and_rank_matches,
)
from ai_firmware_agent.eps import enrich_with_epss
from ai_firmware_agent.charts import render_vulnerability_pie
from ai_firmware_agent.cve_db import CveRecord, EmbeddedCVEDatabase, local_db_lookup, mock_lookup
from ai_firmware_agent.cve_db.sync import sync_database
from ai_firmware_agent.kev import enrich_with_kev
from ai_firmware_agent.gateway_envelope import (
    components_from_payload,
    scan_payload_to_envelope,
)
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.nvd import NvdClient
from ai_firmware_agent.parsers import make_demo_firmware, parse_firmware_file
from ai_firmware_agent.reporter import render_markdown
from ai_firmware_agent.sbom import write_cyclonedx_bom
from ai_firmware_agent.unpack import FirmwareUnpackError, unpack_firmware

console = Console()

CVE_SOURCES = ("nvd", "local", "mock")


@contextmanager
def _lookup_provider(
    source: str,
    *,
    nvd_api_key: str | None,
    db_path: Path | None = None,
) -> Iterator[Callable[[Component], list[CveRecord]]]:
    """Resolve ``--cve-source`` to a lookup callable for one whole scan.

    The NVD provider is scoped rather than per-component so that pacing,
    caching and the HTTP connection are shared across the inventory.
    """
    if source == "local":
        yield local_db_lookup(db_path=db_path)
        return
    if source == "mock":
        yield mock_lookup
        return
    with NvdClient(api_key=nvd_api_key) as nvd:
        yield nvd.lookup


def _reenrich(
    matches: list[ComponentMatch],
    enricher: Callable[[Iterable[CveRecord]], list[CveRecord]],
) -> list[ComponentMatch]:
    """Apply one batched CVE enricher across every match, preserving order."""
    enriched = {
        record.cve: record
        for record in enricher(
            record for match in matches for record in match.cves
        )
    }
    return [
        ComponentMatch(
            component=match.component,
            cves=[enriched.get(record.cve, record) for record in match.cves],
        )
        for match in matches
    ]


def _sbom_vulnerabilities(
    components: list[Component],
    cve_source: str,
    nvd_api_key: str | None,
) -> list[tuple[Component, CveRecord]]:
    """Resolve CVEs for every inventoried component, for the VEX section.

    SBOM export walks the whole inventory, and the NVD provider issues one
    request per component, so an unattended default would mean hundreds of
    rate-limited requests. Unless --cve-source was given explicitly, this
    stays on the offline providers.
    """
    context = click.get_current_context(silent=True)
    explicit = (
        context is not None
        and context.get_parameter_source("cve_source")
        is not ParameterSource.DEFAULT
    )
    source = cve_source if explicit else "mock"
    with _lookup_provider(source, nvd_api_key=nvd_api_key) as lookup:
        return [
            (component, record)
            for component in components
            for record in lookup(component)
        ]


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-Firmware-Security-Agent: firmware SBOM + CVE analyzer."""


@cli.group("cve-db")
def cve_db() -> None:
    """Manage the offline embedded-component CVE cache."""


@cve_db.command("sync")
@click.option(
    "--component",
    "components",
    multiple=True,
    help="Sync only these components (default: the embedded component list).",
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Cache location (or set AI_FIRMWARE_CVE_DB).",
)
@click.option(
    "--nvd-api-key",
    envvar="NVD_API_KEY",
    help="NVD API key (or set NVD_API_KEY). Raises the sync rate limit.",
)
def cve_db_sync(
    components: tuple[str, ...],
    db_path: Path | None,
    nvd_api_key: str | None,
) -> None:
    """Download NVD records into the local SQLite cache."""
    if nvd_api_key:
        os.environ["NVD_API_KEY"] = nvd_api_key
    database = EmbeddedCVEDatabase(db_path)
    console.print(f"[bold]Syncing[/bold] CVE cache at {database.path} ...")
    written = asyncio.run(
        sync_database(database, components=list(components) or None)
    )
    stats = asyncio.run(database.stats())
    console.print(f"  [green]{written}[/green] rows written")
    console.print(
        f"  cache now holds [green]{stats['cves']}[/green] CVEs "
        f"across [green]{stats['products']}[/green] products "
        f"({stats['rows']} rows)"
    )


@cve_db.command("status")
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Cache location (or set AI_FIRMWARE_CVE_DB).",
)
def cve_db_status(db_path: Path | None) -> None:
    """Report what the local CVE cache currently contains."""
    database = EmbeddedCVEDatabase(db_path)
    stats = asyncio.run(database.stats())
    console.print(f"Database: {database.path}")
    console.print(f"CVEs:     {stats['cves']}")
    console.print(f"Products: {stats['products']}")
    console.print(f"Rows:     {stats['rows']}")
    if not stats["rows"]:
        console.print(
            "[yellow]Cache is empty; run "
            "`firmware-agent cve-db sync` first.[/yellow]"
        )


@cli.command()
@click.option("--input", "-i", "input_path", type=str)
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Read an adapter JSON payload and emit a Finding envelope.",
)
@click.option(
    "--sbom",
    "sbom_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write a CycloneDX 1.5 JSON SBOM and skip LLM analysis.",
)
@click.option(
    "--cve-source",
    type=click.Choice(CVE_SOURCES),
    default="nvd",
    show_default=True,
    help="CVE provider: NVD API, the offline local cache, or bundled mock data.",
)
@click.option("--top-n", default=3, show_default=True, type=int)
@click.option("--provider", "-p", default="local", show_default=True)
@click.option("--demo", is_flag=True, help="Use a built-in synthetic firmware instead of --input.")
@click.option(
    "--nvd-api-key",
    envvar="NVD_API_KEY",
    help="NVD API key (or set NVD_API_KEY). The value is never written to reports.",
)
@click.option("--use-epss", is_flag=True, help="Enrich matched CVEs with FIRST EPSS scores.")
@click.option("--use-kev", is_flag=True, help="Mark CVEs found in the CISA KEV catalog.")
def scan(
    input_path: str | None,
    output_path: str,
    json_output: bool,
    sbom_path: Path | None,
    cve_source: str,
    top_n: int,
    provider: str,
    demo: bool,
    nvd_api_key: str | None,
    use_epss: bool,
    use_kev: bool,
) -> None:
    """Scan a .bin or manifest archive (or demo) and emit Markdown."""
    from shared_llm_core.router import LLMRouter

    raw_payload = input_path or ""
    if (json_output or sbom_path is not None) and input_path is None:
        raw_payload = sys.stdin.read()
    if sbom_path is not None:
        if not raw_payload:
            raise click.UsageError("Provide --input for SBOM export.")
        if not raw_payload.lstrip().startswith("{"):
            raw_payload = json.dumps(
                {"firmware_path": str(Path(raw_payload).resolve())}
            )
        components, sbom_errors = components_from_payload(raw_payload)
        if sbom_errors:
            for warning in sbom_errors:
                click.echo(f"[006-firmware] WARNING: {warning}", err=True)
            if json_output:
                click.echo(
                    json.dumps(
                        {
                            "findings": [],
                            "errors": sbom_errors,
                            "summary": {
                                "component_count": 0,
                                "finding_count": 0,
                                "status": "warning",
                            },
                        },
                        ensure_ascii=True,
                    )
                )
                return
            raise click.ClickException("SBOM inventory extraction failed")
        written = write_cyclonedx_bom(
            components,
            sbom_path,
            _sbom_vulnerabilities(components, cve_source, nvd_api_key),
        )
        click.echo(
            f"Wrote CycloneDX SBOM: {written}",
            err=json_output,
        )
        if not json_output:
            return
        input_path = raw_payload

    if json_output:
        raw_payload = input_path if input_path is not None else raw_payload
        envelope = scan_payload_to_envelope(raw_payload)
        for warning in envelope.get("errors", ()):
            if warning.startswith(("GatewayPayloadError:", "FileNotFoundError:")):
                click.echo(f"[006-firmware] WARNING: {warning}", err=True)
        # The shared adapter always decodes stdout as UTF-8. Escaping non-ASCII
        # keeps the byte stream portable even when Windows selects a legacy
        # console encoding for the subprocess pipe.
        click.echo(json.dumps(envelope, ensure_ascii=True))
        return

    if not demo and not input_path:
        raise click.UsageError("Provide --input FILE or pass --demo.")
    if input_path and not Path(input_path).is_file():
        raise click.BadParameter(
            f"Path does not exist: {input_path}",
            param_hint="--input",
        )

    os.environ.setdefault("LLM_PROVIDERS", provider)

    if demo:
        console.print("[bold]Building[/bold] synthetic demo firmware ...")
        from ai_firmware_agent.parsers import parse_firmware
        from io import BytesIO

        components = [
            Component(name="busybox", version="1.36.1", vendor="busybox.net", category="userspace"),
            Component(name="openssl", version="1.1.0", vendor="openssl.org", category="crypto"),
            Component(name="openssh", version="7.4p1", vendor="openssh.com", category="remote_access"),
            Component(name="xz", version="5.6.0", vendor="tukaani.org", category="compression"),
            Component(name="lighttpd", version="1.4.50", vendor="lighttpd.net", category="web_server"),
            Component(name="dropbear", version="2020.80", vendor="matt.ucc.asn.au", category="remote_access"),
            Component(name="kernel", version="5.10.0", vendor="linux.org", category="os"),
        ]
        blob = make_demo_firmware(components)
        parsed = parse_firmware(BytesIO(blob))
        source = "<demo>"
    else:
        console.print(f"[bold]Parsing[/bold] {input_path} ...")
        try:
            if Path(input_path).suffix.lower() == ".bin":  # type: ignore[arg-type]
                parsed = unpack_firmware(input_path)  # type: ignore[arg-type]
            else:
                parsed = parse_firmware_file(input_path)  # type: ignore[arg-type]
        except FirmwareUnpackError as exc:
            raise click.ClickException(str(exc)) from exc
        source = input_path or "<unknown>"

    console.print(f"  [green]{len(parsed)}[/green] components inventoried")

    if not parsed:
        console.print("[yellow]No components parsed; nothing to do.[/yellow]")
        return

    sources = {
        "nvd": "NVD CVE database",
        "local": "local embedded CVE cache",
        "mock": "bundled mock CVE data",
    }
    console.print(f"[bold]Matching[/bold] {sources[cve_source]} ...")
    with _lookup_provider(cve_source, nvd_api_key=nvd_api_key) as lookup:
        matches = match_components(parsed, lookup_fn=lookup)
    console.print(f"  [green]{len(matches)}[/green] vulnerable components")
    if cve_source == "local" and not matches:
        console.print(
            "[yellow]Local cache returned no matches; run "
            "`firmware-agent cve-db sync` to populate it.[/yellow]"
        )

    if use_epss and matches:
        console.print("[bold]Enriching[/bold] CVEs with FIRST EPSS ...")
        matches = _reenrich(matches, enrich_with_epss)

    if use_kev and matches:
        console.print("[bold]Checking[/bold] CISA Known Exploited Vulnerabilities ...")
        matches = _reenrich(matches, enrich_with_kev)

    scores = score_and_rank_matches(matches)
    matches = [item.component for item in scores]
    if scores:
        console.print(f"  [green]Highest PRisk: {scores[0].score:.3f}[/green]")

    console.print(f"[bold]Enriching top {top_n}[/bold] via shared-llm-core ...")
    with LLMRouter.from_env() as router:
        narratives = enrich_top_components(matches, router, top_n=top_n)

    chart_reference = ""
    if output_path != "-":
        report_path = Path(output_path)
        chart_path = report_path.with_name(
            f"{report_path.stem}-vulnerability-distribution.png"
        )
        rendered_chart = render_vulnerability_pie(matches, chart_path)
        if rendered_chart is not None:
            chart_reference = rendered_chart.name
            console.print(f"[green]Wrote[/green] {rendered_chart}")

    report = render_markdown(
        parsed,
        matches,
        narratives,
        source_path=source,
        chart_path=chart_reference,
    )
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


def main() -> None:
    if "--json" in sys.argv[1:] and (
        len(sys.argv) == 1 or sys.argv[1].startswith("-")
    ):
        sys.argv.insert(1, "scan")
    cli()


if __name__ == "__main__":
    main()
