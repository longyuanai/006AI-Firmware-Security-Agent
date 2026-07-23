"""CLI: `firmware-agent scan --input FILE --output FILE`.

Supports two input modes:
  - .tar.gz file containing manifest.yml (real PoC path)
  - --demo flag: build a tiny synthetic firmware in-memory (zero-config)
"""

from __future__ import annotations

import os
import sys
from functools import partial

import click
from rich.console import Console

from ai_firmware_agent import __version__
from ai_firmware_agent.analyzer import (
    ComponentMatch,
    enrich_top_components,
    match_components,
)
from ai_firmware_agent.eps import enrich_with_epss
from ai_firmware_agent.kev import enrich_with_kev
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.nvd import nvd_lookup
from ai_firmware_agent.parsers import make_demo_firmware, parse_firmware_file
from ai_firmware_agent.reporter import render_markdown

console = Console()


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-Firmware-Security-Agent: firmware SBOM + CVE analyzer."""


@cli.command()
@click.option("--input", "-i", "input_path", type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
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
    top_n: int,
    provider: str,
    demo: bool,
    nvd_api_key: str | None,
    use_epss: bool,
    use_kev: bool,
) -> None:
    """Scan a firmware file (or demo) and emit a Markdown report."""
    from shared_llm_core.router import LLMRouter

    if not demo and not input_path:
        raise click.UsageError("Provide --input FILE or pass --demo.")

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
        parsed = parse_firmware_file(input_path)  # type: ignore[arg-type]
        source = input_path or "<unknown>"

    console.print(f"  [green]{len(parsed)}[/green] components inventoried")

    if not parsed:
        console.print("[yellow]No components parsed; nothing to do.[/yellow]")
        return

    console.print("[bold]Matching[/bold] NVD CVE database ...")
    matches = match_components(parsed, lookup_fn=partial(nvd_lookup, api_key=nvd_api_key))
    console.print(f"  [green]{len(matches)}[/green] vulnerable components")

    if use_epss and matches:
        console.print("[bold]Enriching[/bold] CVEs with FIRST EPSS ...")
        enriched = {
            record.cve: record
            for record in enrich_with_epss(
                record for match in matches for record in match.cves
            )
        }
        matches = [
            ComponentMatch(
                component=match.component,
                cves=[enriched.get(record.cve, record) for record in match.cves],
            )
            for match in matches
        ]

    if use_kev and matches:
        console.print("[bold]Checking[/bold] CISA Known Exploited Vulnerabilities ...")
        enriched = {
            record.cve: record
            for record in enrich_with_kev(
                record for match in matches for record in match.cves
            )
        }
        matches = [
            ComponentMatch(
                component=match.component,
                cves=[enriched.get(record.cve, record) for record in match.cves],
            )
            for match in matches
        ]

    console.print(f"[bold]Enriching top {top_n}[/bold] via shared-llm-core ...")
    with LLMRouter.from_env() as router:
        narratives = enrich_top_components(matches, router, top_n=top_n)

    report = render_markdown(parsed, matches, narratives, source_path=source)
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
