"""Diff report rendering, Markdown and end to end through the CLI."""

from __future__ import annotations

from click.testing import CliRunner

from ai_firmware_agent.cli import cli
from ai_firmware_agent.diff import diff_components
from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.parsers import make_demo_firmware
from ai_firmware_agent.reporter import render_diff_markdown


def _c(name: str, version: str) -> Component:
    return Component(name=name, version=version)


def test_render_diff_markdown_summary_counts():
    diff = diff_components(
        [_c("dropbear", "2020.80"), _c("xz", "5.6.0"), _c("busybox", "1.36.0")],
        [_c("dropbear", "2020.80"), _c("lighttpd", "1.4.50"), _c("busybox", "1.36.1")],
    )
    report = render_diff_markdown(diff, ())
    assert "# Firmware Diff Report" in report
    assert "Added: **1**" in report
    assert "Removed: **1**" in report
    assert "Upgraded: **1**" in report
    assert "Unchanged: **1**" in report


def test_render_diff_markdown_lists_persistent_vulnerabilities():
    from ai_firmware_agent.diff import PersistentVulnerability

    diff = diff_components([], [])
    persistent = (
        PersistentVulnerability(
            component="busybox",
            cve="CVE-2023-39810",
            old_version="1.36.0",
            new_version="1.36.1",
        ),
    )
    report = render_diff_markdown(diff, persistent)
    assert "Vulnerabilities That Survived the Change" in report
    assert "CVE-2023-39810" in report
    assert "| busybox | CVE-2023-39810 | 1.36.0 | 1.36.1 |" in report


def test_render_diff_markdown_without_changes_says_none():
    report = render_diff_markdown(diff_components([], []), ())
    assert report.count("_None._") >= 4


def test_render_diff_markdown_includes_sources():
    report = render_diff_markdown(
        diff_components([], []),
        (),
        old_source="old.bin",
        new_source="new.bin",
    )
    assert "`old.bin`" in report
    assert "`new.bin`" in report


# --- CLI end to end -----------------------------------------------------


def _firmware(tmp_path, name, components):
    path = tmp_path / name
    path.write_bytes(make_demo_firmware(components))
    return path


def test_cli_diff_end_to_end(tmp_path):
    old = _firmware(
        tmp_path,
        "old.tar.gz",
        [
            Component(name="busybox", version="1.36.0"),
            Component(name="dropbear", version="2020.80"),
        ],
    )
    new = _firmware(
        tmp_path,
        "new.tar.gz",
        [
            Component(name="busybox", version="1.36.1"),
            Component(name="lighttpd", version="1.4.50"),
        ],
    )
    output = tmp_path / "diff.md"

    result = CliRunner().invoke(
        cli,
        [
            "diff",
            "--old",
            str(old),
            "--new",
            str(new),
            "--cve-source",
            "mock",
            "-o",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    report = output.read_text(encoding="utf-8")
    assert "# Firmware Diff Report" in report
    assert "lighttpd" in report  # added
    assert "dropbear" in report  # removed
    assert "busybox" in report  # upgraded
    # busybox 1.36.0 -> 1.36.1 is still matched by the mock CVE fixture.
    assert "CVE-2023-39810" in report


def test_cli_diff_defaults_to_mock_cve_source_offline(monkeypatch, tmp_path):
    """Bulk two-inventory lookups must not default to a rate-limited NVD call."""
    import ai_firmware_agent.cli as cli_module

    def fail(*_args, **_kwargs):
        raise AssertionError("diff must stay offline by default")

    monkeypatch.setattr(cli_module, "NvdClient", fail)
    old = _firmware(tmp_path, "old.tar.gz", [Component(name="busybox", version="1.36.0")])
    new = _firmware(tmp_path, "new.tar.gz", [Component(name="busybox", version="1.36.1")])

    result = CliRunner().invoke(cli, ["diff", "--old", str(old), "--new", str(new)])
    assert result.exit_code == 0, result.output


def test_cli_diff_missing_old_file_is_a_clean_error(tmp_path):
    new = _firmware(tmp_path, "new.tar.gz", [Component(name="busybox", version="1.36.1")])
    result = CliRunner().invoke(
        cli,
        ["diff", "--old", str(tmp_path / "missing.bin"), "--new", str(new)],
    )
    assert result.exit_code != 0


def test_cli_diff_help_documents_options():
    result = CliRunner().invoke(cli, ["diff", "--help"])
    assert result.exit_code == 0
    assert "--old" in result.output
    assert "--new" in result.output
    assert "--cve-source" in result.output


def test_cli_diff_stdout_output(tmp_path):
    old = _firmware(tmp_path, "old.tar.gz", [Component(name="busybox", version="1.36.0")])
    new = _firmware(tmp_path, "new.tar.gz", [Component(name="busybox", version="1.36.1")])

    result = CliRunner().invoke(cli, ["diff", "--old", str(old), "--new", str(new)])
    assert result.exit_code == 0, result.output
    assert "# Firmware Diff Report" in result.output


def test_scan_command_still_behaves_identically_after_the_shared_helper_refactor(
    tmp_path, stub_router_factory
):
    """diff.py's addition factored scan's input parsing into a shared helper;
    this pins scan's own behavior unchanged."""
    stub_router_factory({})
    firmware = _firmware(
        tmp_path, "fw.tar.gz", [Component(name="lighttpd", version="1.4.50")]
    )
    output = tmp_path / "report.md"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            str(firmware),
            "--output",
            str(output),
            "--cve-source",
            "mock",
            "--top-n",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert output.read_text(encoding="utf-8").startswith("# Firmware Security Report")
