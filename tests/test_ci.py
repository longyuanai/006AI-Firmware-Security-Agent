"""Static contract tests for the Windows/Linux GitHub Actions workflow."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_ci_runs_on_windows_and_linux():
    matrix = _workflow()["jobs"]["quality"]["strategy"]["matrix"]
    assert set(matrix["os"]) == {"ubuntu-latest", "windows-latest"}
    assert matrix["python-version"] == ["3.11"]


def test_ci_checks_out_shared_core_as_a_sibling():
    steps = _workflow()["jobs"]["quality"]["steps"]
    shared = next(step for step in steps if step["name"] == "Check out shared LLM core")
    assert shared["with"]["repository"].endswith("/000shared-llm-core")
    assert shared["with"]["path"] == "000shared-llm-core"
    assert "SHARED_CORE_TOKEN" in shared["with"]["token"]


def test_ci_runs_lint_type_check_and_pytest():
    runs = "\n".join(
        str(step.get("run", ""))
        for step in _workflow()["jobs"]["quality"]["steps"]
    )
    assert "ruff check src tests" in runs
    assert "mypy" in runs
    assert "pytest --basetemp=.pytest-tmp" in runs


def test_ci_installs_squashfs_tools_on_linux():
    steps = _workflow()["jobs"]["quality"]["steps"]
    install = next(step for step in steps if step["name"] == "Install squashfs tools")
    assert install["if"] == "runner.os == 'Linux'"
    assert "squashfs-tools" in install["run"]


def test_ci_audits_dependencies_on_linux():
    """A security scanner must not ship known-vulnerable dependencies."""
    steps = _workflow()["jobs"]["quality"]["steps"]
    audit = next(
        step for step in steps if step.get("name") == "Audit dependencies"
    )
    assert audit["if"] == "runner.os == 'Linux'"
    assert "pip_audit" in audit["run"]
    assert "--strict" in audit["run"]
