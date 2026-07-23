"""Static contract tests for container packaging."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_dockerfile_uses_slim_runtime_and_non_root_user():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim AS runtime" in dockerfile
    assert "USER firmware" in dockerfile
    assert "ENTRYPOINT [\"firmware-agent\"]" in dockerfile


def test_dockerfile_installs_firmware_extraction_tools():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "binwalk" in dockerfile
    assert "squashfs-tools" in dockerfile
    assert "--no-install-recommends" in dockerfile


def test_compose_uses_shared_context_and_read_only_firmware_mount():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["firmware-agent"]
    assert service["build"]["additional_contexts"]["shared"] == "../000shared-llm-core"
    assert "./samples:/firmware:ro" in service["volumes"]
    assert service["environment"]["NVD_API_KEY"] == "${NVD_API_KEY:-}"


def test_dockerignore_excludes_secrets_git_and_test_artifacts():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".git" in ignored
    assert ".env" in ignored
    assert ".test-deps" in ignored
    assert "tests" in ignored
