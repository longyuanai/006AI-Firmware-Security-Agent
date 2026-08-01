"""Static contract tests for container packaging."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
PYTHON_BASE = (
    "python:3.11-slim@sha256:"
    "db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93"
)


def test_dockerfile_uses_slim_runtime_and_non_root_user():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert f"FROM {PYTHON_BASE} AS runtime" in dockerfile
    assert "USER firmware" in dockerfile
    assert "ENTRYPOINT [\"firmware-agent\"]" in dockerfile


def test_dockerfile_pins_both_stages_to_one_immutable_digest():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count(f"FROM {PYTHON_BASE}") == 2
    assert "FROM python:3.11-slim AS" not in dockerfile


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


def test_static_worker_has_no_network_or_privilege_escalation():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["firmware-agent"]
    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["user"] == "10001:10001"
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]


def test_static_worker_limits_resources_and_uses_bounded_tmpfs():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["firmware-agent"]
    assert service["pids_limit"] == 256
    assert service["mem_limit"] == "1g"
    assert service["cpus"] == 2.0
    assert service["tmpfs"] == ["/tmp:rw,noexec,nosuid,nodev,size=256m"]


def test_static_worker_only_mounts_firmware_read_only_and_output_writable():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    volumes = compose["services"]["firmware-agent"]["volumes"]
    assert volumes == ["./samples:/firmware:ro", "./output:/output"]


def test_dockerignore_excludes_secrets_git_and_test_artifacts():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".git" in ignored
    assert ".env" in ignored
    assert ".test-deps" in ignored
    assert "tests" in ignored
