"""Docker/QEMU emulation tests use an injected runner and never execute QEMU."""

from __future__ import annotations

import subprocess

import pytest

from ai_firmware_agent.emulator import (
    EmulationError,
    build_docker_command,
    emulate_firmware,
)
from ai_firmware_agent.v05_compat import FindingSource, is_uuid4


def _rootfs(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    return root


def _completed(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_mipsel_command_is_hardened_and_read_only(tmp_path):
    command = build_docker_command(_rootfs(tmp_path), architecture="mipsel")
    rendered = " ".join(command)
    assert "qemu-mipsel-static" in command[-1]
    assert "--network none" in rendered
    assert "--cap-drop ALL" in rendered
    assert "--read-only" in command
    assert ":/firmware:ro" in rendered


def test_arm_command_uses_qemu_arm_and_selected_init(tmp_path):
    command = build_docker_command(
        _rootfs(tmp_path),
        architecture="arm",
        init_script="/etc/preinit",
    )
    assert "qemu-arm-static" in command[-1]
    assert "/firmware/etc/preinit" in command[-1]


def test_emulation_parses_processes_ports_and_finding(tmp_path):
    stdout = """__AFSA_PROCESSES__
1 qemu-mipsel-static qemu-mipsel-static /firmware/bin/sh
14 httpd /usr/sbin/httpd -f
__AFSA_PORTS__
tcp|0.0.0.0:80
udp|[::]:53
__AFSA_INIT_STATUS__0
"""

    result = emulate_firmware(
        _rootfs(tmp_path),
        architecture="mipsel",
        runner=lambda *args, **kwargs: _completed(stdout),
    )

    assert [process.command for process in result.processes] == [
        "qemu-mipsel-static",
        "httpd",
    ]
    assert [(port.protocol, port.port) for port in result.listening_ports] == [
        ("tcp", 80),
        ("udp", 53),
    ]
    finding = result.findings[0]
    assert finding.source == FindingSource.FIRMWARE
    assert finding.metadata["listening_port_count"] == 2
    assert is_uuid4(finding.id)


def test_emulation_without_ports_emits_info_finding(tmp_path):
    stdout = """__AFSA_PROCESSES__
2 init /sbin/init
__AFSA_PORTS__
__AFSA_INIT_STATUS__0
"""
    result = emulate_firmware(
        _rootfs(tmp_path),
        architecture="arm",
        runner=lambda *args, **kwargs: _completed(stdout),
    )
    assert result.listening_ports == ()
    assert result.findings[0].severity.value == "info"


def test_command_rejects_unsupported_architecture(tmp_path):
    with pytest.raises(ValueError, match="Unsupported architecture"):
        build_docker_command(_rootfs(tmp_path), architecture="x86")


def test_command_rejects_path_traversal_in_init_script(tmp_path):
    with pytest.raises(ValueError, match="init_script"):
        build_docker_command(
            _rootfs(tmp_path),
            architecture="arm",
            init_script="/etc/../host-script",
        )


def test_emulation_wraps_docker_failure(tmp_path):
    with pytest.raises(EmulationError, match="status 125"):
        emulate_firmware(
            _rootfs(tmp_path),
            architecture="mipsel",
            runner=lambda *args, **kwargs: _completed(
                "",
                returncode=125,
                stderr="image missing",
            ),
        )
