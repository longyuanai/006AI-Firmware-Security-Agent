"""Isolated firmware init emulation through Docker-hosted QEMU user mode."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ai_firmware_agent.v05_compat import Finding, FindingSeverity, new_finding

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
SUPPORTED_ARCHITECTURES = {
    "mipsel": "qemu-mipsel-static",
    "arm": "qemu-arm-static",
}
DEFAULT_EMULATOR_IMAGE = "ai-firmware-emulator:0.5"
_PROCESSES_MARKER = "__AFSA_PROCESSES__"
_PORTS_MARKER = "__AFSA_PORTS__"
_STATUS_MARKER = "__AFSA_INIT_STATUS__"


class EmulationError(RuntimeError):
    """Raised when an isolated emulation job cannot produce valid output."""


@dataclass(frozen=True)
class EmulatedProcess:
    pid: int
    command: str
    args: str = ""


@dataclass(frozen=True)
class ListeningPort:
    protocol: str
    address: str
    port: int


@dataclass(frozen=True)
class EmulationResult:
    architecture: str
    init_script: str
    init_status: int
    processes: tuple[EmulatedProcess, ...]
    listening_ports: tuple[ListeningPort, ...]
    findings: tuple[Finding, ...]


def _validate_init_script(init_script: str) -> str:
    path = PurePosixPath(init_script)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("init_script must be an absolute firmware path without '..'")
    return str(path)


def _emulation_script(
    qemu_binary: str,
    init_script: str,
    *,
    emulation_timeout_s: int,
    settle_s: float,
) -> str:
    shell_path = "/firmware/bin/sh"
    firmware_init = f"/firmware{init_script}"
    command = " ".join(
        shlex.quote(part)
        for part in (
            "timeout",
            f"{emulation_timeout_s}s",
            qemu_binary,
            "-L",
            "/firmware",
            shell_path,
            firmware_init,
        )
    )
    return (
        f"{command} >/tmp/firmware-init.log 2>&1 & "
        "emulator_pid=$!; "
        f"sleep {settle_s:g}; "
        f"printf '{_PROCESSES_MARKER}\\n'; "
        "ps -eo pid=,comm=,args=; "
        f"printf '{_PORTS_MARKER}\\n'; "
        "ss -H -lntu | awk '{print $1 \"|\" $5}'; "
        "wait \"$emulator_pid\"; init_status=$?; "
        f"printf '{_STATUS_MARKER}%s\\n' \"$init_status\"; "
        "exit 0"
    )


def build_docker_command(
    rootfs: str | Path,
    *,
    architecture: str,
    init_script: str = "/etc/init.d/rcS",
    image: str = DEFAULT_EMULATOR_IMAGE,
    emulation_timeout_s: int = 15,
    settle_s: float = 2.0,
) -> list[str]:
    """Build the hardened Docker command without executing it."""
    filesystem = Path(rootfs).resolve(strict=True)
    if not filesystem.is_dir():
        raise ValueError(f"rootfs must be a directory: {filesystem}")
    try:
        qemu_binary = SUPPORTED_ARCHITECTURES[architecture]
    except KeyError as exc:
        supported = ", ".join(sorted(SUPPORTED_ARCHITECTURES))
        raise ValueError(f"Unsupported architecture {architecture!r}; use {supported}") from exc
    safe_init = _validate_init_script(init_script)
    if emulation_timeout_s <= 0 or settle_s < 0:
        raise ValueError("timeouts must be positive")

    script = _emulation_script(
        qemu_binary,
        safe_init,
        emulation_timeout_s=emulation_timeout_s,
        settle_s=settle_s,
    )
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--user",
        "65534:65534",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--volume",
        f"{filesystem}:/firmware:ro",
        image,
        "sh",
        "-lc",
        script,
    ]


def _section(lines: Sequence[str], start: str, end: str) -> list[str]:
    try:
        first = lines.index(start) + 1
    except ValueError as exc:
        raise EmulationError(f"Missing emulation output marker: {start}") from exc
    last = next(
        (index for index in range(first, len(lines)) if lines[index].startswith(end)),
        len(lines),
    )
    return [line.strip() for line in lines[first:last] if line.strip()]


def _parse_processes(lines: Sequence[str]) -> tuple[EmulatedProcess, ...]:
    processes: list[EmulatedProcess] = []
    for line in _section(lines, _PROCESSES_MARKER, _PORTS_MARKER):
        parts = line.split(maxsplit=2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        processes.append(
            EmulatedProcess(
                pid=int(parts[0]),
                command=parts[1],
                args=parts[2] if len(parts) == 3 else "",
            )
        )
    return tuple(processes)


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    endpoint = endpoint.strip()
    if not endpoint or ":" not in endpoint:
        return None
    address, raw_port = endpoint.rsplit(":", maxsplit=1)
    if not raw_port.isdigit():
        return None
    return address.strip("[]") or "*", int(raw_port)


def _parse_ports(lines: Sequence[str]) -> tuple[ListeningPort, ...]:
    ports: list[ListeningPort] = []
    for line in _section(lines, _PORTS_MARKER, _STATUS_MARKER):
        try:
            protocol, endpoint = line.split("|", maxsplit=1)
        except ValueError:
            continue
        parsed = _split_endpoint(endpoint)
        if parsed is None:
            continue
        address, port = parsed
        ports.append(ListeningPort(protocol=protocol.lower(), address=address, port=port))
    return tuple(ports)


def _parse_status(lines: Sequence[str]) -> int:
    for line in lines:
        if line.startswith(_STATUS_MARKER):
            raw = line.removeprefix(_STATUS_MARKER).strip()
            if raw.lstrip("-").isdigit():
                return int(raw)
    raise EmulationError("Missing emulation init status")


def emulate_firmware(
    rootfs: str | Path,
    *,
    architecture: str,
    init_script: str = "/etc/init.d/rcS",
    image: str = DEFAULT_EMULATOR_IMAGE,
    runner: CommandRunner = subprocess.run,
    emulation_timeout_s: int = 15,
    settle_s: float = 2.0,
) -> EmulationResult:
    """Run firmware init in a hardened Docker/QEMU sandbox and parse telemetry."""
    command = build_docker_command(
        rootfs,
        architecture=architecture,
        init_script=init_script,
        image=image,
        emulation_timeout_s=emulation_timeout_s,
        settle_s=settle_s,
    )
    try:
        result = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=emulation_timeout_s + 30,
        )
    except FileNotFoundError as exc:
        raise EmulationError("Docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise EmulationError("Docker/QEMU emulation timed out") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise EmulationError(
            f"Docker/QEMU exited with status {result.returncode}"
            + (f": {detail}" if detail else "")
        )

    lines = result.stdout.splitlines()
    processes = _parse_processes(lines)
    listening_ports = _parse_ports(lines)
    init_status = _parse_status(lines)
    evidence = tuple(
        [f"process:{item.pid}:{item.command}" for item in processes]
        + [
            f"listener:{item.protocol}:{item.address}:{item.port}"
            for item in listening_ports
        ]
    )
    severity = FindingSeverity.HIGH if listening_ports else FindingSeverity.INFO
    finding = new_finding(
        severity=severity,
        confidence=0.9,
        title=f"QEMU {architecture} firmware init emulation",
        description=(
            f"Init exited with status {init_status}; observed {len(processes)} processes "
            f"and {len(listening_ports)} listening ports."
        ),
        host=Path(rootfs).name,
        evidence=evidence,
        tags=frozenset({"emulation", "qemu", architecture}),
        metadata={
            "architecture": architecture,
            "init_script": init_script,
            "init_status": init_status,
            "process_count": len(processes),
            "listening_port_count": len(listening_ports),
        },
    )
    return EmulationResult(
        architecture=architecture,
        init_script=init_script,
        init_status=init_status,
        processes=processes,
        listening_ports=listening_ports,
        findings=(finding,),
    )
