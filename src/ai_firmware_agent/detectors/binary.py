"""Component detection from version strings embedded in binaries.

The weakest of the three evidence classes, and the only one available when a
firmware ships no package database at all — which is the common case for
vendor-built images. Files are read, never executed, and every read is
bounded because the input is untrusted.
"""

from __future__ import annotations

import re
from pathlib import Path

from ai_firmware_agent.normalizer import Component

ELF_MAGIC = b"\x7fELF"

# Directories worth scanning in an extracted rootfs. Scanning everything on a
# large image is slow and mostly finds data files.
SCAN_DIRECTORIES = (
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "usr/libexec",
    "lib",
    "usr/lib",
)
MAX_SCAN_FILES = 2_000
MAX_FILE_BYTES = 8 * 1024 * 1024

# (pattern, component name, vendor, category). Patterns are anchored on the
# banner text upstream projects compile into their binaries.
_PATTERNS: tuple[tuple[re.Pattern[bytes], str, str, str], ...] = (
    (
        re.compile(rb"BusyBox v(\d+\.\d+\.\d+)"),
        "busybox",
        "busybox.net",
        "userspace",
    ),
    (
        re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]*)"),
        "openssl",
        "openssl.org",
        "crypto",
    ),
    (
        re.compile(rb"[Dd]ropbear[ _]v?(\d{4}\.\d+)"),
        "dropbear",
        "matt.ucc.asn.au",
        "remote_access",
    ),
    (
        re.compile(rb"lighttpd[/ ](\d+\.\d+\.\d+)"),
        "lighttpd",
        "lighttpd.net",
        "web_server",
    ),
    (
        re.compile(rb"OpenSSH[_ ](\d+\.\d+(?:p\d+)?)"),
        "openssh",
        "openssh.com",
        "remote_access",
    ),
    (
        re.compile(rb"Linux version (\d+\.\d+\.\d+)"),
        "kernel",
        "linux.org",
        "os",
    ),
    (
        re.compile(rb"dnsmasq[- ]v?(\d+\.\d+(?:\.\d+)?)"),
        "dnsmasq",
        "thekelleys.org.uk",
        "network",
    ),
    (
        re.compile(rb"xz \(XZ Utils\) (\d+\.\d+\.\d+)"),
        "xz",
        "tukaani.org",
        "compression",
    ),
    (
        re.compile(rb"U-Boot (\d{4}\.\d+)"),
        "u-boot",
        "denx.de",
        "bootloader",
    ),
    # The five patterns below match a single hardcoded string literal (or an
    # adjacent-literal concatenation the C preprocessor merges at compile
    # time), so the joined "name/version" bytes are guaranteed to sit
    # contiguously in the binary's rodata. That is not true of every banner:
    # some projects assemble their version text at runtime with sprintf,
    # which leaves the format string and the version number in separate,
    # non-adjacent locations, so a substring scan would never match them
    # (libcurl's curl_version() is a real example and is deliberately not
    # included here for that reason). Each pattern below is the exact,
    # well-documented banner text a real build embeds:
    #   zlib       deflate.c:   deflate_copyright[] = " deflate 1.2.11 ..."
    #   wpa_supplicant  .c: "wpa_supplicant v" VERSION_STR "\n..."
    #   hostapd         .c: "hostapd v" VERSION_STR "\n..."
    #   mbedtls    version.h:  MBEDTLS_VERSION_STRING "mbed TLS 2.28.0"
    #   nginx      nginx.h:    NGINX_VER "nginx/" NGINX_VERSION
    (
        re.compile(rb"deflate (\d+\.\d+\.\d+) Copyright"),
        "zlib",
        "zlib.net",
        "compression",
    ),
    (
        re.compile(rb"wpa_supplicant v(\d+\.\d+)"),
        "wpa_supplicant",
        "w1.fi",
        "network",
    ),
    (
        re.compile(rb"hostapd v(\d+\.\d+)"),
        "hostapd",
        "w1.fi",
        "network",
    ),
    (
        re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"),
        "mbedtls",
        "trustedfirmware.org",
        "crypto",
    ),
    (
        re.compile(rb"nginx/(\d+\.\d+\.\d+)"),
        "nginx",
        "nginx.org",
        "web_server",
    ),
)


def _candidate_files(rootfs: Path) -> list[Path]:
    candidates: list[Path] = []
    for relative in SCAN_DIRECTORIES:
        directory = rootfs / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*"), key=str):
            if len(candidates) >= MAX_SCAN_FILES:
                return candidates
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            candidates.append(path)
    return candidates


def _read_bounded(path: Path) -> bytes | None:
    """Read a bounded prefix, skipping anything that is not an executable."""
    try:
        with path.open("rb") as stream:
            head = stream.read(4)
            if head != ELF_MAGIC:
                return None
            return head + stream.read(MAX_FILE_BYTES - 4)
    except OSError:
        return None


def scan_bytes(blob: bytes) -> list[tuple[str, str, str, str]]:
    """Return (name, version, vendor, category) for every banner matched."""
    found: list[tuple[str, str, str, str]] = []
    for pattern, name, vendor, category in _PATTERNS:
        match = pattern.search(blob)
        if match is None:
            continue
        version = match.group(1).decode("ascii", errors="replace")
        found.append((name, version, vendor, category))
    return found


def detect(rootfs: Path) -> list[Component]:
    """Scan executables for the version banners of known components."""
    components: list[Component] = []
    for path in _candidate_files(rootfs):
        blob = _read_bounded(path)
        if blob is None:
            continue
        try:
            evidence = path.relative_to(rootfs).as_posix()
        except ValueError:
            evidence = path.name
        for name, version, vendor, category in scan_bytes(blob):
            components.append(
                Component(
                    name=name,
                    version=version,
                    vendor=vendor,
                    category=category,
                    path=evidence,
                    extra={
                        "detector": "binary",
                        "evidence": f"binary:{evidence}",
                    },
                )
            )
    return components
