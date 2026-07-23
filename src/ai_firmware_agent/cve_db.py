"""Tiny mock CVE database for PoC purposes.

Real-world implementations would query NVD / EPSS / CISA KEV. The PoC ships
a hard-coded dataset so tests are reproducible and there's no network
dependency. The interface mirrors what a real lookup would look like:
input (name, version) → list of `CveRecord`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_firmware_agent.normalizer import Component


@dataclass(frozen=True)
class CveRecord:
    cve: str
    cvss: float
    summary: str
    epss: float = 0.0


# Format: key is (name_lower, version_prefix). version_prefix matches if the
# component's version starts with it. So `("busybox", "1.36")` matches
# BusyBox 1.36.0 and 1.36.1 but not 1.35.
_KNOWN_VULN: list[tuple[tuple[str, str], list[CveRecord]]] = [
    (("busybox", "1.36"), [
        CveRecord(cve="CVE-2023-39810", cvss=7.5, summary="BusyBox 1.36.x awk heap OOB write."),
    ]),
    (("busybox", "1.34"), [
        CveRecord(cve="CVE-2022-48174", cvss=7.5, summary="BusyBox 1.34.x awk OOB read."),
    ]),
    (("openssh", "7.4"), [
        CveRecord(cve="CVE-2018-15473", cvss=5.3, summary="OpenSSH 7.4 user enumeration via timing."),
    ]),
    (("openssl", "1.1.0"), [
        CveRecord(cve="CVE-2017-3735", cvss=5.0, summary="OpenSSL 1.1.0 x509 verify crash."),
        CveRecord(cve="CVE-2018-0734", cvss=5.0, summary="OpenSSL 1.1.0 timing side-channel."),
    ]),
    (("dropbear", "2020.80"), [
        CveRecord(cve="CVE-2021-28041", cvss=6.8, summary="Dropbear 2020.80 double-free in agent."),
    ]),
    (("lighttpd", "1.4.50"), [
        CveRecord(cve="CVE-2018-19052", cvss=9.8, summary="lighttpd 1.4.50 path traversal RCE."),
    ]),
    (("xz", "5.6"), [
        CveRecord(cve="CVE-2024-3094", cvss=10.0, summary="xz/liblzma 5.6.0/5.6.1 backdoor in sshd."),
    ]),
]


def mock_lookup(component: Component) -> list[CveRecord]:
    """Return known CVE records matching `(name, version)`."""
    key = (component.name.strip().lower(), component.version.strip())
    matches: list[CveRecord] = []
    for (n, v_prefix), records in _KNOWN_VULN:
        if n != key[0]:
            continue
        if not key[1].startswith(v_prefix):
            continue
        matches.extend(records)
    return matches
