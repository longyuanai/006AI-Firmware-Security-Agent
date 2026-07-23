"""Tests for the mock CVE database."""

from __future__ import annotations

from ai_firmware_agent.cve_db import mock_lookup
from ai_firmware_agent.normalizer import Component


def _c(name: str, version: str) -> Component:
    return Component(name=name, version=version, vendor="v")


def test_busybox_1_36_has_cve():
    cs = mock_lookup(_c("busybox", "1.36.1"))
    assert any(c.cve == "CVE-2023-39810" for c in cs)


def test_busybox_1_34_has_different_cve():
    cs = mock_lookup(_c("busybox", "1.34.0"))
    assert any(c.cve == "CVE-2022-48174" for c in cs)


def test_unknown_component_returns_empty():
    assert mock_lookup(_c("nginx", "1.0.0")) == []


def test_openssl_1_1_0_returns_multiple_cves():
    cs = mock_lookup(_c("openssl", "1.1.0"))
    assert len(cs) >= 2


def test_version_prefix_match():
    cs = mock_lookup(_c("openssl", "1.1.0g"))
    assert any(c.cve == "CVE-2017-3735" for c in cs)


def test_case_insensitive_name():
    cs = mock_lookup(_c("BUSYBOX", "1.36.0"))
    assert len(cs) == 1


def test_xz_5_6_backdoor():
    cs = mock_lookup(_c("xz", "5.6.0"))
    assert any(c.cve == "CVE-2024-3094" for c in cs)
    assert any(c.cvss == 10.0 for c in cs)