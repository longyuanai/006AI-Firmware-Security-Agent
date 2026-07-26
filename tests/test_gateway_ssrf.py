"""SSRF containment for the firmware_url download path.

A literal-IP check alone let an attacker-controlled hostname resolve into
loopback or cloud-metadata space, and follow_redirects=True let a public URL
bounce there after the check had already passed.
"""

from __future__ import annotations

import httpx
import pytest

from ai_firmware_agent.gateway_envelope import (
    MAX_REDIRECTS,
    GatewayPayloadError,
    materialize_firmware,
    scan_payload_to_envelope,
)

PUBLIC = ["93.184.216.34"]


def _payload(url: str) -> str:
    return f'{{"firmware_url":"{url}"}}'


def _resolves_to(*addresses: str):
    return lambda _host: list(addresses)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "169.254.169.254",  # cloud instance metadata
        "10.0.0.5",  # RFC 1918
        "192.168.1.1",
        "172.16.0.1",
        "::1",
        "fd00::1",  # unique local
    ],
)
def test_hostname_resolving_to_private_address_is_rejected(address):
    envelope = scan_payload_to_envelope(
        _payload("https://firmware.example/router.bin"),
        resolver=_resolves_to(address),
    )
    assert envelope["findings"] == []
    assert "public address" in envelope["errors"][0]


def test_every_resolved_address_must_be_public():
    """A public A record next to a private one must not unlock the download."""
    envelope = scan_payload_to_envelope(
        _payload("https://firmware.example/router.bin"),
        resolver=_resolves_to("93.184.216.34", "127.0.0.1"),
    )
    assert "public address" in envelope["errors"][0]


def test_unresolvable_host_is_rejected():
    envelope = scan_payload_to_envelope(
        _payload("https://firmware.example/router.bin"),
        resolver=_resolves_to(),
    )
    assert "does not resolve" in envelope["errors"][0]


def test_redirect_into_private_space_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "firmware.example":
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        raise AssertionError("the redirect target must never be requested")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        envelope = scan_payload_to_envelope(
            _payload("https://firmware.example/router.bin"),
            client=client,
            resolver=_resolves_to(*PUBLIC),
        )
    assert envelope["findings"] == []
    assert "public address" in envelope["errors"][0]


def test_redirect_to_a_public_host_is_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "firmware.example":
            return httpx.Response(
                302,
                headers={"location": "https://mirror.example/router.tar.gz"},
            )
        return httpx.Response(200, content=b"not a real archive")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with materialize_firmware(
            _payload("https://firmware.example/router.bin"),
            client=client,
            resolver=_resolves_to(*PUBLIC),
        ) as path:
            assert path.read_bytes() == b"not a real archive"


def test_redirect_loop_is_bounded():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://firmware.example/again"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        envelope = scan_payload_to_envelope(
            _payload("https://firmware.example/router.bin"),
            client=client,
            resolver=_resolves_to(*PUBLIC),
        )
    assert f"exceeded {MAX_REDIRECTS} redirects" in envelope["errors"][0]


def test_redirect_without_location_is_rejected():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        envelope = scan_payload_to_envelope(
            _payload("https://firmware.example/router.bin"),
            client=client,
            resolver=_resolves_to(*PUBLIC),
        )
    assert "missing a location" in envelope["errors"][0]


def test_literal_private_ip_is_still_rejected_without_dns():
    def resolver(_host: str) -> list[str]:
        raise AssertionError("a literal IP must not be resolved")

    envelope = scan_payload_to_envelope(
        _payload("http://127.0.0.1/router.bin"),
        resolver=resolver,
    )
    assert "public address" in envelope["errors"][0]


def test_non_http_scheme_is_rejected():
    with pytest.raises(GatewayPayloadError, match="http or https"):
        with materialize_firmware(_payload("file:///etc/passwd")):
            pass
