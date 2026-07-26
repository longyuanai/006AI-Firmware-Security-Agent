"""Pacing, caching and connection reuse for whole-inventory NVD scans.

A scan looks up every component. The OpenWrt sample here carries 135
packages against a 5-request-per-30-second unauthenticated limit, so an
unpaced client earns 403s and silently degrades every component to mock data.
"""

from __future__ import annotations

import httpx

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.nvd import NvdClient


class _Clock:
    """Deterministic stand-in for time.monotonic / time.sleep."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _empty(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"vulnerabilities": []})


def test_requests_are_paced_to_the_unauthenticated_limit():
    clock = _Clock()
    with _client(_empty) as http:
        nvd = NvdClient(client=http, sleep=clock.sleep, monotonic=clock.monotonic)
        assert nvd.min_interval_s == 6.0
        nvd.lookup(Component(name="busybox", version="1.36.1"))
        nvd.lookup(Component(name="openssl", version="3.0.0"))
        nvd.lookup(Component(name="dropbear", version="2020.80"))

    # First request is immediate; each later one waits out the interval.
    assert clock.slept == [6.0, 6.0]


def test_an_api_key_raises_the_rate():
    clock = _Clock()
    with _client(_empty) as http:
        nvd = NvdClient(
            api_key="test-key",
            client=http,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )
        assert nvd.min_interval_s == 0.6
        nvd.lookup(Component(name="busybox", version="1.36.1"))
        nvd.lookup(Component(name="openssl", version="3.0.0"))
    assert clock.slept == [0.6]


def test_time_already_spent_counts_towards_the_interval():
    clock = _Clock()
    with _client(_empty) as http:
        nvd = NvdClient(client=http, sleep=clock.sleep, monotonic=clock.monotonic)
        nvd.lookup(Component(name="busybox", version="1.36.1"))
        clock.now += 4.0  # slow response, parsing, other work
        nvd.lookup(Component(name="openssl", version="3.0.0"))
    assert clock.slept == [2.0]


def test_a_repeated_component_is_served_from_cache():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"vulnerabilities": []})

    clock = _Clock()
    with _client(handler) as http:
        nvd = NvdClient(client=http, sleep=clock.sleep, monotonic=clock.monotonic)
        component = Component(name="busybox", version="1.36.1")
        first = nvd.lookup(component)
        second = nvd.lookup(Component(name="BusyBox", version=" 1.36.1 "))

    assert len(requests) == 1
    assert first == second
    # A cache hit must not burn an interval either.
    assert clock.slept == []


def test_cached_results_cannot_be_mutated_by_a_caller():
    with _client(_empty) as http:
        nvd = NvdClient(client=http)
        component = Component(name="busybox", version="1.36.1")
        nvd.lookup(component).append("tampered")
        assert nvd.lookup(component) == []


def test_a_failed_lookup_is_cached_as_its_mock_fallback():
    """A 403 must not be retried once per repeat of the same component."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(403, text="forbidden")

    with _client(handler) as http:
        nvd = NvdClient(client=http, sleep=lambda _s: None)
        component = Component(name="busybox", version="1.36.1")
        first = nvd.lookup(component)
        second = nvd.lookup(component)

    assert len(requests) == 1
    assert first == second
    assert any(record.cve == "CVE-2023-39810" for record in first)


def test_results_are_bounded_per_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["resultsPerPage"] == "50"
        return httpx.Response(200, json={"vulnerabilities": []})

    with _client(handler) as http:
        NvdClient(client=http).lookup(Component(name="busybox", version="1.36.1"))


def test_an_injected_client_is_not_closed_by_the_nvd_client():
    http = _client(_empty)
    with NvdClient(client=http) as nvd:
        nvd.lookup(Component(name="busybox", version="1.36.1"))
    assert not http.is_closed
    http.close()


def test_one_connection_is_reused_across_the_inventory(monkeypatch):
    import ai_firmware_agent.nvd as nvd_module

    created = []
    real_client = httpx.Client

    def counting_client(**kwargs):
        created.append(kwargs)
        return real_client(transport=httpx.MockTransport(_empty))

    monkeypatch.setattr(nvd_module.httpx, "Client", counting_client)
    with NvdClient(sleep=lambda _s: None) as nvd:
        for name in ("busybox", "openssl", "dropbear"):
            nvd.lookup(Component(name=name, version="1.0"))

    assert len(created) == 1
