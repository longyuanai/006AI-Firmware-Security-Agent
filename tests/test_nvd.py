"""Tests for the NVD CVE API client."""

from __future__ import annotations

import httpx

from ai_firmware_agent.normalizer import Component
from ai_firmware_agent.nvd import NVD_API_URL, nvd_lookup


def _component(name: str = "openssl", version: str = "3.0.0") -> Component:
    return Component(name=name, version=version)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_nvd_lookup_parses_cvss_and_english_description():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(NVD_API_URL)
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-0001",
                            "descriptions": [
                                {"lang": "es", "value": "resumen"},
                                {"lang": "en", "value": "English summary"},
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8}}
                                ]
                            },
                        }
                    }
                ]
            },
        )

    with _client(handler) as client:
        records = nvd_lookup(_component(), client=client)

    assert records[0].cve == "CVE-2024-0001"
    assert records[0].cvss == 9.8
    assert records[0].summary == "English summary"


def test_nvd_lookup_sends_component_query_and_api_key_header():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["keywordSearch"] == "busybox 1.36.1"
        assert request.headers["apiKey"] == "test-key"
        return httpx.Response(200, json={"vulnerabilities": []})

    with _client(handler) as client:
        records = nvd_lookup(
            _component("busybox", "1.36.1"),
            api_key="test-key",
            client=client,
        )

    assert records == []


def test_nvd_lookup_falls_back_to_mock_on_http_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "unavailable"})

    with _client(handler) as client:
        records = nvd_lookup(_component("busybox", "1.36.1"), client=client)

    assert any(record.cve == "CVE-2023-39810" for record in records)


def test_nvd_lookup_falls_back_to_mock_on_malformed_payload():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": []})

    with _client(handler) as client:
        records = nvd_lookup(_component("xz", "5.6.0"), client=client)

    assert any(record.cve == "CVE-2024-3094" for record in records)
