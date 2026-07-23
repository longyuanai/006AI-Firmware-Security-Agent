"""Tests for the CISA KEV catalog client."""

from __future__ import annotations

import httpx

from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.kev import (
    KEV_CATALOG_URL,
    enrich_with_kev,
    fetch_kev_catalog,
    kev_lookup,
)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_kev_catalog_parses_cve_ids():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == KEV_CATALOG_URL
        return httpx.Response(
            200,
            json={
                "catalogVersion": "2026.07.24",
                "vulnerabilities": [
                    {"cveID": "CVE-2024-3094"},
                    {"cveID": "cve-2021-44228"},
                ],
            },
        )

    with _client(handler) as client:
        catalog = fetch_kev_catalog(client=client)

    assert catalog == frozenset({"CVE-2024-3094", "CVE-2021-44228"})


def test_kev_lookup_uses_supplied_catalog_without_http():
    catalog = frozenset({"CVE-2024-3094"})
    assert kev_lookup("cve-2024-3094", catalog=catalog) is True
    assert kev_lookup("CVE-2024-0000", catalog=catalog) is False


def test_kev_lookup_returns_false_on_http_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "unavailable"})

    with _client(handler) as client:
        assert kev_lookup("CVE-2024-3094", client=client) is False


def test_kev_lookup_returns_false_on_malformed_payload():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": []})

    with _client(handler) as client:
        assert kev_lookup("CVE-2024-3094", client=client) is False


def test_enrich_with_kev_downloads_catalog_once_and_preserves_fields():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-KEV"}]},
        )

    records = [
        CveRecord("CVE-KEV", 9.8, "known", epss=0.9),
        CveRecord("CVE-OTHER", 5.0, "other", epss=0.1),
    ]
    with _client(handler) as client:
        enriched = enrich_with_kev(records, client=client)

    assert [record.kev for record in enriched] == [True, False]
    assert enriched[0].epss == 0.9
    assert records[0].kev is False
    assert len(calls) == 1
