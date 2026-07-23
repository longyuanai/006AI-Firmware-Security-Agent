"""Tests for the FIRST EPSS API client."""

from __future__ import annotations

import httpx

from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.eps import EPSS_API_URL, enrich_with_epss, epss_lookup, epss_scores


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_epss_lookup_parses_score_and_query():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(EPSS_API_URL)
        assert request.url.params["cve"] == "CVE-2024-3094"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2024-3094",
                        "epss": "0.734560000",
                        "percentile": "0.990000000",
                    }
                ]
            },
        )

    with _client(handler) as client:
        score = epss_lookup("cve-2024-3094", client=client)

    assert score == 0.73456


def test_epss_scores_batches_cves_in_one_request():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.url.params["cve"] == "CVE-1,CVE-2"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"cve": "CVE-1", "epss": "0.1"},
                    {"cve": "CVE-2", "epss": "0.2"},
                ]
            },
        )

    with _client(handler) as client:
        scores = epss_scores(["CVE-1", "CVE-2", "CVE-1"], client=client)

    assert scores == {"CVE-1": 0.1, "CVE-2": 0.2}
    assert len(calls) == 1


def test_epss_lookup_returns_zero_on_http_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "unavailable"})

    with _client(handler) as client:
        assert epss_lookup("CVE-2024-3094", client=client) == 0.0


def test_epss_lookup_returns_zero_for_missing_or_invalid_score():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"cve": "CVE-OTHER", "epss": "0.3"},
                    {"cve": "CVE-TEST", "epss": "not-a-number"},
                ]
            },
        )

    with _client(handler) as client:
        assert epss_lookup("CVE-TEST", client=client) == 0.0


def test_enrich_with_epss_preserves_cve_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"cve": "CVE-TEST", "epss": "0.42"}]},
        )

    source = CveRecord(cve="CVE-TEST", cvss=8.1, summary="summary")
    with _client(handler) as client:
        [enriched] = enrich_with_epss([source], client=client)

    assert enriched == CveRecord(
        cve="CVE-TEST",
        cvss=8.1,
        summary="summary",
        epss=0.42,
    )
    assert source.epss == 0.0
