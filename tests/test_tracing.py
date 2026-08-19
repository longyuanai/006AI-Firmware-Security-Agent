from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ai_firmware_agent import gateway_envelope


def test_scan_entrypoint_creates_span(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object],
    ) -> Iterator[None]:
        captured.append((name, attributes))
        yield

    expected = {"findings": [], "errors": [], "summary": {}}
    monkeypatch.setattr(gateway_envelope, "span", recording_span)
    monkeypatch.setattr(
        gateway_envelope,
        "_scan_payload_to_envelope",
        lambda _payload, **_kwargs: expected,
    )

    raw_payload = '{"firmware_url":"https://private.example/customer.bin"}'
    assert gateway_envelope.scan_payload_to_envelope(raw_payload) is expected
    assert captured == [
        (
            "product.scan",
            {"product.id": "006", "scan.target_type": "firmware_image"},
        )
    ]
