"""Product-side contract checks for the v0.5 §9 Finding boundary."""

from __future__ import annotations

import pytest

from ai_firmware_agent.v05_compat import (
    Finding,
    FindingSeverity,
    FindingSource,
    is_uuid4,
    new_finding,
)


def test_new_finding_uses_firmware_source_and_unique_uuid4():
    first = new_finding(
        severity=FindingSeverity.INFO,
        confidence=0.5,
        title="first",
    )
    second = new_finding(
        severity=FindingSeverity.INFO,
        confidence=0.5,
        title="second",
    )
    assert first.source == FindingSource.FIRMWARE
    assert is_uuid4(first.id)
    assert is_uuid4(second.id)
    assert first.id != second.id


def test_finding_rejects_confidence_outside_contract_range():
    with pytest.raises(ValueError, match="confidence"):
        Finding(
            id="id",
            source=FindingSource.FIRMWARE,
            severity=FindingSeverity.LOW,
            confidence=1.01,
            title="invalid",
        )


def test_finding_round_trip_ignores_unknown_fields():
    finding = new_finding(
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        title="listener",
        evidence=("tcp:80",),
        tags=frozenset({"qemu", "emulation"}),
    )
    payload = finding.to_dict()
    payload["future_field"] = "ignored"
    restored = Finding.from_dict(payload)
    assert restored == finding


def test_finding_to_dict_field_order_matches_frozen_schema():
    finding = new_finding(
        severity=FindingSeverity.MEDIUM,
        confidence=0.7,
        title="ordered",
    )
    assert list(finding.to_dict()) == [
        "id",
        "source",
        "severity",
        "confidence",
        "title",
        "description",
        "host",
        "cve",
        "ts",
        "evidence",
        "related",
        "tags",
        "metadata",
    ]
