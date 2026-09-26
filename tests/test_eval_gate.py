from __future__ import annotations

import re
from pathlib import Path

import pytest
from shared_llm_core.evaluation import EvalCase, EvalResult, run_eval

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"

_CASE_ROWS = {
    "native": (
        ("native-firmware-critical", "critical", {"component": "synthetic-critical"}),
        ("native-firmware-high", "high", {"component": "synthetic-high"}),
        ("native-firmware-medium", "medium", {"component": "synthetic-medium"}),
        (
            "native-firmware-kev-hit",
            "critical",
            {"component": "synthetic-kev", "kev": True},
        ),
        (
            "native-firmware-no-cve",
            "medium",
            {"component": "synthetic-no-cve", "cves": []},
        ),
        (
            "native-firmware-high-epss",
            "high",
            {"component": "synthetic-epss", "epss": 0.9},
        ),
    ),
    "emba": (
        (
            "emba-firmware-critical",
            "critical",
            {"component": "synthetic-critical", "finding_origin": "emba_import"},
        ),
        (
            "emba-firmware-high",
            "high",
            {"component": "synthetic-high", "finding_origin": "emba_import"},
        ),
        (
            "emba-firmware-medium",
            "medium",
            {"component": "synthetic-medium", "finding_origin": "emba_import"},
        ),
        (
            "emba-firmware-kev-hit",
            "critical",
            {
                "component": "synthetic-kev",
                "kev": True,
                "finding_origin": "emba_import",
            },
        ),
        (
            "emba-firmware-no-cve",
            "medium",
            {
                "component": "synthetic-no-cve",
                "cves": [],
                "finding_origin": "emba_import",
            },
        ),
        (
            "emba-firmware-high-epss",
            "high",
            {
                "component": "synthetic-epss",
                "epss": 0.9,
                "finding_origin": "emba_import",
            },
        ),
    ),
}


def _cases(source: str) -> list[EvalCase]:
    return [
        EvalCase(
            id=case_id,
            inputs=inputs,
            expected={
                "required_fields": [
                    "finding.severity",
                    "finding.confidence",
                    "business_impact",
                    "remediation_summary",
                    "rationale",
                ],
                "severity": {
                    "field": "finding.severity",
                    "allowed": ["low", "medium", "high", "critical"],
                    "baseline": severity,
                    "max_drift": 0,
                },
                "confidence": {
                    "field": "finding.confidence",
                    "min": 0.0,
                    "max": 1.0,
                },
            },
        )
        for case_id, severity, inputs in _CASE_ROWS[source]
    ]


def _run_replay(monkeypatch: pytest.MonkeyPatch, source: str) -> list[EvalResult]:
    monkeypatch.setenv("SHARED_LLM_EVAL_MODE", "replay")
    monkeypatch.setenv("SHARED_LLM_EVAL_FIXTURES", str(FIXTURES))
    return run_eval(_cases(source))


def test_native_golden_set_passes_in_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    results = _run_replay(monkeypatch, "native")
    assert all(result.passed for result in results), results


def test_imported_golden_set_passes_in_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    results = _run_replay(monkeypatch, "emba")
    assert all(result.passed for result in results), results


def test_golden_set_has_expected_case_count() -> None:
    cases = [*_cases("native"), *_cases("emba")]
    assert len(cases) >= 12
    assert len({case.id for case in cases}) == len(cases)
    assert {path.stem for path in FIXTURES.glob("*.json")} == {case.id for case in cases}


def test_sources_have_separate_baselines() -> None:
    native_ids = {case.id for case in _cases("native")}
    imported_ids = {case.id for case in _cases("emba")}
    assert native_ids.isdisjoint(imported_ids)
    assert all(case_id.startswith("native-") for case_id in native_ids)
    assert all(case_id.startswith("emba-") for case_id in imported_ids)


def test_fixtures_contain_no_real_identifiers() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in FIXTURES.glob("*.json"))
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", combined)
    assert not re.search(r"(?i)(?:api[_-]?key|password|secret|token)\s*[:=]", combined)
    assert not re.search(r"(?i)(?:[a-z]:\\|/(?:home|users|workspace|repo)/)", combined)
    assert "customer" not in combined.lower()
