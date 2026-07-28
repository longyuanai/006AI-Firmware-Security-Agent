"""Scoring arithmetic for benchmarks/run.py.

tech-spec section 9 stated four accuracy targets with no corpus and no
scoring code behind any of them. These tests check the arithmetic itself
against hand-computed fractions and small synthetic cases; they do not run
against the real corpus, which needs a separate opt-in pass (see
test_real_corpus_entries_are_internally_consistent below, the one test that
does touch benchmarks/corpus/ and only to check shape, not to assert an
accuracy number).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

BENCHMARKS_DIR = Path(__file__).parents[1] / "benchmarks"
if str(BENCHMARKS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS_DIR.parent))

from benchmarks.run import (  # noqa: E402
    ExpectedComponent,
    ScoreResult,
    _f1,
    discover_corpus,
    load_expected,
    score_sample,
)
from ai_firmware_agent.normalizer import Component  # noqa: E402


def _score(expected_count, actual_count, tp, fn, fp, version_correct):
    tp = frozenset(tp)
    return ScoreResult(
        sample="synthetic",
        expected_count=expected_count,
        actual_count=actual_count,
        true_positive_names=tp,
        false_negative_names=frozenset(fn),
        false_positive_names=frozenset(fp),
        version_correct_names=frozenset(version_correct),
        version_mismatch_names=tp - frozenset(version_correct),
        detect_seconds=0.0,
    )


def test_perfect_match_scores_one_everywhere():
    result = _score(3, 3, {"a", "b", "c"}, set(), set(), {"a", "b", "c"})
    assert result.name_precision == result.name_recall == result.name_f1 == 1.0
    assert result.version_precision == result.version_recall == 1.0


def test_empty_expected_and_empty_actual_is_vacuously_perfect():
    result = _score(0, 0, set(), set(), set(), set())
    assert result.name_precision == 1.0
    assert result.name_recall == 1.0


def test_false_negative_only_hurts_recall_not_precision():
    """One missed component: everything detected was correct."""
    result = _score(2, 1, {"a"}, {"b"}, set(), {"a"})
    assert result.name_precision == 1.0
    assert result.name_recall == 0.5


def test_false_positive_only_hurts_precision_not_recall():
    """One spurious component: everything expected was still found."""
    result = _score(1, 2, {"a"}, set(), {"b"}, {"a"})
    assert result.name_recall == 1.0
    assert result.name_precision == 0.5


def test_version_mismatch_counts_as_a_name_hit_but_a_version_miss():
    result = _score(1, 1, {"a"}, set(), set(), set())
    assert result.name_precision == 1.0
    assert result.name_recall == 1.0
    assert result.version_precision == 0.0
    assert result.version_recall == 0.0
    assert result.version_mismatch_names == {"a"}


@pytest.mark.parametrize(
    ("precision", "recall", "expected_f1"),
    [
        (1.0, 1.0, 1.0),
        (1.0, 0.0, 0.0),
        (0.0, 0.0, 0.0),
        (0.5, 0.5, 0.5),
        (2 / 3, 2 / 3, 2 / 3),
    ],
)
def test_f1_matches_the_harmonic_mean_formula(precision, recall, expected_f1):
    assert _f1(precision, recall) == pytest.approx(expected_f1)


def test_load_expected_lowercases_and_strips(tmp_path):
    path = tmp_path / "expected.yml"
    path.write_text(
        yaml.safe_dump({"components": [{"name": "  BusyBox  ", "version": " 1.36.1 "}]}),
        encoding="utf-8",
    )
    loaded = load_expected(path)
    assert loaded == [ExpectedComponent(name="busybox", version="1.36.1")]


def test_score_sample_against_the_shipped_selfcheck_fixture_matches_by_hand():
    """The exact fractions documented in benchmarks/README.md and by hand:

    expected = {known-good, version-drift, missing-component}
    actual   = {known-good, version-drift, extra-component}
    TP names = {known-good, version-drift} -> 2/3 precision, 2/3 recall
    version-correct = {known-good} only    -> 1/3 precision, 1/3 recall
    """

    def fake_detect(rootfs: Path) -> list[Component]:
        return [
            Component(name="known-good", version="1.0.0"),
            Component(name="version-drift", version="2.0.0"),
            Component(name="extra-component", version="9.9.9"),
        ]

    sample_dir = BENCHMARKS_DIR / "corpus" / "harness-selfcheck"
    result = score_sample(sample_dir, fake_detect)

    assert result.expected_count == 3
    assert result.actual_count == 3
    assert result.name_precision == pytest.approx(2 / 3)
    assert result.name_recall == pytest.approx(2 / 3)
    assert result.version_precision == pytest.approx(1 / 3)
    assert result.version_recall == pytest.approx(1 / 3)
    assert result.false_negative_names == {"missing-component"}
    assert result.false_positive_names == {"extra-component"}
    assert result.version_mismatch_names == {"version-drift"}


def test_score_sample_actually_runs_the_real_detector_on_the_fixture():
    """No detect() stub this time: exercises detectors/packages.py for real."""
    from ai_firmware_agent.detectors import detect_components

    sample_dir = BENCHMARKS_DIR / "corpus" / "harness-selfcheck"
    result = score_sample(sample_dir, detect_components)

    assert result.true_positive_names == {"known-good", "version-drift"}
    assert result.version_mismatch_names == {"version-drift"}


def test_discover_corpus_finds_every_shipped_entry():
    found = {path.name for path in discover_corpus()}
    assert {"harness-selfcheck", "openwrt-23.05.5-ath79-tiny"} <= found


def test_real_corpus_entries_are_internally_consistent():
    """Every shipped corpus entry must have a loadable expected.yml and rootfs/."""
    for sample_dir in discover_corpus():
        expected = load_expected(sample_dir / "expected.yml")
        assert expected, f"{sample_dir.name}: expected.yml has no components"
        assert (sample_dir / "rootfs").is_dir(), f"{sample_dir.name}: no rootfs/"


def test_openwrt_corpus_measures_only_the_package_detector(monkeypatch):
    """Guards the scope claim in benchmarks/README.md: no ELF or os-release
    evidence is present, so this entry cannot accidentally start exercising
    detectors/binary.py or detectors/osrelease.py without anyone noticing."""
    sample_dir = BENCHMARKS_DIR / "corpus" / "openwrt-23.05.5-ath79-tiny" / "rootfs"
    assert not list(sample_dir.rglob("os-release"))
    elf_files = [
        path
        for path in sample_dir.rglob("*")
        if path.is_file() and path.read_bytes()[:4] == b"\x7fELF"
    ]
    assert elf_files == []
