"""Score component detection against the corpus in benchmarks/corpus/.

Read benchmarks/README.md before treating any number this prints as a
validated accuracy claim: several tech-spec section 9 metrics are only
partially measurable in this environment, for reasons stated there (no
network access, no binwalk install), and this script does not pretend
otherwise.

Usage (from the repository root, with ai_firmware_agent importable):

    poetry run python benchmarks/run.py
    poetry run python benchmarks/run.py --corpus benchmarks/corpus/openwrt-23.05.5-ath79-tiny
    poetry run python benchmarks/run.py --time-scan
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from ai_firmware_agent.analyzer import match_components, score_and_rank_matches
from ai_firmware_agent.cve_db import mock_lookup
from ai_firmware_agent.detectors import detect_components
from ai_firmware_agent.normalizer import Component

CORPUS_ROOT = Path(__file__).parent / "corpus"


@dataclass(frozen=True)
class ExpectedComponent:
    name: str
    version: str


@dataclass(frozen=True)
class ScoreResult:
    sample: str
    expected_count: int
    actual_count: int
    true_positive_names: frozenset[str]
    false_negative_names: frozenset[str]
    false_positive_names: frozenset[str]
    version_correct_names: frozenset[str]
    version_mismatch_names: frozenset[str]
    detect_seconds: float

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 1.0

    @property
    def name_precision(self) -> float:
        return self._ratio(len(self.true_positive_names), self.actual_count)

    @property
    def name_recall(self) -> float:
        return self._ratio(len(self.true_positive_names), self.expected_count)

    @property
    def name_f1(self) -> float:
        return _f1(self.name_precision, self.name_recall)

    @property
    def version_precision(self) -> float:
        return self._ratio(len(self.version_correct_names), self.actual_count)

    @property
    def version_recall(self) -> float:
        return self._ratio(len(self.version_correct_names), self.expected_count)

    @property
    def version_f1(self) -> float:
        return _f1(self.version_precision, self.version_recall)


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def load_expected(path: Path) -> list[ExpectedComponent]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = data.get("components", [])
    return [
        ExpectedComponent(
            name=str(item["name"]).strip().lower(),
            version=str(item["version"]).strip(),
        )
        for item in items
    ]


def score_sample(
    sample_dir: Path,
    detect: Callable[[Path], list[Component]],
) -> ScoreResult:
    """Run detection on one corpus entry and score it against expected.yml."""
    expected = load_expected(sample_dir / "expected.yml")
    expected_by_name = {item.name: item.version for item in expected}

    started = time.perf_counter()
    actual = detect(sample_dir / "rootfs")
    elapsed = time.perf_counter() - started
    actual_by_name = {
        component.name.strip().lower(): component.version.strip()
        for component in actual
    }

    expected_names = frozenset(expected_by_name)
    actual_names = frozenset(actual_by_name)
    true_positive_names = expected_names & actual_names
    version_correct = frozenset(
        name
        for name in true_positive_names
        if actual_by_name[name] == expected_by_name[name]
    )

    return ScoreResult(
        sample=sample_dir.name,
        expected_count=len(expected_names),
        actual_count=len(actual_names),
        true_positive_names=true_positive_names,
        false_negative_names=expected_names - actual_names,
        false_positive_names=actual_names - expected_names,
        version_correct_names=version_correct,
        version_mismatch_names=true_positive_names - version_correct,
        detect_seconds=elapsed,
    )


def discover_corpus(root: Path = CORPUS_ROOT) -> list[Path]:
    return sorted(
        path
        for path in root.iterdir()
        if path.is_dir() and (path / "expected.yml").is_file()
    )


def _print_result(result: ScoreResult) -> None:
    print(f"\n=== {result.sample} ===")
    print(f"  expected: {result.expected_count}   detected: {result.actual_count}")
    print(f"  detection time: {result.detect_seconds * 1000:.1f} ms")
    print(
        f"  name-level    precision={result.name_precision:.3f} "
        f"recall={result.name_recall:.3f} f1={result.name_f1:.3f}"
    )
    print(
        f"  name+version  precision={result.version_precision:.3f} "
        f"recall={result.version_recall:.3f} f1={result.version_f1:.3f}"
    )
    if result.false_negative_names:
        print(f"  missed:  {sorted(result.false_negative_names)}")
    if result.false_positive_names:
        print(f"  extra:   {sorted(result.false_positive_names)}")
    if result.version_mismatch_names:
        print(f"  wrong version: {sorted(result.version_mismatch_names)}")


def time_scan() -> None:
    """Time detection + mock CVE matching + PRisk scoring, end to end.

    Does not include binwalk/unsquashfs extraction: this environment has no
    binwalk install, so that step cannot be exercised here at all. See
    benchmarks/README.md.
    """
    sample = CORPUS_ROOT / "openwrt-23.05.5-ath79-tiny" / "rootfs"
    started = time.perf_counter()
    components = detect_components(sample)
    detected_at = time.perf_counter()
    matches = match_components(components, lookup_fn=mock_lookup)
    matched_at = time.perf_counter()
    score_and_rank_matches(matches)
    scored_at = time.perf_counter()

    print(f"\n=== timing: {sample.name} ({len(components)} components) ===")
    print(f"  detect_components:      {(detected_at - started) * 1000:8.1f} ms")
    print(f"  match_components (mock):{(matched_at - detected_at) * 1000:8.1f} ms")
    print(f"  score_and_rank_matches: {(scored_at - matched_at) * 1000:8.1f} ms")
    print(f"  total:                  {(scored_at - started) * 1000:8.1f} ms")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        help="Score only this corpus entry (default: every entry under benchmarks/corpus/).",
    )
    parser.add_argument(
        "--time-scan",
        action="store_true",
        help="Also time detection + mock CVE matching + PRisk scoring.",
    )
    args = parser.parse_args(argv)

    samples = [args.corpus] if args.corpus else discover_corpus()
    if not samples:
        print(f"No corpus entries found under {CORPUS_ROOT}", file=sys.stderr)
        return 1

    for sample_dir in samples:
        result = score_sample(sample_dir, detect_components)
        _print_result(result)

    if args.time_scan:
        time_scan()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
