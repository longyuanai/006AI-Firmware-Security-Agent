"""CPE parsing and version-range comparison."""

from __future__ import annotations

import pytest

from ai_firmware_agent.cve_db.version import (
    VersionRange,
    matches_version,
    parse_cpe,
    split_cpe_fields,
    version_key,
)


def test_parse_cpe_extracts_product_and_version():
    parsed = parse_cpe("cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*")
    assert parsed is not None
    assert parsed.part == "a"
    assert parsed.vendor == "busybox"
    assert parsed.product == "busybox"
    assert parsed.version == "1.36.1"


def test_parse_cpe_rejects_non_cpe_strings():
    assert parse_cpe("busybox 1.36.1") is None
    assert parse_cpe("cpe:2.2:a:busybox:busybox") is None


def test_split_cpe_fields_honours_escaped_colons():
    fields = split_cpe_fields(r"cpe:2.3:a:vendor:pro\:duct:1.0")
    assert fields[4] == r"pro\:duct"
    assert fields[5] == "1.0"


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.36.9", "1.36.10"),
        ("1.36", "1.36.1"),
        ("8.5", "8.5p1"),
        ("2020.79", "2020.80"),
        ("1.9", "1.10"),
    ],
)
def test_version_key_orders_embedded_versions(lower, higher):
    assert version_key(lower) < version_key(higher)


def test_exact_cpe_version_matches_case_insensitively():
    assert matches_version("8.5p1", "8.5P1") is True
    assert matches_version("8.5p1", "9.0") is False


def test_wildcard_cpe_requires_a_bounded_range():
    # "affects every version ever released" is not actionable, so a wildcard
    # CPE without bounds must not match anything.
    assert matches_version("*", "1.36.1") is False
    assert matches_version("-", "1.36.1") is False


def test_range_bounds_are_inclusive_and_exclusive_as_declared():
    bounded = VersionRange(start_including="1.30.0", end_excluding="1.36.1")
    assert matches_version("*", "1.30.0", bounded) is True
    assert matches_version("*", "1.35.0", bounded) is True
    assert matches_version("*", "1.36.1", bounded) is False
    assert matches_version("*", "1.29.9", bounded) is False

    exclusive_start = VersionRange(start_excluding="1.30.0", end_including="1.36.1")
    assert matches_version("*", "1.30.0", exclusive_start) is False
    assert matches_version("*", "1.36.1", exclusive_start) is True


def test_unbounded_range_is_not_considered_bounded():
    assert VersionRange().is_bounded is False
    assert VersionRange(end_excluding="2.0").is_bounded is True
