"""Firmware-to-firmware component diffing."""

from __future__ import annotations

from ai_firmware_agent.analyzer import ComponentMatch
from ai_firmware_agent.cve_db import CveRecord
from ai_firmware_agent.diff import diff_components, diff_vulnerabilities
from ai_firmware_agent.normalizer import Component


def _c(name: str, version: str, **extra) -> Component:
    return Component(name=name, version=version, extra=extra)


def test_added_and_removed_components():
    result = diff_components(
        [_c("dropbear", "2020.80"), _c("xz", "5.6.0")],
        [_c("dropbear", "2020.80"), _c("lighttpd", "1.4.50")],
    )
    assert [c.name for c in result.added] == ["lighttpd"]
    assert result.added[0].old_version is None
    assert result.added[0].new_version == "1.4.50"
    assert [c.name for c in result.removed] == ["xz"]
    assert result.removed[0].new_version is None


def test_upgraded_and_downgraded_are_ordered_by_version_key():
    result = diff_components(
        [_c("busybox", "1.36.0"), _c("openssl", "3.0.5")],
        [_c("busybox", "1.36.1"), _c("openssl", "3.0.1")],
    )
    assert {c.name for c in result.upgraded} == {"busybox"}
    assert {c.name for c in result.downgraded} == {"openssl"}
    upgrade = result.upgraded[0]
    assert upgrade.old_version == "1.36.0"
    assert upgrade.new_version == "1.36.1"


def test_identical_version_string_is_unchanged():
    result = diff_components([_c("busybox", "1.36.1")], [_c("busybox", "1.36.1")])
    assert [c.name for c in result.unchanged] == ["busybox"]
    assert not result.upgraded and not result.downgraded and not result.changed


def test_versions_with_no_digits_or_letters_are_changed_not_guessed():
    """version_key() orders digit and letter chunks; punctuation-only strings
    produce no chunks at all, and that is the one case ordering must not
    guess a direction for."""
    result = diff_components(
        [_c("thing", "---")],
        [_c("thing", "+++")],
    )
    assert [c.name for c in result.changed] == ["thing"]
    assert not result.upgraded and not result.downgraded


def test_letter_only_versions_still_get_an_ordering_from_version_key():
    """Not incomparable: version_key() tokenizes letters too (e.g. "8.5p1" >
    "8.5" relies on this), so two letter-only strings are still ordered --
    for better or worse, per the module's documented caveat about
    non-semantic build identifiers."""
    result = diff_components(
        [_c("thing", "unknown-build")],
        [_c("thing", "also-unknown")],
    )
    assert not result.changed
    assert [c.name for c in result.upgraded] + [c.name for c in result.downgraded] == [
        "thing"
    ]


def test_component_matching_is_case_insensitive():
    result = diff_components([_c("BusyBox", "1.36.0")], [_c("busybox", "1.36.1")])
    assert [c.name for c in result.upgraded] == ["busybox"]


def test_duplicate_name_on_one_side_keeps_the_first_entry():
    result = diff_components(
        [_c("busybox", "1.36.0"), _c("busybox", "1.30.0")],
        [_c("busybox", "1.36.1")],
    )
    assert len(result.upgraded) == 1
    assert result.upgraded[0].old_version == "1.36.0"


def test_empty_inventories_diff_to_nothing():
    result = diff_components([], [])
    assert not result.has_changes
    assert result.added == result.removed == result.upgraded == ()


def test_has_changes_is_false_when_only_unchanged_present():
    result = diff_components([_c("a", "1.0")], [_c("a", "1.0")])
    assert result.has_changes is False


def test_has_changes_is_true_for_any_non_unchanged_bucket():
    result = diff_components([], [_c("a", "1.0")])
    assert result.has_changes is True


# --- diff_vulnerabilities ----------------------------------------------------


def _match(name: str, version: str, cves: list[str]) -> ComponentMatch:
    return ComponentMatch(
        component=_c(name, version),
        cves=[CveRecord(cve=cve, cvss=7.5, summary="x") for cve in cves],
    )


def test_persistent_vulnerability_is_flagged_across_a_version_bump():
    old_matches = [_match("busybox", "1.36.0", ["CVE-2023-39810"])]
    new_matches = [_match("busybox", "1.36.1", ["CVE-2023-39810"])]

    persistent = diff_vulnerabilities(old_matches, new_matches)

    assert len(persistent) == 1
    assert persistent[0].component == "busybox"
    assert persistent[0].cve == "CVE-2023-39810"
    assert persistent[0].old_version == "1.36.0"
    assert persistent[0].new_version == "1.36.1"


def test_a_fixed_cve_is_not_flagged_as_persistent():
    old_matches = [_match("busybox", "1.34.0", ["CVE-2022-48174"])]
    new_matches = [_match("busybox", "1.36.1", ["CVE-2023-39810"])]

    assert diff_vulnerabilities(old_matches, new_matches) == ()


def test_component_missing_from_one_side_has_no_persistent_cves():
    old_matches = [_match("busybox", "1.36.0", ["CVE-2023-39810"])]
    new_matches = [_match("lighttpd", "1.4.50", ["CVE-2018-19052"])]

    assert diff_vulnerabilities(old_matches, new_matches) == ()


def test_multiple_shared_cves_are_all_reported():
    old_matches = [_match("openssl", "1.1.0", ["CVE-2017-3735", "CVE-2018-0734"])]
    new_matches = [_match("openssl", "1.1.0", ["CVE-2017-3735", "CVE-2018-0734"])]

    persistent = diff_vulnerabilities(old_matches, new_matches)
    assert {item.cve for item in persistent} == {"CVE-2017-3735", "CVE-2018-0734"}
