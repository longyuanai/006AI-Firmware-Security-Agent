# Detection accuracy benchmark

Before this harness existed, tech-spec section 9 stated four accuracy
targets with no corpus and no scoring code behind any of them. This is the
first pass at measuring one of the four honestly, plus what would be needed
to measure the rest.

## What is measured, and what is not

| tech-spec §9 metric | Measured here? |
|---|---|
| Component identification accuracy | **Partially.** `detectors/packages.py` (opkg/dpkg status parsing) is measured against one real, 135-package OpenWrt build manifest. `detectors/binary.py` and `detectors/osrelease.py` are exercised only by the small hand-built self-check fixture, which is not independent ground truth (see below) — their real-world accuracy remains unmeasured. |
| CVE match recall | **Not measured.** Would require either live NVD access or a locally synced cache to validate against, and this environment has neither (`services.nvd.nist.gov` returns 403 through the sandbox's outbound proxy, and `cve-db sync` needs the same access). |
| PRisk ranking agreement with human judgement | **Not measured.** Needs a human-labeled priority ranking; no such labels exist yet. |
| Report generation time | **Partially.** `run.py --time-scan` times component detection + mock CVE matching + PRisk scoring end to end. It does **not** include binwalk/unsquashfs extraction time, because binwalk is not installed in this environment (`BinwalkRunner().is_available()` returns `False` here) — this harness cannot exercise that step at all right now.

Do not read a "done" marker in this file, in the harness's output, or in
tech-spec section 9 as license to treat these numbers as validated beyond
the scope stated above. If you extend the corpus and the numbers move,
update tech-spec section 9 to match — do not leave a stale claim in place.

## Corpus format

```
benchmarks/corpus/<name>/
  rootfs/           # a directory ai_firmware_agent.detectors.detect_components() can run against
  expected.yml      # ground truth: {"components": [{"name": ..., "version": ...}, ...]}
  SOURCE.md         # provenance for real-world entries: origin URL, SHA-256, how rootfs/ was derived
```

`expected.yml` versions are the *normalized* (CVE-matchable) form — the same
transformation `detectors/packages.py:upstream_version()` applies — not the
raw packaging string, since that is what a consumer of `Component.version`
actually acts on.

## Corpus entries

- **`harness-selfcheck/`** — four components, hand-built, one of each outcome
  class (correct match, version mismatch, missed detection, spurious
  detection). This is **not** an accuracy benchmark: the fixture and its
  expected values were written by the same person in the same sitting, so a
  perfect score would prove nothing about real-world detection. Its only job
  is to prove the scoring arithmetic in `run.py` is correct, which is what
  `tests/test_benchmark_harness.py` checks it against by hand-computed
  fractions.

- **`openwrt-23.05.5-ath79-tiny/`** — derived from
  `samples/openwrt-23.05.5-ath79-tiny.manifest`, the unmodified official
  OpenWrt build manifest already checked into this repository (source URL
  and SHA-256 in `samples/README.md`). `generate.py` converts its 135
  `package - version` lines into an opkg `status` file and a matching
  `expected.yml`. This is genuine external data — OpenWrt's build system
  produced it, not this benchmark — so it is a real test of the opkg
  stanza parser and `upstream_version()` against 135 real, varied version
  strings (git-hash-based dates, multi-dash revisions, bare integers).

  What it does **not** validate: the rootfs here is *synthesized* from the
  manifest, not extracted from the real `.bin` with binwalk (which is
  unavailable in this environment), so it contains nothing that isn't
  already in the manifest by construction — no false positives are
  structurally possible here, which is a property of this corpus entry, not
  a claim about the detector in general. It also does not exercise
  `detectors/binary.py` or `detectors/osrelease.py` at all, since the
  synthesized rootfs carries no ELF files or `/etc/os-release`.

## Running it

```bash
poetry run python benchmarks/run.py
poetry run python benchmarks/run.py --time-scan
```

No network access is used or required; CVE matching in `--time-scan` uses
`--cve-source mock` deliberately, for the same reason `cli._sbom_vulnerabilities`
defaults away from `nvd`: this harness must stay runnable offline.
