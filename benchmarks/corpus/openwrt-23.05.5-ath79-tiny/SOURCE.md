# Provenance

- **Origin**: OpenWrt 23.05.5, target `ath79/tiny`, EnGenius EAP350 v1 build.
  Same release documented in `samples/README.md` (source URL and SHA-256 of
  the `.bin` and `.manifest` there).
- **Ground truth source**: `samples/openwrt-23.05.5-ath79-tiny.manifest`,
  the unmodified official OpenWrt build manifest — 135 `package - version`
  lines, produced by OpenWrt's own build system, not authored for this
  benchmark.
- **How `rootfs/` was derived**: `generate.py` in this directory converts
  each manifest line into an opkg control stanza
  (`Package: / Version: / Status: install user installed`), which is the
  file format `detectors/packages.py` actually parses
  (`usr/lib/opkg/status`). This is a reshaping of real data into the
  on-device format, not a hand-picked or fabricated package list.
- **What this is not**: an extraction of the real `.bin`. That would need
  `binwalk`/`unsquashfs`, which are not installed in the environment this
  corpus entry was built in. See `benchmarks/README.md` for exactly what
  this entry does and does not validate.
