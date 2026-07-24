# Firmware samples

## OpenWrt 23.05.5 ath79/tiny

`openwrt-23.05.5-ath79-tiny-engenius-eap350-v1-initramfs-kernel.bin` is an
unmodified public OpenWrt firmware image for the EnGenius EAP350 v1.

- Source:
  <https://downloads.openwrt.org/releases/23.05.5/targets/ath79/tiny/>
- Size: 5,043,932 bytes
- SHA-256:
  `3338f67cd3e34331482372a5cadf8e62a25f627447c2b6e2481d040a6df970de`
- Release date: 2024-09-24
- License: OpenWrt is distributed under GPL-2.0; individual packages retain
  their upstream licenses.

The adjacent `openwrt-23.05.5-ath79-tiny.manifest` is the unmodified official
target package manifest (SHA-256
`d6d8c29d14911ba988883d9772052a58defedd271ae15afea93b74c91a01a694`).
The JSON adapter uses this build inventory as a deterministic fallback when
native `binwalk`/SquashFS extraction is unavailable, which keeps the Windows
integration test offline and reproducible.
