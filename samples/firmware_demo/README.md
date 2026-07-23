# SquashFS firmware demo

`demo-router.squashfs.bin` is a small, redistributable SquashFS 4.0 image
built from `rootfs/`. It exercises the real `unsquashfs` path without
including proprietary vendor firmware.

Rebuild on Linux with:

```bash
mksquashfs rootfs demo-router.squashfs.bin \
  -noappend -comp gzip -all-root -no-xattrs
```
