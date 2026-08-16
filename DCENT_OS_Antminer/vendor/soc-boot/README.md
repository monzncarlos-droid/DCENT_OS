# vendor/soc-boot — public-safe SoC boot inputs

Place **operator-supplied** (non-redistributable) SoC boot components here when
building signed sysupgrade / SD images. These files are **not** shipped in the
public GitHub mirror.

```
vendor/soc-boot/
  s9/           kernel / dtb / related am1-s9 inputs
  s19j/         kernel.bin, fpga_bitstream.bit (am2 shared)
```

Overrides (preferred in CI/lab):

- `DCENT_EXTRACTIONS_DIR` — am1-s9 package_sysupgrade inputs directory
- `DCENT_VENDOR_SOC_BOOT` — root that contains `s9/`, `s19j/`, …
- `DCENT_AM2_S19J_KERNEL` / `DCENT_AM2_S19J_BITSTREAM` — explicit file paths
- `DCENT_AM2_S19PRO_KERNEL` / `DCENT_AM2_S19PRO_BITSTREAM` — explicit file paths

Private monorepo remains a last-resort lab fallback
only and must not be required for a clean public clone.
