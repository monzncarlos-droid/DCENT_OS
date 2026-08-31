# K210 boot-route adjudication

This is the executable decision boundary between an admitted exact-unit
boot-policy measurement and route-specific firmware engineering. It ranks all
four A1246 replacement paths without converting a measurement into contact,
debug, flash, install, power, mining, or release authority.

The adjudicator is host-only. It opens no miner endpoint and contains no
network, serial, USB, JTAG, ROM-ISP, GPIO, block-device, flash, programmer, or
power-control transport. It accepts only a boot-policy bundle that verifies
under the two distinct SSHSIG keys pinned by the canonical manifest.

## Decision classes

| Route | Positive prerequisite | Decision meaning |
|---|---|---|
| `native_aes0_flash` | compatible measured load contract, force-decrypt disabled, and a performed signed plaintext probe that booted | measured-compatible engineering route; still not install-ready |
| `rom_isp_sram_bootstrap` | compatible load contract plus accessible, flash-independent, write-capable ROM ISP | eligible for a separately authorized bounded SRAM execution probe |
| `jtag_sram_bootstrap` | compatible load contract plus accessible JTAG with halt and memory-write capability | eligible for a separately authorized program-counter/resume SRAM probe |
| `clean_replacement_controller` | no in-controller route survives | explicit fallback requiring a separate exact controller, connector, signal, power, cooling, recovery, and cutoff contract |

The priority order is native AES0, ROM ISP, JTAG, then replacement controller.
ROM-ISP and JTAG accessibility alone never become deployment proof. The current
boot-policy schema establishes only the prerequisite transport capabilities;
actual SRAM execution, program-counter/resume behavior, and post-probe recovery
remain separate evidence. The replacement-controller result is always
`requires_external_qualification` until its own contract exists.

Every output carries:

- the exact target, unit fingerprint, discovery, recovery, boot-policy, stock
  backup, and flash-policy joins;
- all four route outcomes and machine-readable reason codes;
- the selected *next engineering route* and its evidence class;
- `selected_route_is_deployment_ready: false`;
- a fixed false authority ceiling; and
- a domain-separated SHA-256 over the complete decision.

## Canonical command

After the complete 24-role ceremony and an admitted exact-unit boot-policy bundle:

```powershell
python DCENT_OS_AvalonMiner/scripts/k210_boot_route.py adjudicate `
  --boot-policy-bundle .k210-gauntlet-evidence/boot-policy/a1246-unit-01 `
  --json-out .k210-gauntlet-evidence/boot-route/a1246-unit-01.json `
  --format text
```

The command refuses to run while the manifest's boot-policy operator or witness
anchor is null, when the two principals are not distinct, when a key path or
key ID drifts, when the bundle signature or exact member set fails, or when the
output already exists.

The generated JSON is a deterministic engineering decision record. It is not a
signed replacement-firmware receipt and must not be passed to an installer as
authority.

## Desk verification

```powershell
python DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py
python -m ruff check `
  DCENT_OS_AvalonMiner/scripts/k210_boot_route.py `
  DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py
```

The canonical unpinned manifest intentionally produces:

```text
K210_BOOT_ROUTE_ERROR: boot-policy operator trust anchor is not pinned
```

That is the expected pre-ceremony posture.
