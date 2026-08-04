param(
    [string]$BuildRoot,
    [string]$DistRoot,
    [switch]$IncludeInternalTargets
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Join-Path $PSScriptRoot ".."
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path $root "build-matrix"
}
if ([string]::IsNullOrWhiteSpace($DistRoot)) {
    $DistRoot = Join-Path $root "dist"
}

if ([string]::IsNullOrWhiteSpace($env:CC_xtensa_esp32s3_espidf)) {
    $env:CC_xtensa_esp32s3_espidf = "xtensa-esp32s3-elf-gcc"
}

Push-Location $root

$publicTargets = @(
    @{ Feature = "bitaxe-max"; BoardTarget = "bitaxe-max" },
    @{ Feature = "bitaxe-ultra"; BoardTarget = "bitaxe-ultra" },
    @{ Feature = "bitaxe-supra"; BoardTarget = "bitaxe-supra" },
    @{ Feature = "bitaxe-gamma"; BoardTarget = "bitaxe-gamma" },
    @{ Feature = "bitaxe-hex-ultra"; BoardTarget = "bitaxe-hex-ultra" },
    @{ Feature = "bitaxe-hex-supra"; BoardTarget = "bitaxe-hex-supra" }
)

$internalTargets = @(
    @{ Feature = "bitaxe-gamma-duo"; BoardTarget = "bitaxe-gamma-duo" },
    @{ Feature = "bitaxe-gt"; BoardTarget = "bitaxe-gt" },
    @{ Feature = "bitaxe-touch"; BoardTarget = "bitaxe-touch" },
    @{ Feature = "bitaxe-gt-touch"; BoardTarget = "bitaxe-gt-touch" },
    @{ Feature = "nerdnos"; BoardTarget = "nerdnos" },
    @{ Feature = "nerdaxe"; BoardTarget = "nerdaxe" },
    @{ Feature = "nerdaxe-gamma"; BoardTarget = "nerdaxe-gamma" },
    @{ Feature = "nerdqaxe-plus"; BoardTarget = "nerdqaxe-plus" },
    @{ Feature = "nerdqaxe-pp"; BoardTarget = "nerdqaxe-pp" },
    @{ Feature = "nerdoctaxe-plus"; BoardTarget = "nerdoctaxe-plus" },
    @{ Feature = "nerdoctaxe-gamma"; BoardTarget = "nerdoctaxe-gamma" },
    # The rest of the Nerd multi-ASIC line + the Q-series (EXPERIMENTAL).
    @{ Feature = "nerdqx"; BoardTarget = "nerdqx" },
    @{ Feature = "nerdhaxe-gamma"; BoardTarget = "nerdhaxe-gamma" },
    @{ Feature = "nerdeko"; BoardTarget = "nerdeko" },
    @{ Feature = "q1370"; BoardTarget = "q1370" },
    @{ Feature = "q1373"; BoardTarget = "q1373" },
    # DCENT_axe targets (drift fix: build-matrix.sh already carried these).
    @{ Feature = "dcent-axe-bm1397"; BoardTarget = "dcent-axe-bm1397" },
    @{ Feature = "dcent-axe-quad-bm1397"; BoardTarget = "dcent-axe-quad-bm1397" },
    @{ Feature = "dcent-axe-hex-bm1397"; BoardTarget = "dcent-axe-hex-bm1397" },
    # Hammer BC0x (EXPERIMENTAL): 16 MB (N16R8) flash — shared 16 MB layout.
    @{ Feature = "hammer-bc01"; BoardTarget = "hammer-bc01"; Flash16Mb = $true },
    @{ Feature = "hammer-bc01-pro"; BoardTarget = "hammer-bc01-pro"; Flash16Mb = $true },
    @{ Feature = "hammer-bc02"; BoardTarget = "hammer-bc02"; Flash16Mb = $true },
    @{ Feature = "hammer-bc04"; BoardTarget = "hammer-bc04"; Flash16Mb = $true },
    # Hammer DC0x (EXPERIMENTAL, Scrypt) — same 16 MB flash geometry.
    @{ Feature = "hammer-dc02"; BoardTarget = "hammer-dc02"; Flash16Mb = $true },
    @{ Feature = "hammer-dc04"; BoardTarget = "hammer-dc04"; Flash16Mb = $true },
    @{ Feature = "hammer-dc06"; BoardTarget = "hammer-dc06"; Flash16Mb = $true },
    # Lucky Miner LVxx (EXPERIMENTAL) — ESP32-S3 N16R8, same 16 MB geometry.
    # No Lucky hardware is on any bench: these images are host-built only and
    # have never been flashed to, or run on, a Lucky unit.
    @{ Feature = "lucky-lv06"; BoardTarget = "lucky-lv06"; Flash16Mb = $true },
    @{ Feature = "lucky-lv07"; BoardTarget = "lucky-lv07"; Flash16Mb = $true },
    @{ Feature = "lucky-lv08"; BoardTarget = "lucky-lv08"; Flash16Mb = $true },
    # BitForge Nano (EXPERIMENTAL) — 16 MB, confirmed from the vendor's own
    # sdkconfig.defaults (`CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y`) and its
    # partitions.csv (4M factory + 3M www + 2x 4M OTA = 16 MB). No BitForge
    # hardware is on any bench: host-built only, never flashed to a unit.
    @{ Feature = "bitforge-nano"; BoardTarget = "bitforge-nano"; Flash16Mb = $true },
    # BitAxe Naja (EXPERIMENTAL) — 16 MB, from the BOM part rather than a
    # vendor sdkconfig: bitaxeorg ships no firmware, and the fitted module is
    # an ESP32-S3-WROOM-1-N16R8 (16 MB flash / 8 MB PSRAM) per ESP32.kicad_sch.
    # Schematic-only board; no Naja hardware exists on any bench.
    @{ Feature = "bitaxe-naja"; BoardTarget = "bitaxe-naja"; Flash16Mb = $true }
)

$targets = $publicTargets
if ($IncludeInternalTargets) {
    $targets += $internalTargets
}

foreach ($target in $targets) {
    $cargoTargetDir = Join-Path $BuildRoot $target.BoardTarget
    $releaseDir = Join-Path $cargoTargetDir "xtensa-esp32s3-espidf\release"

    # 16 MB (N16R8) targets build against the shared 16 MB partition layout;
    # every other target keeps the default sdkconfig/partition staging.
    $is16Mb = $target.ContainsKey("Flash16Mb") -and $target.Flash16Mb
    $partitionsCsv = $null
    if ($is16Mb) {
        $env:ESP_IDF_SDKCONFIG_DEFAULTS = "sdkconfig.defaults;sdkconfig.defaults.16mb"
        # Drift fix (R2 §15.1): this script never passed -PartitionsCsv, so
        # package-firmware.ps1 fell back to the 8 MB partitions.csv and wrote a
        # WRONG ota.slotSize / updateFitsSlot into the manifest for every 16 MB
        # board packaged on Windows. build-matrix.sh always exported it.
        $partitionsCsv = Join-Path $root "partitions-16mb.csv"
    }

    Write-Host "==> Building $($target.BoardTarget) ($($target.Feature))"
    $env:CARGO_TARGET_DIR = $cargoTargetDir
    cargo build --locked --release -p dcentaxe --no-default-features --features $target.Feature

    Write-Host "==> Packaging $($target.BoardTarget)"
    $packageArgs = @{
        TargetDir   = $releaseDir
        BoardTarget = $target.BoardTarget
        OutDir      = (Join-Path $DistRoot $target.BoardTarget)
    }
    if ($partitionsCsv) {
        $packageArgs["PartitionsCsv"] = $partitionsCsv
    }
    & (Join-Path $PSScriptRoot "package-firmware.ps1") @packageArgs

    if ($is16Mb) {
        Remove-Item Env:ESP_IDF_SDKCONFIG_DEFAULTS -ErrorAction SilentlyContinue
    }
}

Pop-Location
