param(
    [string]$BuildRoot,
    [string]$DistRoot,
    [switch]$IncludeInternalTargets
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
    $env:SOURCE_DATE_EPOCH = (& git -C (Join-Path $PSScriptRoot "..") log -1 --format=%ct -- .).Trim()
}
if ($env:SOURCE_DATE_EPOCH -notmatch '^\d+$') {
    throw "Unable to derive numeric SOURCE_DATE_EPOCH"
}

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

$matrixPath = Join-Path $root "esp-targets.json"
$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
$targets = @($matrix.targets | Where-Object { $_.release_scope -eq "public" })
if ($IncludeInternalTargets) {
    $targets += @($matrix.targets | Where-Object { $_.release_scope -eq "internal" })
}

Push-Location $root
try {
    foreach ($target in $targets) {
        $cargoTargetDir = Join-Path $BuildRoot $target.board_target
        $releaseDir = Join-Path $cargoTargetDir "xtensa-esp32s3-espidf\release"
        $is16Mb = $target.flash_layout -eq "n16r8"
        $partitionsCsv = Join-Path $root $(if ($is16Mb) { "partitions-16mb.csv" } else { "partitions.csv" })
        $env:ESP_IDF_SDKCONFIG_DEFAULTS = if ($is16Mb) {
            "sdkconfig.defaults;sdkconfig.defaults.16mb"
        } else {
            "sdkconfig.defaults"
        }

        Write-Host "==> Building $($target.board_target) ($($target.feature), $($target.flash_layout))"
        $env:CARGO_TARGET_DIR = $cargoTargetDir
        cargo build --locked --release -p dcentaxe --no-default-features --features $target.feature
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed for $($target.board_target)"
        }

        Write-Host "==> Packaging $($target.board_target)"
        & (Join-Path $PSScriptRoot "package-firmware.ps1") `
            -TargetDir $releaseDir `
            -BoardTarget $target.board_target `
            -OutDir (Join-Path $DistRoot $target.board_target) `
            -PartitionsCsv $partitionsCsv
    }
}
finally {
    Remove-Item Env:ESP_IDF_SDKCONFIG_DEFAULTS -ErrorAction SilentlyContinue
    Pop-Location
}
