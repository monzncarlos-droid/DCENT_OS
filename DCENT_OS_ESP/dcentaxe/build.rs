// DCENT_axe build script
// Propagates ESP-IDF linker arguments from esp-idf-sys to this binary crate

fn main() {
    embuild::espidf::sysenv::output();

    // Declare the ESP-IDF sdkconfig cfg the `eth-w5500` feature branches on
    // (`eth_w5500.rs`), so rustc's check-cfg lint knows it is expected even on
    // builds where the sdkconfig overlay (and thus the propagated cfg) is
    // absent. Zero behavioral impact — it only silences unexpected_cfgs.
    println!("cargo:rustc-check-cfg=cfg(esp_idf_eth_spi_ethernet_w5500)");

    if std::env::var_os("DCENT_ENFORCE_SIGNED_OTA").is_some()
        && std::env::var_os("DCENT_OTA_PUBLIC_KEY_HEX").is_none()
    {
        panic!("DCENT_ENFORCE_SIGNED_OTA is set but DCENT_OTA_PUBLIC_KEY_HEX is missing");
    }

    // ── Git hash + build epoch stamps ──
    // Surfaced via /api/system/info so operators know exactly what commit is
    // on a miner — essential for OTA audit trails and field debugging.
    let git_commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    let git_hash: String = git_commit.chars().take(10).collect();
    println!("cargo:rustc-env=DCENTAXE_GIT_HASH={git_hash}");

    let git_dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    println!(
        "cargo:rustc-env=DCENTAXE_GIT_DIRTY={}",
        if git_dirty { "1" } else { "0" }
    );

    // Release/gauntlet builds set SOURCE_DATE_EPOCH to the source commit time.
    // This keeps the embedded build stamp (and therefore the signed update
    // payload) byte-stable across an exact-candidate rebuild. Interactive
    // developer builds retain the useful wall-clock fallback.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|_| {
            panic!("SOURCE_DATE_EPOCH must be an unsigned integer, got {value:?}")
        }),
        Err(std::env::VarError::NotPresent) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("SOURCE_DATE_EPOCH must be valid Unicode")
        }
    };
    println!("cargo:rustc-env=DCENTAXE_BUILD_EPOCH={epoch}");

    // Re-run if git state changes.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let bitaxe_touch = std::env::var_os("CARGO_FEATURE_BITAXE_TOUCH").is_some();
    let bitaxe_gt_touch = std::env::var_os("CARGO_FEATURE_BITAXE_GT_TOUCH").is_some();
    let mut selected_targets: Vec<&'static str> = Vec::new();

    if std::env::var_os("CARGO_FEATURE_BITAXE_MAX").is_some() {
        selected_targets.push("bitaxe-max");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_ULTRA").is_some() {
        selected_targets.push("bitaxe-ultra");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_SUPRA").is_some() {
        selected_targets.push("bitaxe-supra");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_GAMMA").is_some() && !bitaxe_touch {
        selected_targets.push("bitaxe-gamma");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_GAMMA_DUO").is_some() {
        selected_targets.push("bitaxe-gamma-duo");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_GT").is_some() && !bitaxe_gt_touch {
        selected_targets.push("bitaxe-gt");
    }
    if bitaxe_touch {
        selected_targets.push("bitaxe-touch");
    }
    if bitaxe_gt_touch {
        selected_targets.push("bitaxe-gt-touch");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_HEX_ULTRA").is_some() {
        selected_targets.push("bitaxe-hex-ultra");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_HEX_SUPRA").is_some() {
        selected_targets.push("bitaxe-hex-supra");
    }
    if std::env::var_os("CARGO_FEATURE_NERDNOS").is_some() {
        selected_targets.push("nerdnos");
    }
    if std::env::var_os("CARGO_FEATURE_NERDAXE").is_some() {
        selected_targets.push("nerdaxe");
    }
    if std::env::var_os("CARGO_FEATURE_NERDAXE_GAMMA").is_some() {
        selected_targets.push("nerdaxe-gamma");
    }
    if std::env::var_os("CARGO_FEATURE_NERDQAXE_PLUS").is_some() {
        selected_targets.push("nerdqaxe-plus");
    }
    if std::env::var_os("CARGO_FEATURE_NERDQAXE_PP").is_some() {
        selected_targets.push("nerdqaxe-pp");
    }
    if std::env::var_os("CARGO_FEATURE_NERDOCTAXE_PLUS").is_some() {
        selected_targets.push("nerdoctaxe-plus");
    }
    if std::env::var_os("CARGO_FEATURE_NERDOCTAXE_GAMMA").is_some() {
        selected_targets.push("nerdoctaxe-gamma");
    }
    if std::env::var_os("CARGO_FEATURE_DCENT_AXE_BM1397").is_some() {
        selected_targets.push("dcent-axe-bm1397");
    }
    if std::env::var_os("CARGO_FEATURE_DCENT_AXE_QUAD_BM1397").is_some() {
        selected_targets.push("dcent-axe-quad-bm1397");
    }
    if std::env::var_os("CARGO_FEATURE_DCENT_AXE_HEX_BM1397").is_some() {
        selected_targets.push("dcent-axe-hex-bm1397");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_BC01").is_some() {
        selected_targets.push("hammer-bc01");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_BC01_PRO").is_some() {
        selected_targets.push("hammer-bc01-pro");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_BC02").is_some() {
        selected_targets.push("hammer-bc02");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_BC04").is_some() {
        selected_targets.push("hammer-bc04");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_DC02").is_some() {
        selected_targets.push("hammer-dc02");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_DC04").is_some() {
        selected_targets.push("hammer-dc04");
    }
    if std::env::var_os("CARGO_FEATURE_HAMMER_DC06").is_some() {
        selected_targets.push("hammer-dc06");
    }
    // Lucky Miner LVxx (EXPERIMENTAL). Without these arms a lucky-* build hits
    // the `selected_targets.len() != 1` panic below (0 targets) — loud, but
    // the arms are still required for the SKU to build at all.
    if std::env::var_os("CARGO_FEATURE_LUCKY_LV06").is_some() {
        selected_targets.push("lucky-lv06");
    }
    if std::env::var_os("CARGO_FEATURE_LUCKY_LV07").is_some() {
        selected_targets.push("lucky-lv07");
    }
    if std::env::var_os("CARGO_FEATURE_LUCKY_LV08").is_some() {
        selected_targets.push("lucky-lv08");
    }
    if std::env::var_os("CARGO_FEATURE_BITFORGE_NANO").is_some() {
        selected_targets.push("bitforge-nano");
    }
    if std::env::var_os("CARGO_FEATURE_BITAXE_NAJA").is_some() {
        selected_targets.push("bitaxe-naja");
    }
    // Nerd multi-ASIC + Q-series (EXPERIMENTAL). Same note as the Lucky arms:
    // without these, a `--features nerdqx` build fails the len()!=1 panic below
    // with 0 targets — loud, but the arm is what makes the SKU buildable.
    if std::env::var_os("CARGO_FEATURE_NERDQX").is_some() {
        selected_targets.push("nerdqx");
    }
    if std::env::var_os("CARGO_FEATURE_NERDHAXE_GAMMA").is_some() {
        selected_targets.push("nerdhaxe-gamma");
    }
    if std::env::var_os("CARGO_FEATURE_NERDEKO").is_some() {
        selected_targets.push("nerdeko");
    }
    if std::env::var_os("CARGO_FEATURE_Q1370").is_some() {
        selected_targets.push("q1370");
    }
    if std::env::var_os("CARGO_FEATURE_Q1373").is_some() {
        selected_targets.push("q1373");
    }

    if selected_targets.len() != 1 {
        panic!(
            "exactly one DCENT_axe board feature must be enabled; got {}: {}",
            selected_targets.len(),
            selected_targets.join(", ")
        );
    }
    let board_target = selected_targets[0];

    println!("cargo:rustc-env=DCENTAXE_BOARD_TARGET={board_target}");
    emit_registry_metadata(board_target, &git_commit, git_dirty, epoch);
}

/// Bind the compiled image to the same ownership/evidence row used by the
/// build matrix, packagers, verifier, and production gauntlet.
///
/// This intentionally fails the build if the registry is absent or incomplete:
/// a firmware image whose runtime API cannot state its install/runtime policy is
/// not a releasable artifact. `scripts/target_matrix.py validate` performs the
/// wider cross-file validation; this is the last-mile, compile-time binding.
fn emit_registry_metadata(
    board_target: &str,
    git_commit: &str,
    git_dirty: bool,
    source_date_epoch: u64,
) {
    use serde_json::Value;
    use std::path::PathBuf;

    let registry_path = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    )
    .join("../esp-targets.json");
    println!("cargo:rerun-if-changed={}", registry_path.display());

    let raw = std::fs::read_to_string(&registry_path).unwrap_or_else(|err| {
        panic!(
            "failed to read ESP target registry {}: {err}",
            registry_path.display()
        )
    });
    let registry: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!(
            "failed to parse ESP target registry {}: {err}",
            registry_path.display()
        )
    });
    let targets = registry
        .get("targets")
        .and_then(Value::as_array)
        .expect("esp-targets.json targets must be an array");
    let registered_row = targets
        .iter()
        .find(|row| row.get("board_target").and_then(Value::as_str) == Some(board_target))
        .unwrap_or_else(|| panic!("board target {board_target} is missing from esp-targets.json"));

    // A qualification build may compile the exact final production row before
    // its live receipt exists. It is deliberately opt-in, source/epoch pinned,
    // and non-publishable. The descriptor is NOT compiled into the payload, so
    // the retained candidate bytes remain identical when that exact row is
    // admitted to esp-targets.json after hardware proof.
    println!("cargo:rerun-if-env-changed=DCENTAXE_PROMOTION_CANDIDATE_PATH");
    println!("cargo:rerun-if-env-changed=DCENTAXE_PROMOTION_CANDIDATE_VALIDATED");
    println!("cargo:rerun-if-env-changed=DCENTAXE_PROMOTION_CANDIDATE_CONFIRM");
    let candidate = std::env::var_os("DCENTAXE_PROMOTION_CANDIDATE_PATH").map(|path| {
        let path = PathBuf::from(path);
        println!("cargo:rerun-if-changed={}", path.display());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read promotion candidate {}: {err}",
                path.display()
            )
        });
        serde_json::from_str::<Value>(&raw).unwrap_or_else(|err| {
            panic!(
                "failed to parse promotion candidate {}: {err}",
                path.display()
            )
        })
    });
    let row = if let Some(candidate) = candidate.as_ref() {
        let required_string = |key: &str| {
            candidate
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("promotion candidate is missing string field {key}"))
        };
        if candidate.get("schema").and_then(Value::as_u64) != Some(1)
            || required_string("authority") != "unreleased-exact-binary-promotion-candidate"
            || required_string("disposition") != "qualification-only-not-publishable"
            || candidate.get("publishable").and_then(Value::as_bool) != Some(false)
        {
            panic!("promotion candidate does not carry the qualification-only authority contract");
        }
        let candidate_id = required_string("candidate_id");
        if std::env::var("DCENTAXE_PROMOTION_CANDIDATE_VALIDATED").as_deref() != Ok(candidate_id) {
            panic!(
                "promotion candidate must first pass promotion_candidate.py validate --for-build"
            );
        }
        let expected_confirmation = format!("build-{board_target}");
        if std::env::var("DCENTAXE_PROMOTION_CANDIDATE_CONFIRM").as_deref()
            != Ok(expected_confirmation.as_str())
        {
            panic!(
                "set DCENTAXE_PROMOTION_CANDIDATE_CONFIRM=build-{board_target} for this qualification build"
            );
        }
        if required_string("board_target") != board_target {
            panic!("promotion candidate board target does not match the selected Cargo feature");
        }
        let source = candidate
            .get("source")
            .and_then(Value::as_object)
            .expect("promotion candidate source must be an object");
        if source.get("git_dirty").and_then(Value::as_bool) != Some(false)
            || git_commit == "unknown"
            || git_dirty
        {
            panic!("promotion candidate requires a clean, known source checkout");
        }
        if source.get("git_commit").and_then(Value::as_str) != Some(git_commit) {
            panic!("promotion candidate git commit does not match this checkout");
        }
        let expected_epoch = source
            .get("source_date_epoch")
            .and_then(Value::as_str)
            .expect("promotion candidate source_date_epoch must be a string")
            .parse::<u64>()
            .expect("promotion candidate source_date_epoch must be numeric");
        if expected_epoch != source_date_epoch {
            panic!("promotion candidate SOURCE_DATE_EPOCH does not match this build");
        }
        if source.get("firmware_version").and_then(Value::as_str) != Some(env!("CARGO_PKG_VERSION"))
        {
            panic!("promotion candidate firmware version does not match this build");
        }
        let proposed = candidate
            .get("registry_row")
            .and_then(Value::as_object)
            .expect("promotion candidate registry_row must be an object");
        for key in [
            "feature",
            "board_target",
            "device_model",
            "model_variant",
            "hardware_family",
            "asic",
            "chip_count",
            "flash_layout",
        ] {
            if proposed.get(key) != registered_row.get(key) {
                panic!("promotion candidate changes immutable hardware field {key}");
            }
        }
        for (key, expected) in [
            ("support_tier", "production"),
            ("evidence_level", "sustained-soak"),
            ("runtime_mode", "mining"),
            ("install_policy", "production"),
            ("release_scope", "public"),
            ("package_policy", "public"),
        ] {
            if proposed.get(key).and_then(Value::as_str) != Some(expected) {
                panic!("promotion candidate requires {key}={expected}");
            }
        }
        if !matches!(
            proposed.get("blockers").and_then(Value::as_array),
            Some(items) if items.is_empty()
        ) {
            panic!("promotion candidate requires an empty blockers array");
        }
        candidate
            .get("registry_row")
            .expect("promotion candidate registry_row exists")
    } else {
        registered_row
    };

    let required = |key: &str| -> &str {
        let value = row
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("registry row {board_target} is missing string field {key}"));
        if value.is_empty() || value.contains(['\r', '\n']) {
            panic!("registry row {board_target} has an invalid {key}");
        }
        value
    };

    let feature = required("feature");
    let feature_env = format!(
        "CARGO_FEATURE_{}",
        feature.replace('-', "_").to_ascii_uppercase()
    );
    if std::env::var_os(&feature_env).is_none() {
        panic!(
            "registry row {board_target} names feature {feature}, but {feature_env} is not enabled"
        );
    }

    for (env_name, key) in [
        ("DCENTAXE_DEVICE_MODEL", "device_model"),
        ("DCENTAXE_HARDWARE_FAMILY", "hardware_family"),
        ("DCENTAXE_RELEASE_SCOPE", "release_scope"),
        ("DCENTAXE_SUPPORT_TIER", "support_tier"),
        ("DCENTAXE_EVIDENCE_LEVEL", "evidence_level"),
        ("DCENTAXE_RUNTIME_MODE", "runtime_mode"),
        ("DCENTAXE_INSTALL_POLICY", "install_policy"),
        ("DCENTAXE_PACKAGE_POLICY", "package_policy"),
        ("DCENTAXE_FLASH_LAYOUT", "flash_layout"),
    ] {
        println!("cargo:rustc-env={env_name}={}", required(key));
    }
    if let Some(receipt_id) = row.get("promotion_receipt_id").and_then(Value::as_str) {
        if receipt_id.is_empty() || receipt_id.contains(['\r', '\n']) {
            panic!("registry row {board_target} has an invalid promotion_receipt_id");
        }
        println!("cargo:rustc-env=DCENTAXE_PROMOTION_RECEIPT_ID={receipt_id}");
    }

    let blockers = row
        .get("blockers")
        .and_then(Value::as_array)
        .expect("registry blockers must be an array");
    if blockers.iter().any(|item| item.as_str().is_none()) {
        panic!("registry row {board_target} blockers must all be strings");
    }
    let blockers_json = serde_json::to_string(blockers)
        .expect("registry blockers must serialize as a compact JSON array");
    println!("cargo:rustc-env=DCENTAXE_PRODUCTION_BLOCKERS_JSON={blockers_json}");
}
