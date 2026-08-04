//! UB-23 by-name GPIO resolution — contract pins.
//!
//! Covers: name found; name absent → TYPED error (never a fallback);
//! duplicate names (same chip + cross chip) → typed error; explicit
//! legacy-integer fallback taken + surfaced/logged; sysfs/DT fixture
//! enumeration; and pins that NO call site was rewired and NO existing
//! constant changed (the capability landed without touching behaviour).

use std::path::{Path, PathBuf};

use dcentrald_hal::gpio_name_resolver::{
    parse_dt_line_names, resolve_by_name_in, resolve_name_or_legacy_in, snapshot_chips_from_roots,
    GpioChipSnapshot, GpioNameError, ResolvedGpioLine,
};

fn chip(path: &str, base: Option<u32>, names: &[Option<&str>]) -> GpioChipSnapshot {
    GpioChipSnapshot {
        chip_path: PathBuf::from(path),
        base,
        line_names: names.iter().map(|n| n.map(str::to_string)).collect(),
    }
}

// ---------------------------------------------------------------------------
// Name found
// ---------------------------------------------------------------------------

#[test]
fn name_found_returns_chip_offset_and_global() {
    // Names are synthetic test fixtures — deliberately NOT ePIC's line names
    // and NOT claiming to be our units' DT names.
    let snaps = vec![
        chip("/dev/gpiochip0", Some(400), &[None, Some("t_led"), None]),
        chip(
            "/dev/gpiochip1",
            Some(500),
            &[Some("t_plug0"), Some("t_rst0"), None],
        ),
    ];

    let hit = resolve_by_name_in(&snaps, "t_rst0").expect("name must resolve");
    match hit {
        ResolvedGpioLine::ByName {
            chip_path,
            offset,
            global,
        } => {
            assert_eq!(chip_path, PathBuf::from("/dev/gpiochip1"));
            assert_eq!(offset, 1);
            assert_eq!(global, Some(501));
        }
        other => panic!("expected ByName, got {other:?}"),
    }
}

#[test]
fn name_found_without_base_reports_no_global() {
    let snaps = vec![chip("/dev/gpiochip0", None, &[Some("t_detect")])];
    let hit = resolve_by_name_in(&snaps, "t_detect").expect("name must resolve");
    assert_eq!(hit.global(), None);
    assert!(!hit.is_fallback());
}

#[test]
fn name_first_wins_even_when_legacy_integer_is_supplied() {
    // Name-first: when the name exists, the legacy integer must be ignored
    // entirely — including a legacy integer pointing somewhere else.
    let snaps = vec![chip("/dev/gpiochip0", Some(100), &[Some("t_pwr"), None])];
    let hit = resolve_name_or_legacy_in(&snaps, "t_pwr", 437).expect("name must win");
    assert!(!hit.is_fallback());
    assert_eq!(hit.global(), Some(100));
}

// ---------------------------------------------------------------------------
// Name absent → typed error, never a silent fallback
// ---------------------------------------------------------------------------

#[test]
fn absent_name_is_a_typed_error_not_a_fallback() {
    let snaps = vec![chip("/dev/gpiochip0", Some(400), &[Some("t_led"), None])];
    let err = resolve_by_name_in(&snaps, "t_missing").expect_err("must fail closed");
    assert_eq!(
        err,
        GpioNameError::NameNotFound {
            name: "t_missing".to_string(),
            chips_scanned: 1,
        }
    );
}

#[test]
fn empty_name_is_refused_it_would_alias_unnamed_lines() {
    let snaps = vec![chip("/dev/gpiochip0", Some(0), &[None, None])];
    let err = resolve_by_name_in(&snaps, "").expect_err("empty name must be refused");
    assert_eq!(err, GpioNameError::EmptyName);
    // Even with a legacy integer available, "" must not ride the fallback.
    let err = resolve_name_or_legacy_in(&snaps, "", 1).expect_err("empty name must be refused");
    assert_eq!(err, GpioNameError::EmptyName);
}

#[test]
fn unnamed_lines_never_match_any_query() {
    let snaps = vec![chip("/dev/gpiochip0", Some(0), &[None, None, None])];
    let err = resolve_by_name_in(&snaps, "t_anything").expect_err("must fail closed");
    assert!(matches!(err, GpioNameError::NameNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Duplicate names → typed error (same chip and cross chip)
// ---------------------------------------------------------------------------

#[test]
fn duplicate_name_on_one_chip_is_refused() {
    let snaps = vec![chip(
        "/dev/gpiochip0",
        Some(0),
        &[Some("t_dup"), None, Some("t_dup")],
    )];
    let err = resolve_by_name_in(&snaps, "t_dup").expect_err("ambiguity must fail closed");
    match err {
        GpioNameError::DuplicateName {
            name,
            first,
            second,
        } => {
            assert_eq!(name, "t_dup");
            assert_eq!(first, "/dev/gpiochip0:0");
            assert_eq!(second, "/dev/gpiochip0:2");
        }
        other => panic!("expected DuplicateName, got {other:?}"),
    }
}

#[test]
fn duplicate_name_across_chips_is_refused_and_does_not_fall_back() {
    let snaps = vec![
        chip("/dev/gpiochip0", Some(0), &[Some("t_dup")]),
        chip("/dev/gpiochip1", Some(32), &[Some("t_dup")]),
    ];
    // Name-only form refuses.
    assert!(matches!(
        resolve_by_name_in(&snaps, "t_dup"),
        Err(GpioNameError::DuplicateName { .. })
    ));
    // The integer-fallback form must ALSO refuse: falling back would mask the
    // broken DT.
    assert!(matches!(
        resolve_name_or_legacy_in(&snaps, "t_dup", 7),
        Err(GpioNameError::DuplicateName { .. })
    ));
}

// ---------------------------------------------------------------------------
// Explicit legacy-integer fallback: taken, surfaced, logged
// ---------------------------------------------------------------------------

#[test]
fn fallback_is_taken_only_when_name_absent_and_is_loudly_marked() {
    let snaps = vec![chip("/dev/gpiochip0", Some(410), &[None; 100])];
    let hit = resolve_name_or_legacy_in(&snaps, "t_pwr_en", 437).expect("explicit fallback");
    match &hit {
        ResolvedGpioLine::LegacyIntegerFallback {
            global,
            chip_path,
            offset,
            warning,
        } => {
            // The caller's integer is passed through VERBATIM.
            assert_eq!(*global, 437);
            // Chip/offset derived from the base range: 437 - 410 = 27.
            assert_eq!(chip_path.as_deref(), Some(Path::new("/dev/gpiochip0")));
            assert_eq!(*offset, Some(27));
            // The logged message is surfaced on the result and names both the
            // missing name and the fallback integer.
            assert!(warning.contains("t_pwr_en"), "warning: {warning}");
            assert!(warning.contains("gpio437"), "warning: {warning}");
            assert!(
                warning.to_lowercase().contains("fall"),
                "warning must say it is a fallback: {warning}"
            );
        }
        other => panic!("expected LegacyIntegerFallback, got {other:?}"),
    }
    assert!(hit.is_fallback());
    assert_eq!(hit.global(), Some(437));
}

#[test]
fn fallback_without_base_info_passes_integer_through_unlocated() {
    // No chip publishes a base: absence of the number can't be proven, so the
    // explicit integer passes through with no chip/offset claim.
    let snaps = vec![chip("/dev/gpiochip0", None, &[None, None])];
    let hit = resolve_name_or_legacy_in(&snaps, "t_pwr_en", 907).expect("explicit fallback");
    match hit {
        ResolvedGpioLine::LegacyIntegerFallback {
            global,
            chip_path,
            offset,
            ..
        } => {
            assert_eq!(global, 907);
            assert_eq!(chip_path, None);
            assert_eq!(offset, None);
        }
        other => panic!("expected LegacyIntegerFallback, got {other:?}"),
    }
}

#[test]
fn fallback_fails_closed_when_integer_provably_cannot_exist() {
    // Every chip publishes base+ngpio and none contains gpio9999 → typed
    // error, not a dead number handed back.
    let snaps = vec![
        chip("/dev/gpiochip0", Some(0), &[None; 32]),
        chip("/dev/gpiochip1", Some(400), &[None; 100]),
    ];
    let err = resolve_name_or_legacy_in(&snaps, "t_pwr_en", 9999).expect_err("must fail closed");
    match err {
        GpioNameError::FallbackUnresolvable {
            name, legacy_gpio, ..
        } => {
            assert_eq!(name, "t_pwr_en");
            assert_eq!(legacy_gpio, 9999);
        }
        other => panic!("expected FallbackUnresolvable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// DT blob parsing + sysfs fixture enumeration
// ---------------------------------------------------------------------------

#[test]
fn dt_line_names_blob_parses_nul_separated_with_unnamed_gaps() {
    // "alpha\0\0beta\0" → [Some(alpha), None(unnamed), Some(beta)] padded to 5.
    let raw = b"alpha\0\0beta\0";
    let names = parse_dt_line_names(raw, 5);
    assert_eq!(
        names,
        vec![
            Some("alpha".to_string()),
            None,
            Some("beta".to_string()),
            None,
            None,
        ]
    );
    // Over-long blobs truncate to ngpio.
    let names = parse_dt_line_names(raw, 2);
    assert_eq!(names, vec![Some("alpha".to_string()), None]);
    // Empty property → all unnamed.
    assert_eq!(parse_dt_line_names(b"", 3), vec![None, None, None]);
}

#[test]
fn sysfs_fixture_tree_enumerates_chips_with_dt_names() {
    let tmp = std::env::temp_dir().join(format!(
        "dcent_gpio_name_resolver_test_{}",
        std::process::id()
    ));
    let sysfs = tmp.join("sys_class_gpio");
    let dev = tmp.join("dev");
    let chip0 = sysfs.join("gpiochip0");
    std::fs::create_dir_all(chip0.join("device/of_node")).unwrap();
    std::fs::create_dir_all(&dev).unwrap();
    std::fs::write(chip0.join("base"), "410\n").unwrap();
    std::fs::write(chip0.join("ngpio"), "4\n").unwrap();
    std::fs::write(
        chip0.join("device/of_node/gpio-line-names"),
        b"t_a\0\0t_c\0",
    )
    .unwrap();
    // NOTE: no <dev>/gpiochip0 chardev — forces the sysfs/DT fallback path.

    let snaps = snapshot_chips_from_roots(&sysfs, &dev);
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].base, Some(410));
    assert_eq!(
        snaps[0].line_names,
        vec![Some("t_a".to_string()), None, Some("t_c".to_string()), None]
    );

    // End-to-end over the fixture: by-name hit resolves to global 412,
    // absent name + explicit legacy integer rides the marked fallback.
    let hit = resolve_by_name_in(&snaps, "t_c").unwrap();
    assert_eq!(hit.global(), Some(412));
    let fb = resolve_name_or_legacy_in(&snaps, "t_missing", 411).unwrap();
    assert!(fb.is_fallback());
    assert_eq!(fb.global(), Some(411));

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn missing_sysfs_root_yields_no_chips_and_name_lookup_fails_closed() {
    let snaps = snapshot_chips_from_roots(
        Path::new("/nonexistent/dcent/sysfs"),
        Path::new("/nonexistent/dcent/dev"),
    );
    assert!(snaps.is_empty());
    assert!(matches!(
        resolve_by_name_in(&snaps, "t_anything"),
        Err(GpioNameError::NameNotFound {
            chips_scanned: 0,
            ..
        })
    ));
    // With zero chips, absence can't be proven — the EXPLICIT legacy integer
    // still passes through as a marked fallback (callers keep their existing
    // sysfs mechanism), never as a name hit.
    let fb = resolve_name_or_legacy_in(&snaps, "t_anything", 59).unwrap();
    assert!(fb.is_fallback());
    assert_eq!(fb.global(), Some(59));
}

// ---------------------------------------------------------------------------
// Pins: capability landed WITHOUT rewiring any call site or changing behaviour
// ---------------------------------------------------------------------------

/// No production source outside the new module (and the lib.rs declaration)
/// references the resolver: proof that this change landed the CAPABILITY
/// only and rewired zero call sites. The migration pass that flips call
/// sites must consciously delete/adjust this pin.
#[test]
fn no_call_site_is_rewired_yet() {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![src_root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("walk src/") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path
                .strip_prefix(&src_root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            // The module itself and the lib.rs declaration are the only
            // permitted references.
            if rel == "gpio_name_resolver.rs" || rel == "lib.rs" {
                continue;
            }
            // libgpiod.rs may MENTION the resolver in a doc pointer, but must
            // not call into it (no `gpio_name_resolver::` path usage).
            let contents = std::fs::read_to_string(&path).expect("read source file");
            if contents.contains("gpio_name_resolver::") {
                offenders.push(rel.to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "call sites unexpectedly rewired onto gpio_name_resolver (must be one \
         deliberate reviewed migration pass, per module docs): {offenders:?}"
    );
}

/// The existing integer-addressed GPIO surface is byte-for-byte unchanged:
/// gpio.rs AXI masks/layouts still decode exactly as before this change.
#[test]
fn existing_gpio_constants_and_layouts_are_unchanged() {
    use dcentrald_hal::gpio;
    assert_eq!(gpio::GPIO_INPUT_BASE, 0x4120_0000);
    assert_eq!(gpio::GPIO_OUTPUT_BASE, 0x4121_0000);
    assert_eq!(gpio::PLUG_DETECT_J6, 1 << 5);
    assert_eq!(gpio::PLUG_DETECT_J7, 1 << 6);
    assert_eq!(gpio::PLUG_DETECT_J8, 1 << 7);
    assert_eq!(gpio::BOARD_RESET_J6, 1 << 9);
    assert_eq!(gpio::BOARD_RESET_J7, 1 << 10);
    assert_eq!(gpio::BOARD_RESET_J8, 1 << 11);
    assert_eq!(gpio::BOARD_RESET_ALL, 0x0E00);
    // Aliases preserved for daemon.rs.
    assert_eq!(gpio::BOARD_ENABLE_ALL, gpio::BOARD_RESET_ALL);
}

/// Safety-adjacent integer constants this task was explicitly forbidden from
/// touching remain exactly as shipped (addressing capability must not carry a
/// polarity or renumbering opinion).
#[test]
fn forbidden_constants_untouched() {
    // gpio907 (AM2 PWR_CONTROL) — polarity constant deliberately kept; the
    // resolver must not have moved or re-derived these numbers.
    assert_eq!(dcentrald_hal::board_control::AM2_PSU_ENABLE_GPIO, 907);
    assert_eq!(dcentrald_hal::psu_apw12_plus::GPIO_PSU_ENABLE, 907);
    // BeagleBone board-enable stays 59.
    assert_eq!(
        dcentrald_hal::platform::beaglebone::GPIO_BOARD_ENABLE_V2_0,
        59
    );
}

/// The resolver's public result type carries NO polarity notion — resolving
/// a line answers only WHERE it is. (Compile-time shape pin: constructing
/// both variants requires no active-low/high input.)
#[test]
fn resolver_result_carries_no_polarity_semantics() {
    let by_name = ResolvedGpioLine::ByName {
        chip_path: PathBuf::from("/dev/gpiochip0"),
        offset: 3,
        global: Some(413),
    };
    let fallback = ResolvedGpioLine::LegacyIntegerFallback {
        global: 437,
        chip_path: None,
        offset: None,
        warning: "test".to_string(),
    };
    // Display must clearly distinguish a fallback so logs can never present
    // it as a name hit.
    assert!(format!("{by_name}").contains("gpio413"));
    assert!(format!("{fallback}").contains("LEGACY INTEGER FALLBACK"));
}
