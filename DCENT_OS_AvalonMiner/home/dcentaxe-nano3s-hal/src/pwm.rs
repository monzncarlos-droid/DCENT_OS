// SPDX-License-Identifier: GPL-3.0-or-later
//
// sysfs PWM (`/sys/class/pwm/pwmchipN/`) for K230 Linux fan control.
// Stub for Phase 1 — Nano 3 / 3S use 3 axial fans per
//  §1, but the
// pwmchip number / channel mapping is not yet known. Real implementation
// lands in next plan after live unit probing.
//
// FAIL-CLOSED (Wave 6 R4a): a missing `/sys/class/pwm` tree returns `Err`,
// never an empty `Ok`. Absent fan-control sysfs must never read as "no PWM
// chips, everything fine" — a caller planning fan control has to see the
// failure, not silently proceed fanless.

use std::path::Path;

use crate::HalError;

const PWM_ROOT: &str = "/sys/class/pwm";

/// List `/sys/class/pwm/pwmchip*` chips present on the host.
///
/// Errors:
/// - `HalError::SysfsMissing` when `/sys/class/pwm` does not exist.
/// - `HalError::Io` on any other error opening the pwm root.
///
/// An existing-but-empty pwm class still returns `Ok(vec![])`; callers that
/// need fan authority must treat an empty list as "no PWM available" too.
pub fn list_chips() -> Result<Vec<String>, HalError> {
    list_chips_at(Path::new(PWM_ROOT))
}

/// Testable core of [`list_chips`] with an explicit pwm class root.
pub fn list_chips_at(root: &Path) -> Result<Vec<String>, HalError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HalError::SysfsMissing(root.display().to_string()));
        }
        Err(e) => return Err(HalError::Io(e)),
    };
    for e in entries.flatten() {
        if let Some(name) = e.file_name().to_str() {
            if name.starts_with("pwmchip") {
                out.push(format!("{}/{}", root.display(), name));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::list_chips_at;
    use crate::HalError;

    #[test]
    fn missing_pwm_root_is_an_error_not_an_empty_ok() {
        let dir = std::env::temp_dir().join(format!(
            "dcentaxe-nano3s-hal-pwm-missing-{}",
            std::process::id()
        ));
        // Deliberately never created.
        let err = list_chips_at(&dir).expect_err("missing sysfs must be Err");
        match err {
            HalError::SysfsMissing(p) => assert!(p.contains("dcentaxe-nano3s-hal-pwm-missing")),
            other => panic!("expected SysfsMissing, got: {other:?}"),
        }
    }

    #[test]
    fn present_pwm_root_lists_pwmchips_only() {
        let dir = std::env::temp_dir().join(format!(
            "dcentaxe-nano3s-hal-pwm-present-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("pwmchip0")).unwrap();
        std::fs::create_dir_all(dir.join("not-a-pwmchip")).unwrap();

        let chips = list_chips_at(&dir).unwrap();
        assert_eq!(chips.len(), 1);
        assert!(chips[0].ends_with("pwmchip0"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
