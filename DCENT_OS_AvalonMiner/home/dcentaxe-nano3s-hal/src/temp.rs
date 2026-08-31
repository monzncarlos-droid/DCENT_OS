// SPDX-License-Identifier: GPL-3.0-or-later
//
// hwmon temperature read for K230 Linux. Reads `/sys/class/hwmon/hwmonN/temp*_input`.
// K230 has on-die temp sensor (-40 to 125°C ±3°C per
// ); kernel exposes it via
// hwmon when the relevant DT node is present. NTC thermistors on the Nano 3S
// hashboard wait on teardown confirmation.
//
// FAIL-CLOSED (Wave 6 R4a): a missing `/sys/class/hwmon` tree returns `Err`,
// never an empty `Ok`. An absent thermal sensor tree must never read as
// "no temperatures, everything fine" — the caller has to see the failure and
// decide (refuse to mine, bypass with an explicit lab override, etc.).

use std::path::Path;

use crate::HalError;

const HWMON_ROOT: &str = "/sys/class/hwmon";

/// Iterate hwmon temp inputs; returns `(label, millicelsius)` tuples.
///
/// Errors:
/// - `HalError::SysfsMissing` when `/sys/class/hwmon` does not exist.
/// - `HalError::Io` on any other error opening the hwmon root.
///
/// An existing-but-empty hwmon tree still returns `Ok(vec![])`; callers that
/// need a live sensor must treat an empty list as "no thermal telemetry" too.
pub fn read_all_temps() -> Result<Vec<(String, i32)>, HalError> {
    read_all_temps_at(Path::new(HWMON_ROOT))
}

/// Testable core of [`read_all_temps`] with an explicit hwmon root.
pub fn read_all_temps_at(root: &Path) -> Result<Vec<(String, i32)>, HalError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HalError::SysfsMissing(root.display().to_string()));
        }
        Err(e) => return Err(HalError::Io(e)),
    };
    for hwmon in entries.flatten() {
        let name = std::fs::read_to_string(hwmon.path().join("name"))
            .unwrap_or_else(|_| hwmon.file_name().to_string_lossy().into());
        let name = name.trim().to_string();
        if let Ok(inputs) = std::fs::read_dir(hwmon.path()) {
            for inp in inputs.flatten() {
                let fname = inp.file_name();
                let fname = fname.to_string_lossy();
                if fname.starts_with("temp") && fname.ends_with("_input") {
                    if let Ok(s) = std::fs::read_to_string(inp.path()) {
                        if let Ok(millic) = s.trim().parse::<i32>() {
                            out.push((format!("{}/{}", name, fname), millic));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::read_all_temps_at;
    use crate::HalError;

    #[test]
    fn missing_hwmon_root_is_an_error_not_an_empty_ok() {
        let dir = std::env::temp_dir().join(format!(
            "dcentaxe-nano3s-hal-temp-missing-{}",
            std::process::id()
        ));
        // Deliberately never created.
        let err = read_all_temps_at(&dir).expect_err("missing sysfs must be Err");
        match err {
            HalError::SysfsMissing(p) => assert!(p.contains("dcentaxe-nano3s-hal-temp-missing")),
            other => panic!("expected SysfsMissing, got: {other:?}"),
        }
    }

    #[test]
    fn present_hwmon_root_parses_temp_inputs() {
        let dir = std::env::temp_dir().join(format!(
            "dcentaxe-nano3s-hal-temp-present-{}",
            std::process::id()
        ));
        let hwmon0 = dir.join("hwmon0");
        std::fs::create_dir_all(&hwmon0).unwrap();
        std::fs::write(hwmon0.join("name"), "k230_tsensor\n").unwrap();
        std::fs::write(hwmon0.join("temp1_input"), "47500\n").unwrap();
        std::fs::write(hwmon0.join("temp1_label"), "die\n").unwrap(); // ignored: not *_input

        let temps = read_all_temps_at(&dir).unwrap();
        assert_eq!(
            temps,
            vec![("k230_tsensor/temp1_input".to_string(), 47_500)]
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
