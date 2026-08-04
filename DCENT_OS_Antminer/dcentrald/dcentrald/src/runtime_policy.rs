//! Process-wide runtime policy selected by the launcher.
//!
//! A temporary hardware-acceptance deployment must not inherit the persistent
//! storage behavior of an installed daemon merely because `/data` is mounted.
//! The launcher therefore sets [`EPHEMERAL_RUNTIME_ENV`] to the single admitted
//! value `1`.  Every daemon-owned persistence path consults this policy and
//! moves to tmpfs, while API construction becomes observation-only.

use std::path::{Path, PathBuf};

pub const EPHEMERAL_RUNTIME_ENV: &str = "DCENTOS_EPHEMERAL_RUNTIME";

fn enabled_value(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

pub fn ephemeral_runtime_enabled() -> bool {
    enabled_value(std::env::var(EPHEMERAL_RUNTIME_ENV).ok().as_deref())
}

pub fn persistence_path(persistent: &Path, ephemeral: &Path) -> PathBuf {
    if ephemeral_runtime_enabled() {
        ephemeral.to_path_buf()
    } else {
        persistent.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::enabled_value;

    #[test]
    fn ephemeral_policy_requires_the_exact_explicit_value() {
        assert!(enabled_value(Some("1")));
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some(" 1"),
        ] {
            assert!(!enabled_value(value));
        }
    }
}
