// SPDX-License-Identifier: GPL-3.0-or-later
//
// Native Nano 3 passive safety observation.
//
// This is an intentionally incomplete, non-authorizing boundary. It reads the
// evidenced IIO temperature and PWM readback nodes, but never exports or writes
// PWM, enables/reads timer5, opens the UART, touches the watchdog, or claims an
// external interlock. The timer5 tach needs an enabling ioctl; that operation
// belongs to a future exclusive-custody runtime and must not be disguised as a
// passive read.

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use tokio::io::AsyncReadExt;
#[cfg(unix)]
use tracing::info;

use crate::nano3_safety::{
    BoardTemperatures, NANO3_INLET_ADC, NANO3_OUTLET_ADC, NANO3_PWM_DUTY, NANO3_PWM_ENABLE,
    NANO3_PWM_PERIOD, NANO3_PWM_PERIOD_NS, NANO3_STOCK_MAX_DUTY_NS, NANO3_STOCK_MIN_DUTY_NS,
};

const MAX_SYSFS_SAMPLE_BYTES: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PassivePwmReadback {
    period_ns: u32,
    duty_ns: u32,
    enabled: bool,
}

impl PassivePwmReadback {
    fn decode(period: &[u8], duty: &[u8], enabled: &[u8]) -> Result<Self> {
        let period_ns = strict_decimal_u32(period, "PWM period")?;
        let duty_ns = strict_decimal_u32(duty, "PWM duty")?;
        let enabled = match strict_decimal_u32(enabled, "PWM enable")? {
            0 => false,
            1 => true,
            other => bail!("Nano 3 PWM enable must be 0 or 1, observed {other}"),
        };
        Ok(Self {
            period_ns,
            duty_ns,
            enabled,
        })
    }

    const fn matches_held_stock_envelope(self) -> bool {
        self.period_ns == NANO3_PWM_PERIOD_NS
            && self.duty_ns >= NANO3_STOCK_MIN_DUTY_NS
            && self.duty_ns <= NANO3_STOCK_MAX_DUTY_NS
            && self.duty_ns <= self.period_ns
    }
}

/// One simultaneous passive read set. This type deliberately has no conversion
/// into `Nano3SafetySnapshot`: readback is not actuator custody, timer5 was not
/// enabled/sampled, and no independent cut or heartbeat was observed.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PassiveNano3Observation {
    board: BoardTemperatures,
    pwm: PassivePwmReadback,
}

impl PassiveNano3Observation {
    const fn authorizes_energization(self) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
struct ObservationPaths {
    inlet_adc: PathBuf,
    outlet_adc: PathBuf,
    pwm_period: PathBuf,
    pwm_duty: PathBuf,
    pwm_enable: PathBuf,
}

impl ObservationPaths {
    fn system() -> Self {
        Self {
            inlet_adc: PathBuf::from(NANO3_INLET_ADC),
            outlet_adc: PathBuf::from(NANO3_OUTLET_ADC),
            pwm_period: PathBuf::from(NANO3_PWM_PERIOD),
            pwm_duty: PathBuf::from(NANO3_PWM_DUTY),
            pwm_enable: PathBuf::from(NANO3_PWM_ENABLE),
        }
    }

    #[cfg(test)]
    fn fixture(root: &Path) -> Self {
        Self {
            inlet_adc: root.join("inlet_adc"),
            outlet_adc: root.join("outlet_adc"),
            pwm_period: root.join("pwm_period"),
            pwm_duty: root.join("pwm_duty"),
            pwm_enable: root.join("pwm_enable"),
        }
    }
}

#[cfg(unix)]
pub async fn run_once() -> Result<()> {
    let observation = observe(&ObservationPaths::system()).await?;
    info!(
        observer_schema = 1,
        target = "canaan-avalon-nano3-non-s",
        inlet_adc_raw = observation.board.inlet_raw(),
        outlet_adc_raw = observation.board.outlet_raw(),
        inlet_c = observation.board.inlet_c(),
        outlet_c = observation.board.outlet_c(),
        pwm_period_ns = observation.pwm.period_ns,
        pwm_duty_ns = observation.pwm.duty_ns,
        pwm_enabled = observation.pwm.enabled,
        pwm_matches_held_stock_envelope = observation.pwm.matches_held_stock_envelope(),
        authorizes_energization = observation.authorizes_energization(),
        tach_sample = "not-observed: timer5 requires control ioctl",
        actuator_custody = "not-claimed",
        independent_interlock = "not-observed",
        "Nano 3 passive safety observation complete"
    );
    Ok(())
}

async fn observe(paths: &ObservationPaths) -> Result<PassiveNano3Observation> {
    // One try_join set is one passive observation iteration. None of these
    // reads is accepted as an independently timed production safety snapshot.
    let (inlet, outlet, period, duty, enabled) = tokio::try_join!(
        read_small_regular(&paths.inlet_adc),
        read_small_regular(&paths.outlet_adc),
        read_small_regular(&paths.pwm_period),
        read_small_regular(&paths.pwm_duty),
        read_small_regular(&paths.pwm_enable),
    )?;

    Ok(PassiveNano3Observation {
        board: BoardTemperatures::decode(&inlet, &outlet)
            .context("decoding Nano 3 board temperatures")?,
        pwm: PassivePwmReadback::decode(&period, &duty, &enabled)?,
    })
}

async fn read_small_regular(path: &Path) -> Result<Vec<u8>> {
    let before = tokio::fs::symlink_metadata(path)
        .await
        .with_context(|| format!("inspecting passive observation node {}", path.display()))?;
    ensure!(
        !before.file_type().is_symlink(),
        "passive observation node must not be a final-component symlink: {}",
        path.display()
    );
    ensure!(
        before.is_file(),
        "passive observation node is not a regular/sysfs attribute: {}",
        path.display()
    );

    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // SAFETY BOUNDARY: O_NOFOLLOW makes a final-component replacement with
        // a symlink fail at open time; O_CLOEXEC prevents descriptor leakage.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .await
        .with_context(|| format!("opening passive observation node {}", path.display()))?;
    let opened = file
        .metadata()
        .await
        .with_context(|| format!("checking opened observation node {}", path.display()))?;
    ensure!(
        opened.is_file(),
        "passive observation node is not a regular/sysfs attribute: {}",
        path.display()
    );

    let mut bytes = Vec::new();
    file.take(MAX_SYSFS_SAMPLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("reading passive observation node {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_SYSFS_SAMPLE_BYTES as usize,
        "passive observation node exceeds {MAX_SYSFS_SAMPLE_BYTES} bytes: {}",
        path.display()
    );
    Ok(bytes)
}

fn strict_decimal_u32(raw: &[u8], field: &str) -> Result<u32> {
    let text = std::str::from_utf8(raw).with_context(|| format!("{field} is not UTF-8"))?;
    let trimmed = text.trim();
    ensure!(
        !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()),
        "Nano 3 {field} is not strict decimal ASCII"
    );
    trimmed
        .parse::<u32>()
        .with_context(|| format!("Nano 3 {field} is outside u32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write_fixture(path: &Path, value: &[u8]) {
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(path, value).await.unwrap();
    }

    async fn complete_fixture(paths: &ObservationPaths) {
        write_fixture(&paths.inlet_adc, b"2150\n").await;
        write_fixture(&paths.outlet_adc, b"2250\n").await;
        write_fixture(&paths.pwm_period, b"40000\n").await;
        write_fixture(&paths.pwm_duty, b"10000\n").await;
        write_fixture(&paths.pwm_enable, b"1\n").await;
    }

    #[test]
    fn production_wiring_uses_only_the_exact_evidenced_nodes() {
        let paths = ObservationPaths::system();
        assert_eq!(paths.inlet_adc, PathBuf::from(NANO3_INLET_ADC));
        assert_eq!(paths.outlet_adc, PathBuf::from(NANO3_OUTLET_ADC));
        assert_eq!(paths.pwm_period, PathBuf::from(NANO3_PWM_PERIOD));
        assert_eq!(paths.pwm_duty, PathBuf::from(NANO3_PWM_DUTY));
        assert_eq!(paths.pwm_enable, PathBuf::from(NANO3_PWM_ENABLE));
    }

    #[tokio::test]
    async fn reads_exact_evidenced_nodes_but_never_authorizes() {
        let root = tempfile::tempdir().unwrap();
        let paths = ObservationPaths::fixture(root.path());
        complete_fixture(&paths).await;

        let observed = observe(&paths).await.unwrap();
        assert_eq!(observed.board.inlet_raw(), 2150);
        assert_eq!(observed.board.outlet_raw(), 2250);
        assert_eq!(observed.pwm.period_ns, 40_000);
        assert_eq!(observed.pwm.duty_ns, 10_000);
        assert!(observed.pwm.enabled);
        assert!(observed.pwm.matches_held_stock_envelope());
        assert!(!observed.authorizes_energization());
    }

    #[tokio::test]
    async fn rejects_oversized_and_non_regular_inputs() {
        let root = tempfile::tempdir().unwrap();
        let paths = ObservationPaths::fixture(root.path());
        complete_fixture(&paths).await;
        write_fixture(&paths.pwm_duty, &[b'7'; 65]).await;
        let err = observe(&paths).await.unwrap_err();
        assert!(err.to_string().contains("exceeds 64 bytes"), "{err:#}");

        let root = tempfile::tempdir().unwrap();
        let paths = ObservationPaths::fixture(root.path());
        complete_fixture(&paths).await;
        tokio::fs::remove_file(&paths.pwm_duty).await.unwrap();
        tokio::fs::create_dir(&paths.pwm_duty).await.unwrap();
        let err = observe(&paths).await.unwrap_err();
        assert!(err.to_string().contains("not a regular"), "{err:#}");
    }

    #[tokio::test]
    async fn unsafe_or_malformed_pwm_is_reported_or_rejected() {
        let root = tempfile::tempdir().unwrap();
        let paths = ObservationPaths::fixture(root.path());
        complete_fixture(&paths).await;
        write_fixture(&paths.pwm_duty, b"40001\n").await;
        let observed = observe(&paths).await.unwrap();
        assert!(!observed.pwm.matches_held_stock_envelope());
        assert!(!observed.authorizes_energization());

        write_fixture(&paths.pwm_enable, b"2\n").await;
        let err = observe(&paths).await.unwrap_err();
        assert!(err.to_string().contains("must be 0 or 1"), "{err:#}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn final_component_symlinks_are_refused() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let paths = ObservationPaths::fixture(root.path());
        complete_fixture(&paths).await;
        tokio::fs::remove_file(&paths.pwm_duty).await.unwrap();
        symlink("pwm_period", &paths.pwm_duty).unwrap();
        let err = observe(&paths).await.unwrap_err();
        assert!(
            err.to_string().contains("final-component symlink"),
            "{err:#}"
        );
    }

    #[test]
    fn source_contains_no_control_or_transport_operations() {
        let source = include_str!("nano3_observer.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production source prefix");
        for forbidden in [
            concat!("Async", "WriteExt"),
            concat!(".write", "_all("),
            concat!(".cre", "ate("),
            concat!("tokio::fs::", "write"),
            concat!("NANO3_TACH_ENABLE_", "IOCTL"),
            concat!("NANO3_PWM_", "EXPORT"),
            concat!("NANO3_STOCK_WATCHDOG_", "DEVICE"),
            concat!("NANO3_CHAIN_", "UART"),
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden observer token: {forbidden}"
            );
        }
    }
}
