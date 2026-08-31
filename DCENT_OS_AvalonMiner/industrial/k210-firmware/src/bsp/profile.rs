//! Sealed Phase-A board profile.
//!
//! A1246 pin assignments, console routing, actuator polarity, sensors, power
//! cutoff, and cooling topology are all exact-unit evidence. The generic core
//! therefore exposes only a sealed profile: there is deliberately no public
//! constructor for an admitted board-bound assignment in this crate.

pub const PROFILE_SCHEMA: &str = "dcent-k210-bsp-profile-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartInstance {
    Uarths,
    Uart1,
    Uart2,
    Uart3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleConfig {
    instance: UartInstance,
    baud: u32,
}

impl ConsoleConfig {
    #[must_use]
    pub const fn instance(self) -> UartInstance {
        self.instance
    }

    #[must_use]
    pub const fn baud(self) -> u32 {
        self.baud
    }
}

/// The only generic profile value. It cannot authorize MMIO or actuation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SealedBoardProfile;

pub const SEALED: SealedBoardProfile = SealedBoardProfile;

impl SealedBoardProfile {
    #[must_use]
    pub const fn schema(self) -> &'static str {
        PROFILE_SCHEMA
    }

    #[must_use]
    pub const fn profile_id(self) -> Option<&'static str> {
        None
    }

    #[must_use]
    pub const fn console(self) -> Option<ConsoleConfig> {
        None
    }

    #[must_use]
    pub const fn board_bound_assignments_present(self) -> bool {
        false
    }

    #[must_use]
    pub const fn permits_mmio(self) -> bool {
        false
    }

    #[must_use]
    pub const fn permits_actuation(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_profile_is_permanently_sealed_and_empty() {
        assert_eq!(SEALED.schema(), PROFILE_SCHEMA);
        assert_eq!(SEALED.profile_id(), None);
        assert_eq!(SEALED.console(), None);
        assert!(!SEALED.board_bound_assignments_present());
        assert!(!SEALED.permits_mmio());
        assert!(!SEALED.permits_actuation());
    }
}
