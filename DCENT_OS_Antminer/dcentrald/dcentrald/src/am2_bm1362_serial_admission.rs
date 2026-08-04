//! One-shot admission for the experimental AM2/Zynq BM1362 direct-serial route.
//!
//! A serial ASIC-protocol admission proves descriptor/config agreement only.
//! It cannot identify the carrier that owns fan, reset, UART, I2C, dsPIC, or
//! PSU resources. This module binds the immutable startup snapshot to the
//! exact public-beta AM2 composition before `SerialMiner` can construct any
//! hardware-owning object.

use crate::daemon_lifecycle::PlatformIdentitySnapshot;
use crate::runtime::hardware_info::OBSERVED_CONTROL_BOARD_ZYNQ_AM2;
use crate::RuntimeDispatchKind;
use dcentrald_common::{
    AsicProtocolIdentity, BoardFamily, ChainTransportKind, SlotPolicy, VoltageControllerClass,
    WorkEngineKind,
};

const BOARD_TARGET: &str = "am2-s19j";

/// Move-only carrier/composition authority for one direct-serial diagnostic.
#[must_use = "AM2 BM1362 serial route admission must be consumed by SerialMiner"]
#[derive(Debug)]
pub(crate) struct Am2Bm1362SerialRouteAdmission {
    _seal: Seal,
}

#[derive(Debug)]
enum Seal {
    Admitted,
}

pub(crate) fn admit_am2_bm1362_serial_route(
    identity: &PlatformIdentitySnapshot,
    dispatch: RuntimeDispatchKind,
    configured_asic_protocol: Option<AsicProtocolIdentity>,
) -> Result<Am2Bm1362SerialRouteAdmission, String> {
    if dispatch != RuntimeDispatchKind::Serial {
        return Err(format!(
            "AM2 BM1362 direct-serial admission requires the serial runtime route, got {}",
            dispatch.label()
        ));
    }
    if identity.board_target() != BOARD_TARGET {
        return Err(format!(
            "AM2 BM1362 direct-serial admission requires declared board target {BOARD_TARGET}, got {:?}",
            identity.board_target()
        ));
    }

    let board_desc = identity.board_desc.ok_or_else(|| {
        format!(
            "AM2 BM1362 direct-serial admission requires the registered {BOARD_TARGET} BoardDesc"
        )
    })?;
    if board_desc.board_target != identity.board_target() {
        return Err(format!(
            "immutable board target {:?} contradicts bound BoardDesc {}",
            identity.board_target(),
            board_desc.board_target
        ));
    }

    let exact_facets = board_desc.board_target == BOARD_TARGET
        && board_desc.family == BoardFamily::Zynq
        && board_desc.chain_transport == ChainTransportKind::ZynqHybrid
        && board_desc.work_engine == WorkEngineKind::SerialWork
        && board_desc.asic_protocol == AsicProtocolIdentity::Bm1362
        && board_desc.voltage_controller == VoltageControllerClass::DsPic33Ep
        && board_desc.slot_policy == SlotPolicy::ZynqAbFwSetenv;
    if !exact_facets {
        return Err(format!(
            "BoardDesc {} is not the exact AM2/Zynq BM1362 composition",
            board_desc.board_target
        ));
    }

    if identity.observed_control_board != OBSERVED_CONTROL_BOARD_ZYNQ_AM2 {
        return Err(format!(
            "declared AM2 direct-serial composition contradicts observed control board {:?}",
            identity.observed_control_board
        ));
    }
    if configured_asic_protocol != Some(AsicProtocolIdentity::Bm1362) {
        return Err(format!(
            "AM2 BM1362 direct-serial admission requires exact configured ASIC identity Bm1362, got {configured_asic_protocol:?}"
        ));
    }

    Ok(Am2Bm1362SerialRouteAdmission {
        _seal: Seal::Admitted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("am2_bm1362_serial_admission.rs");

    fn identity(board_target: &str, observed_control_board: &str) -> PlatformIdentitySnapshot {
        PlatformIdentitySnapshot {
            declared_board_target: Some(board_target.to_string()),
            observed_board_target: None,
            board_desc: dcentrald_common::BoardDesc::lookup(board_target),
            declared_platform_marker: Some("zynq-bm3-am2".to_string()),
            declared_subtype: None,
            declared_psu_hardware_variant: None,
            observed_control_board: observed_control_board.to_string(),
        }
    }

    #[test]
    fn exact_am2_zynq_bm1362_direct_serial_composition_is_admitted() {
        let _admission = admit_am2_bm1362_serial_route(
            &identity(BOARD_TARGET, OBSERVED_CONTROL_BOARD_ZYNQ_AM2),
            RuntimeDispatchKind::Serial,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .expect("canonical AM2/Zynq BM1362 direct-serial composition must admit");
    }

    #[test]
    fn same_bm1362_on_other_carriers_cannot_launder_serial_admission() {
        for (board_target, observed_control_board) in [
            ("am3-bb-s19jpro", "BeagleBone S9"),
            ("am3-s19jpro-aml", "AML Amlogic"),
            ("cv1835-s19jpro", "CVITEK CV1835"),
        ] {
            assert!(
                admit_am2_bm1362_serial_route(
                    &identity(board_target, observed_control_board),
                    RuntimeDispatchKind::Serial,
                    Some(AsicProtocolIdentity::Bm1362),
                )
                .is_err(),
                "same ASIC protocol on {board_target} must not authorize AM2 resources"
            );
        }
    }

    #[test]
    fn stale_am2_declaration_on_wrong_observed_carrier_fails_closed() {
        for observed_control_board in ["Zynq am1-s9", "BeagleBone S9", "AML Amlogic", "Unknown"] {
            assert!(admit_am2_bm1362_serial_route(
                &identity(BOARD_TARGET, observed_control_board),
                RuntimeDispatchKind::Serial,
                Some(AsicProtocolIdentity::Bm1362),
            )
            .is_err());
        }
    }

    #[test]
    fn wrong_route_or_family_fails_closed() {
        let am2 = identity(BOARD_TARGET, OBSERVED_CONTROL_BOARD_ZYNQ_AM2);
        assert!(admit_am2_bm1362_serial_route(
            &am2,
            RuntimeDispatchKind::S19jHybrid,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .is_err());
        assert!(admit_am2_bm1362_serial_route(
            &am2,
            RuntimeDispatchKind::Serial,
            Some(AsicProtocolIdentity::Bm1398),
        )
        .is_err());
    }

    #[test]
    fn capability_has_no_public_mint_clone_or_copy_surface() {
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("pub(crate) struct Am2Bm1362SerialRouteAdmission"));
        assert!(production.contains("_seal: Seal"));
        assert!(!production.contains("pub struct Am2Bm1362SerialRouteAdmission"));
        assert!(!production.contains("pub fn admit_am2_bm1362_serial_route"));
        assert!(!production.contains("impl Clone for Am2Bm1362SerialRouteAdmission"));
        assert!(!production.contains("impl Copy for Am2Bm1362SerialRouteAdmission"));
    }
}
