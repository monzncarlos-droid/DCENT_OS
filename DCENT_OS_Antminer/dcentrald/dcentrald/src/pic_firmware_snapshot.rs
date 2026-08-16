//! Read-only adapter from the standard runtime's retained PIC16 observations
//! to the public PIC firmware snapshot contract.
//!
//! The runtime has already classified the firmware and admitted each endpoint
//! before this adapter runs. This module performs no I2C operation and exposes
//! no PIC command. It only converts those retained facts into bounded API data.

use dcentrald_api_types::pic_firmware::{PicFirmwareClassification, PicFirmwareLiveSlot};
use dcentrald_asic::pic::PicFirmware;
use std::collections::BTreeSet;

/// The standard PIC16 lane has at most three hash-board endpoints today. Keep
/// a wider, explicit reporting bound so a corrupt endpoint list cannot become
/// an unbounded API payload.
pub(crate) const MAX_PIC16_SNAPSHOT_SLOTS: usize = 8;

/// Exact endpoint identity retained after successful runtime initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pic16SnapshotEndpoint {
    pub chain_id: Option<u8>,
    pub i2c_bus: u8,
    pub i2c_addr: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pic16SnapshotError {
    NoInitializedEndpoints,
    TooManyEndpoints { observed: usize, maximum: usize },
    FirmwareUnclassified,
    UnsupportedStockFirmware(u8),
    InvalidI2cAddress(u8),
    DuplicateEndpoint { i2c_bus: u8, i2c_addr: u8 },
    DuplicateChainId(u8),
}

impl std::fmt::Display for Pic16SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInitializedEndpoints => write!(f, "no initialized PIC16 endpoints"),
            Self::TooManyEndpoints { observed, maximum } => write!(
                f,
                "PIC16 endpoint count {observed} exceeds snapshot bound {maximum}"
            ),
            Self::FirmwareUnclassified => {
                write!(f, "PIC16 firmware was not classified by the runtime")
            }
            Self::UnsupportedStockFirmware(firmware) => write!(
                f,
                "stock PIC16 firmware byte 0x{firmware:02X} is outside the observed allowlist"
            ),
            Self::InvalidI2cAddress(address) => {
                write!(
                    f,
                    "PIC16 I2C address 0x{address:02X} is not a 7-bit address"
                )
            }
            Self::DuplicateEndpoint { i2c_bus, i2c_addr } => write!(
                f,
                "duplicate PIC16 endpoint bus {i2c_bus} address 0x{i2c_addr:02X}"
            ),
            Self::DuplicateChainId(chain_id) => {
                write!(f, "duplicate PIC16 chain id {chain_id}")
            }
        }
    }
}

fn retained_firmware_class(
    firmware: PicFirmware,
) -> Result<PicFirmwareClassification, Pic16SnapshotError> {
    match firmware {
        // `classify_pic_raw_state` collapses both raw 0x03 and app-mode 0x60
        // into this enum. Never reconstruct either byte here.
        PicFirmware::BraiinsOs => Ok(PicFirmwareClassification::BraiinsOsOrAppModePic16),
        PicFirmware::Stock(version) if matches!(version, 0x56 | 0x5A | 0x5E) => {
            Ok(PicFirmwareClassification::StockBitmainPic16)
        }
        PicFirmware::Stock(version) => Err(Pic16SnapshotError::UnsupportedStockFirmware(version)),
        PicFirmware::Unknown => Err(Pic16SnapshotError::FirmwareUnclassified),
    }
}

/// Build one atomic read-only snapshot from retained runtime observations.
///
/// Unknown firmware, invalid/duplicate endpoints, duplicate chain identities,
/// and an oversized list all fail closed. Callers should omit the live section
/// on error and retain the catalog-only API response.
pub(crate) fn build_pic16_snapshot(
    firmware: PicFirmware,
    endpoints: &[Pic16SnapshotEndpoint],
) -> Result<Vec<PicFirmwareLiveSlot>, Pic16SnapshotError> {
    if endpoints.is_empty() {
        return Err(Pic16SnapshotError::NoInitializedEndpoints);
    }
    if endpoints.len() > MAX_PIC16_SNAPSHOT_SLOTS {
        return Err(Pic16SnapshotError::TooManyEndpoints {
            observed: endpoints.len(),
            maximum: MAX_PIC16_SNAPSHOT_SLOTS,
        });
    }

    let classification = retained_firmware_class(firmware)?;
    let mut seen_endpoints = BTreeSet::new();
    let mut seen_chains = BTreeSet::new();
    let mut slots = Vec::with_capacity(1);

    for endpoint in endpoints {
        if endpoint.i2c_addr > 0x7F {
            return Err(Pic16SnapshotError::InvalidI2cAddress(endpoint.i2c_addr));
        }
        if !seen_endpoints.insert((endpoint.i2c_bus, endpoint.i2c_addr)) {
            return Err(Pic16SnapshotError::DuplicateEndpoint {
                i2c_bus: endpoint.i2c_bus,
                i2c_addr: endpoint.i2c_addr,
            });
        }
        if let Some(chain_id) = endpoint.chain_id {
            if !seen_chains.insert(chain_id) {
                return Err(Pic16SnapshotError::DuplicateChainId(chain_id));
            }
        }
    }

    // The daemon retained one global PicFirmware enum, not an exact raw state
    // per endpoint. Publish one global classification and only the number of
    // endpoints initialized when it was captured; do not attribute that class
    // to any endpoint and do not emit chain/address/byte claims.
    slots.push(PicFirmwareLiveSlot::classified_runtime_global(
        classification,
        endpoints.len(),
        "daemon_retained_pic16_runtime_classification",
    ));

    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_api_types::pic_firmware::{
        PicFirmwareInfoResponse, PicFirmwareInfoStatus, PicFirmwareLiveSlotStatus,
        PicFirmwareObservationScope,
    };

    fn endpoint(chain_id: u8, i2c_addr: u8) -> Pic16SnapshotEndpoint {
        Pic16SnapshotEndpoint {
            chain_id: Some(chain_id),
            i2c_bus: 0,
            i2c_addr,
        }
    }

    #[test]
    fn stock_snapshot_preserves_global_classification_boundary() {
        let slots = build_pic16_snapshot(
            PicFirmware::Stock(0x5E),
            &[endpoint(6, 0x55), endpoint(7, 0x56), endpoint(8, 0x57)],
        )
        .unwrap();

        assert_eq!(slots.len(), 1);
        assert_eq!(
            slots[0].observation_scope,
            PicFirmwareObservationScope::RuntimeGlobalClassification
        );
        assert_eq!(
            slots[0].classification,
            Some(PicFirmwareClassification::StockBitmainPic16)
        );
        assert_eq!(slots[0].initialized_endpoint_count, Some(3));
        assert_eq!(
            slots[0].slot.as_deref(),
            Some("runtime-global-pic16-classification")
        );
        assert_eq!(slots[0].chain_id, None);
        assert_eq!(slots[0].i2c_bus, None);
        assert_eq!(slots[0].i2c_addr, None);
        assert_eq!(slots[0].fw_byte, None);
        assert_eq!(slots[0].fw_byte_decimal, None);
        assert!(slots[0].variants.is_empty());
        assert_eq!(slots[0].status, PicFirmwareLiveSlotStatus::Live);
        assert_eq!(
            slots[0].source,
            "daemon_retained_pic16_runtime_classification"
        );
    }

    #[test]
    fn snapshot_drives_existing_live_read_only_response_contract() {
        let slots = build_pic16_snapshot(PicFirmware::BraiinsOs, &[endpoint(6, 0x55)]).unwrap();
        let response = PicFirmwareInfoResponse::from_live_slots(true, slots);

        assert_eq!(response.status, PicFirmwareInfoStatus::LiveSnapshot);
        assert!(response.read_only);
        assert!(!response.rest_handler_hardware_reads);
        assert!(!response.rest_handler_hardware_writes);
        assert!(!response.control_actions);
        let observation = &response.live_per_slot.observations[0];
        assert_eq!(
            observation.classification,
            Some(PicFirmwareClassification::BraiinsOsOrAppModePic16)
        );
        assert_eq!(observation.fw_byte_decimal, None);
        assert!(observation.variants.is_empty());
    }

    #[test]
    fn unknown_and_unobserved_firmware_fail_closed() {
        assert_eq!(
            build_pic16_snapshot(PicFirmware::Unknown, &[endpoint(6, 0x55)]),
            Err(Pic16SnapshotError::FirmwareUnclassified)
        );
        assert_eq!(
            build_pic16_snapshot(PicFirmware::Stock(0x42), &[endpoint(6, 0x55)]),
            Err(Pic16SnapshotError::UnsupportedStockFirmware(0x42))
        );
    }

    #[test]
    fn duplicate_or_hostile_endpoints_fail_closed() {
        assert!(matches!(
            build_pic16_snapshot(
                PicFirmware::BraiinsOs,
                &[endpoint(6, 0x55), endpoint(7, 0x55)]
            ),
            Err(Pic16SnapshotError::DuplicateEndpoint { .. })
        ));
        assert_eq!(
            build_pic16_snapshot(
                PicFirmware::BraiinsOs,
                &[endpoint(6, 0x55), endpoint(6, 0x56)]
            ),
            Err(Pic16SnapshotError::DuplicateChainId(6))
        );
        assert_eq!(
            build_pic16_snapshot(
                PicFirmware::BraiinsOs,
                &[Pic16SnapshotEndpoint {
                    chain_id: None,
                    i2c_bus: 0,
                    i2c_addr: 0x80,
                }]
            ),
            Err(Pic16SnapshotError::InvalidI2cAddress(0x80))
        );
    }

    #[test]
    fn empty_and_oversized_snapshots_are_refused() {
        assert_eq!(
            build_pic16_snapshot(PicFirmware::BraiinsOs, &[]),
            Err(Pic16SnapshotError::NoInitializedEndpoints)
        );
        let too_many = vec![endpoint(0, 0x20); MAX_PIC16_SNAPSHOT_SLOTS + 1];
        assert_eq!(
            build_pic16_snapshot(PicFirmware::BraiinsOs, &too_many),
            Err(Pic16SnapshotError::TooManyEndpoints {
                observed: MAX_PIC16_SNAPSHOT_SLOTS + 1,
                maximum: MAX_PIC16_SNAPSHOT_SLOTS,
            })
        );
    }
}
