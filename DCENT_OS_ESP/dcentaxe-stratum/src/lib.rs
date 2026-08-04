// DCENT_axe Stratum V1 Client
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
// Stratum V1 protocol client for ESP32-S3 BitAxe miners.
// Handles pool connection, job reception, share submission.
//
// Uses std::net::TcpStream (supported on ESP-IDF) — no async runtime needed.

pub mod address;
pub mod client;
pub mod gateway_solo;
pub mod mask;
pub mod mesh_solo;
pub mod pool_agreement;
pub mod scrypt;
pub mod solo;
pub mod types;
pub mod work;

pub use address::address_to_script_hex;
pub use client::{set_solo_share_hook, StratumClient};
pub use gateway_solo::{
    coinbase_wire_to_nonwitness, GatewaySoloError, GatewaySoloSubmit, SubmitPrep,
    MAX_SOLO_BLOCK_BYTES, MIN_SOLO_BLOCK_BYTES,
};
pub use mask::{mask_wallet, sanitize_pool_url};
pub use mesh_solo::{
    MeshSoloController, MeshSoloError, MeshSoloMetrics, MeshSoloMode, SoloBlockCandidate,
    SoloWorkEpoch, TipAdmit,
};
pub use pool_agreement::{PoolAgreement, PoolAgreementMonitor};
pub use scrypt::{ltc_pow_hash, ScryptError, LTC_SCRATCH_LEN};
pub use solo::{
    assemble_coinbase_full, assemble_coinbase_nonwitness, assemble_solo_block, block_subsidy_sats,
    block_subsidy_sats_with_interval, coinbase_txid, compact_target_be, header_from_work,
    rolled_version, tip_supersedes, validate_found_block, validate_found_header, validate_tip,
    validate_tip_for_chain, ChainId, SoloChainParams, SoloError, SoloTemplateBuilder, SoloTip,
    BIP320_VERSION_MASK, MAINNET_HALVING_INTERVAL, REGTEST_HALVING_INTERVAL, SOLO_EXTRANONCE2_SIZE,
};
pub use types::*;
pub use work::{
    difficulty_to_target, difficulty_to_target_for, difficulty_to_target_generic, double_sha256,
    full_header_difficulty_and_target_for, parse_coinbase, CoinbaseDecoded, CoinbaseOutput,
    MiningWork, WorkBuilder,
};

// P1 Scrypt seam: the algorithm enum is rooted in `dcentaxe_asic::common`
// (design §4.2); re-exported here so `dcentaxe-mining` and the binary crate
// reach it through their existing dependency edge. P2 adds the per-algorithm
// diff-1 constants alongside it.
pub use dcentaxe_asic::common::{
    HashrateUnit, PowAlgorithm, SCRYPT_DIFF1_SCALE_VS_BITCOIN, SCRYPT_MIN_POOL_DIFFICULTY,
    SCRYPT_PDIFF1_TARGET,
};
