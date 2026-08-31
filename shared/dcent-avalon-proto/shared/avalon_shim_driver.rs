// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — SHARED Avalon Phase-1 shim driver source.
//
// ⚠ THIS FILE IS NOT A MODULE OF `dcent-avalon-proto`. `src/lib.rs` does not
// declare it and this crate never compiles it. It is the SINGLE canonical
// source of the Avalon `AsicDriver` shim, `include!`d verbatim by the two
// consumer crates, which carry identical dependency sets:
//
//   DCENT_OS_AvalonMiner/dcentrald/dcentrald-avalon-asic/src/lib.rs  (industrial)
//   DCENT_OS_AvalonMiner/home/dcentaxe-nano3s-asic/src/lib.rs            (home)
//
// WHY THIS FILE EXISTS. Until 2026-08-03 those two `lib.rs` files were
// byte-identical 581-line copies (md5 4a7af19223ab3a99e0045d645a17ec21 each,
// `diff` empty). That is a silent-divergence hazard, not a cosmetic one: the
// Wave-6 R4b fix that stopped STATUS_ASIC Temp/Volt words from being decoded as
// `RegisterType::Hashrate` had to be applied twice, and nothing would have
// caught it if only one copy had been fixed. One source, two consumers, zero
// divergence (H8 §4 item #5).
//
// WHY `include!` AND NOT A NORMAL MODULE. The shim needs
// `dcentaxe_asic::AsicDriver`, which `dcent-avalon-proto` does not depend on.
// Hosting it as a real module here would require a new Cargo dependency; the
// `include!` keeps one source with zero manifest change. rustc records
// `include!`d files in its dep-info, so both consumers rebuild when this
// file changes. (Consequence: these crates are path-only and must not be
// packaged for a registry, which was already true.)
//
// BEHAVIOUR-PRESERVATION. The body below is the byte-exact pre-collapse source
// with ONE recorded amendment. Only comments precede it and only new items
// follow it. The `include!` places the body at each consumer's crate root,
// exactly where it used to live, so `crate::` paths, `#[cfg(unix)]` gating and
// visibility are unchanged. Re-checkable from the repo root at any time —
// the two marker comments delimit the body:
//
//   awk '/BODY BEGINS ON THE NEXT LINE/{f=1;next}
//        /BODY ENDS ON THE PREVIOUS LINE/{f=0} f' \
//     shared/dcent-avalon-proto/shared/avalon_shim_driver.rs \
//     | head -n -1 | md5sum      # => 4c9056104cf44fc90684d962fbaed75d
//
// History of the body md5:
//   4a7af19223ab3a99e0045d645a17ec21 — both pre-collapse copies at commit
//     e151f77d4 (unchanged at the 2026-08-03 collapse).
//   91c149aa095eb4b3ef2c08945a610c67 — 2026-08-29 amendment: port the body
//     onto the corrected mm_pkg codec API (2026-08-23). The frozen 1-arg
//     `MmPkg::decode` call and `header.opcode` field broke compilation of
//     every unix target (masked on Windows by the `#[cfg(unix)]` gate), and
//     the subtype byte still rode at `payload[0]` in the pre-correction
//     wire format. The body now builds command/reply `TypeWord`s with the
//     subtype in the compound type word on both TX and RX sides, decodes
//     replies as `MmToHost`, and derives the codec direction from the
//     received msgq mtype in the transport.
//   78e7e907f1ecefd597d5a682bc5cba0e — 2026-08-29 second amendment (review
//     fixes): version-roll reconstruction moved to the SHARED slot-table
//     model in dcentaxe_asic::common (one table hypothesis for the whole
//     tree), and dispatched base fields now resolve PER ECHOED JOB via
//     RollBases instead of a single chain-wide base (a nonce reported after
//     the next dispatch used to be rebuilt against the wrong job's base).
//   b5308f8e1ab80042616fd0ec08ad8738 — 2026-08-29 third amendment (P2
//     liveness): read_responses is now a non-blocking bounded drain
//     (IPC_NOWAIT poll loop with a timeout budget, two-empty-poll drain
//     terminator, 64-result batch cap) instead of one BLOCKING msgrcv that
//     hung the mining loop whenever the queue went quiet.
//   432f5e44e1d43b07d757e19170e00968 — 2026-08-29 fourth amendment
//     (mm_miner RE): the set_version_mask comment updated to the resolved
//     push mechanism — there is no vmask config opcode; the 8-slot table
//     of byte-swapped absolute version words rides inside every SET_JOB
//     (mm_work.vmask, offset 0x1CC4; codec in dcent-avalon-proto
//     mm_work.rs). Test expectations moved to the stock table
//     construction (single-bit slots from bit 15).
//   4c9056104cf44fc90684d962fbaed75d — 2026-08-29 fifth amendment (coinbase
//     interface extension): send_work now emits the COMPLETE 7408-byte
//     mm_work via build_mm_work + the codec (the tentative 81-byte
//     scaffold is retired); the version-roll table pushes per-job through
//     stock_vmask_table; jobs lacking coinbase parts still encode the
//     complete shape with a loud warning.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/
//
// ── BYTE-EXACT PRE-COLLAPSE BODY BEGINS ON THE NEXT LINE ────────────────────
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Phase 1 shim driver — replaces Canaan's `mm_miner` (Linux little core) but
// keeps Canaan's encrypted `asic_miner_e` RT-Smart blob untouched.
//
// Strategy (per approved plan, locked decision):
//
//   [Linux little core]                    [RT-Smart big core]
//     dcentaxe-nano3s (Rust)        ←→        asic_miner_e (Canaan blob)
//         ↓ SysV msgq                              ↓ SPI
//         ↓ 268-byte mm_pkg                        ↓ A3xxx ASICs
//     Stratum / dashboard / fan / autotuner
//
// We DO NOT redistribute Canaan's blob. Lab-only / D-Central units only
// per Phase 1. Phase 3 (clean-room A3xxx driver) is a future ship-readiness
// milestone, not Phase 1 scope.
//
// This crate implements the canonical `dcentaxe_asic::AsicDriver` trait so
// the same `dcentaxe_mining::MiningDispatcher` that drives Bitmain BM-family
// chips can also drive Avalon. Transport is SysV msgq instead of UART; the
// trait stays unchanged.
//
// References:
//   -  (Plan 2)
//   -  §5
//
//
//

#[cfg(unix)]
mod unix_driver {
    use crate::validate_avalon_frequency_mhz;
    use dcent_avalon_proto::mm_pkg::{
        Direction as CodecDirection, MinerNonce, MmPkg, Opcode, SetAsicSubtype, StatusAsicSubtype,
        TypeWord, MM_PKG_PAYLOAD_SIZE, MM_PKG_SIZE,
    };
    use dcent_avalon_proto::mm_work::{stock_vmask_table, MmWork};
    use dcent_avalon_proto::transport::{Direction, SysVMsgQ};
    use dcentaxe_asic::common::{
        now_us, reconstruct_rolled_version, version_roll_table, AsicError, AsicResult, MiningJob,
        RegisterData, RegisterType, RollBases,
    };
    use dcentaxe_asic::AsicDriver;
    use tracing::{debug, trace, warn};

    /// Per-job dispatched base fields + the active version mask — everything
    /// `decode_one` needs to reconstruct rolled version/ntime before share
    /// verify. The version-roll slot table itself lives in
    /// `dcentaxe_asic::common::version_roll_table` (one shared, bench-gated
    /// hypothesis for the whole tree, so the shim and the native driver can
    /// never silently disagree on the reconstruction).
    #[derive(Debug, Clone, Default)]
    struct RollContext {
        version_mask: u32,
        bases: RollBases,
    }

    /// Avalon shim driver — speaks 268-byte `mm_pkg` to Canaan's RT-Smart blob
    /// over a SysV message queue.
    ///
    /// Phase 1 implementation: single-chain only. Industrial multi-hashboard
    /// mux (TCA9546A I2C) lives in `DCENT_OS_AvalonMiner/.../dcentrald-avalon-asic`
    /// and is deferred to a future plan.
    pub struct AvalonShimDriver {
        msgq: SysVMsgQ,
        chip_count: u8,
        current_frequency: f32,
        roll_ctx: RollContext,
    }

    /// Default placeholder UART baud reported by `set_max_baud()`. K230's
    /// RT-Smart owns the chip UART; the host has no real baud control.
    /// 1 MHz keeps consumers happy without overpromising.
    const PLACEHOLDER_BAUD: u32 = 1_000_000;

    /// Default chip count when `init()`'s ACKDETECT payload doesn't carry one.
    /// Nano 3S = 12 chips, Nano 3 = 10. Caller can override via `chain_count`.
    const FALLBACK_CHIP_COUNT: u8 = 12;

    /// `read_responses` poll interval while waiting for the first message.
    const READ_RESPONSES_POLL_INTERVAL_MS: u64 = 5;
    /// Hard cap on results decoded in one `read_responses` call — one tick
    /// must never monopolize the mining loop.
    const READ_RESPONSES_MAX_BATCH: usize = 64;

    fn map_proto_err<E: std::fmt::Display>(e: E) -> AsicError {
        AsicError::InvalidResponse(format!("avalon proto: {}", e))
    }

    /// Build the complete 7408-byte mm_work SET_JOB payload from a
    /// MiningJob + the recorded version mask (pure; the send path only
    /// fragments the result). The version-roll table rides inside the job
    /// via `stock_vmask_table` — there is no separate vmask opcode. Jobs
    /// without coinbase parts still encode (the RT blob will reject them)
    /// so callers get a loud, logged, complete-shape frame rather than a
    /// silently different layout.
    fn build_mm_work(job: &MiningJob, version_mask: u32) -> Result<MmWork, AsicError> {
        // 80-byte block header, internal byte order (LE fields) — the same
        // layout every share validator in this workspace reconstructs.
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&job.version.to_le_bytes());
        header[4..36].copy_from_slice(&job.prev_block_hash);
        header[36..68].copy_from_slice(&job.merkle_root);
        header[68..72].copy_from_slice(&job.ntime.to_le_bytes());
        header[72..76].copy_from_slice(&job.nbits.to_le_bytes());
        header[76..80].copy_from_slice(&job.starting_nonce.to_le_bytes());
        Ok(MmWork {
            job_id: u32::from(job.job_id),
            coinbase: job.coinbase.clone(),
            nonce2: job.nonce2,
            nonce2_offset: job.nonce2_offset,
            nonce2_size: job.nonce2_size,
            merkle_offset: job.merkle_offset,
            nmerkles: job.merkle_branches.len() as i32,
            merkles: job.merkle_branches.clone(),
            header,
            target: job.target.unwrap_or([0u8; 32]),
            vmask: stock_vmask_table(job.version, version_mask),
            start: 0,
            range: 0,
            work_restart: false,
        })
    }

    impl AvalonShimDriver {
        /// Open the canonical Canaan SysV msgq (`ftok("/dev/null", 'A')`).
        ///
        /// Errors out with `AsicError::Serial` on Unix syscall failure (no
        /// asic_miner running, permission denied, etc.).
        pub fn open_default() -> Result<Self, AsicError> {
            let msgq = SysVMsgQ::open_default()
                .map_err(|e| AsicError::Serial(format!("SysV msgq open: {}", e)))?;
            Ok(Self {
                msgq,
                chip_count: 0,
                current_frequency: 0.0,
                roll_ctx: RollContext::default(),
            })
        }

        /// Open with a custom key path / proj_id (testing, multi-instance).
        pub fn open(key_path: &str, proj_id: u8) -> Result<Self, AsicError> {
            let msgq = SysVMsgQ::open(key_path, proj_id)
                .map_err(|e| AsicError::Serial(format!("SysV msgq open: {}", e)))?;
            Ok(Self {
                msgq,
                chip_count: 0,
                current_frequency: 0.0,
                roll_ctx: RollContext::default(),
            })
        }

        /// Build a host→ASIC-daemon command type word. Subtypes ride in the
        /// compound type word (`(primary << 8) | subtype`), never in the
        /// payload — this is the corrected wire format the codec enforces.
        fn command(primary: Opcode, subtype: Option<u8>) -> TypeWord {
            TypeWord {
                primary,
                subtype,
                direction: CodecDirection::HostToMm,
            }
        }

        fn send(&self, type_word: TypeWord, payload: &[u8]) -> Result<(), AsicError> {
            let fragments = MmPkg::fragment(type_word, payload).map_err(map_proto_err)?;
            let fragment_count = fragments.len();
            for pkg in fragments {
                self.msgq
                    .send(Direction::HostToAsic, &pkg)
                    .map_err(|e| AsicError::Serial(format!("msgsnd: {}", e)))?;
            }
            trace!(?type_word, len = payload.len(), fragment_count, "mm_pkg sent");
            Ok(())
        }

        fn recv_asic_to_host(&self) -> Result<MmPkg, AsicError> {
            let pkg = self
                .msgq
                .recv(Some(Direction::AsicToHost))
                .map_err(|e| AsicError::Serial(format!("msgrcv: {}", e)))?;
            Ok(pkg)
        }
    }

    impl AsicDriver for AvalonShimDriver {
        fn init(
            &mut self,
            frequency: f32,
            chain_count: u8,
            initial_difficulty: f64,
        ) -> Result<u8, AsicError> {
            debug!(
                frequency,
                chain_count, initial_difficulty, "AvalonShimDriver::init"
            );

            // Step 1: P_DETECT handshake. Empty payload — RT-Smart blob
            // reports back via P_ACKDETECT.
            self.send(Self::command(Opcode::Detect, None), &[])?;
            let ack = self.recv_asic_to_host()?;
            if ack.header.type_word.primary != Opcode::AckDetect {
                return Err(AsicError::InitFailed(format!(
                    "expected AckDetect, got {:?}",
                    ack.header.type_word.primary
                )));
            }

            // ACKDETECT payload format is not in the cleartext mm_miner.h; the
            // closed mm_miner ELF reads module count + DNA + version from the
            // first ~16 bytes. For Phase 1 scaffolding we trust caller's
            // chain_count hint and fall back to FALLBACK_CHIP_COUNT (12, Nano 3S).
            let detected = if chain_count > 0 {
                chain_count
            } else {
                FALLBACK_CHIP_COUNT
            };
            self.chip_count = detected;

            // Step 2: send initial frequency via P_SET_ASIC subtype Pll.
            // Payload[0] = subtype byte; payload[1..] is the PLL register
            // encoding (TODO — exact A3197/A3198 register format pending RE).
            self.set_frequency(frequency)?;

            // Step 3: difficulty. Phase 1 records but does not transmit a
            // separate set_difficulty packet — the TicketMask subtype isn't
            // listed in cleartext (only Pll/Ss/SsdnPro/PllSel). Live-unit
            // testing will resolve. See plan §B.3 open question 3.
            self.set_difficulty(initial_difficulty)?;

            Ok(detected)
        }

        fn send_work(&mut self, job: &MiningJob) -> Result<(), AsicError> {
            // Record this job's base fields (keyed by the dispatcher job id)
            // so late nonce reports reconstruct against the job that actually
            // hashed them, not whichever job was dispatched most recently.
            self.roll_ctx.bases.record(job.job_id, job.version, job.ntime);

            // Complete mm_work SET_JOB (2026-08-29: the scaffold's tentative
            // 81-byte layout is retired — the held-binary RE pinned SET_JOB
            // as the raw 7408-byte mm_work struct, codec in mm_work.rs). The
            // version-roll table rides inside every job (no config opcode).
            let work = build_mm_work(job, self.roll_ctx.version_mask)?;
            if !job.has_coinbase_parts() {
                warn!(
                    job = job.job_id,
                    "SET_JOB without coinbase parts — the RT blob cannot mine an incomplete mm_work"
                );
            }
            let payload = work.encode().map_err(map_proto_err)?;
            self.send(Self::command(Opcode::SetJob, None), &payload)
        }

        fn process_work(&mut self, rx_buf: &[u8]) -> Result<Vec<AsicResult>, AsicError> {
            if rx_buf.len() < MM_PKG_SIZE {
                return Ok(Vec::new());
            }
            // Replies arrive on mtype 0x2 (ASIC daemon → host), so the
            // compound type word must be read in the MmToHost byte order.
            let pkg = MmPkg::decode(rx_buf, CodecDirection::MmToHost).map_err(map_proto_err)?;
            Self::decode_one(&pkg, &self.roll_ctx.clone())
        }

        fn set_frequency(&mut self, target_freq: f32) -> Result<(), AsicError> {
            let target_freq = validate_avalon_frequency_mhz(target_freq)?;
            // SET_ASIC subtype Pll rides in the type word; the payload carries
            // only the PLL register encoding. Plan §B.3 open question 2: exact
            // A3197/A3198 PLL encoding pending RE. Scaffold ships a placeholder
            // LE u32 representation of the integer MHz value (zero-extended to
            // 8 bytes to leave room for the expected register-level encoding)
            // so the wire path is exercised; the live RT-Smart blob will
            // likely reject this until we match the real register layout.
            let mhz_int: u32 = target_freq.round() as u32;
            let mut payload = [0u8; 8];
            payload[0..4].copy_from_slice(&mhz_int.to_le_bytes());
            self.send(Self::command(Opcode::SetAsic, Some(SetAsicSubtype::Pll as u8)), &payload)?;
            self.current_frequency = target_freq;
            Ok(())
        }

        fn set_version_mask(&mut self, mask: u32) -> Result<(), AsicError> {
            // Version-rolling is REAL on this chain: the ASIC-side engine
            // mines a BIP320 version-roll slot table and every nonce report
            // carries the slot index it hashed with (mid_id). Record the mask;
            // reconstruction uses the SHARED table model in
            // dcentaxe_asic::common — now the STOCK construction (slot 0 =
            // no roll, slot 1 = full mask, single bits 15..=28 ascending,
            // 8 entries; two Canaan-origin sources agree, see
            // dcent-avalon-proto/src/mm_work.rs). Never drop the mask and
            // never reject rolled shares — the old no-op here failed every
            // rolled share.
            //
            // PUSH MECHANISM (2026-08-29 held-evidence exhaustion, formerly
            // an open research item): there is NO separate vmask config
            // opcode — Canaan's cgminer fills `mm_work.vmask[8]` (offset
            // 0x1CC4 of the 7408-byte SET_JOB payload) with byte-swapped
            // ABSOLUTE version words, so the table rides inside every
            // SET_JOB. Pushing it therefore happens in send_work once the
            // AsicDriver interface carries coinbase (MiningJob lacks
            // coinbase/merkle branches today — the recorded integration
            // gap; the codec itself is landed in mm_work.rs).
            self.roll_ctx.version_mask = mask;
            warn!(
                mask,
                slots = version_roll_table(mask).len(),
                "AvalonShimDriver: version mask recorded; table pushes per-job via mm_work.vmask (codec landed; awaits the coinbase-carrying job interface)"
            );
            Ok(())
        }

        fn set_difficulty(&mut self, _difficulty: f64) -> Result<(), AsicError> {
            // SET_ASIC TicketMask-equivalent subtype is not in the cleartext
            // mm_miner.h subtype list (Pll/Ss/SsdnPro/PllSel only). Plan §B.3
            // open question 3 — likely lives elsewhere (SET_SYS subtype, or
            // embedded in SET_JOB). Phase 1 scaffold no-ops. Filter happens
            // host-side in MiningDispatcher until we wire the on-chip filter.
            Ok(())
        }

        fn set_max_baud(&mut self) -> Result<u32, AsicError> {
            // K230's RT-Smart owns the chip UART; we have no baud control.
            Ok(PLACEHOLDER_BAUD)
        }

        fn read_registers(&mut self) -> Result<Vec<RegisterData>, AsicError> {
            // Poll STATUS_ASIC for telemetry. Phase 1: just request PLL +
            // Temp + Volt; richer per-chip slicing comes later.
            let mut out = Vec::new();
            for sub in [
                StatusAsicSubtype::Pll,
                StatusAsicSubtype::Temp,
                StatusAsicSubtype::Volt,
            ] {
                self.send(Self::command(Opcode::StatusAsic, Some(sub as u8)), &[])?;
                let pkg = self.recv_asic_to_host()?;
                if pkg.header.type_word.primary != Opcode::StatusAsic {
                    continue;
                }
                if let Some(reg) = decode_status_asic(&pkg) {
                    out.push(reg);
                }
            }
            Ok(out)
        }

        fn chip_count(&self) -> u8 {
            self.chip_count
        }

        fn current_frequency(&self) -> f32 {
            self.current_frequency
        }

        fn read_responses(&mut self, timeout_ms: u16) -> Result<Vec<AsicResult>, AsicError> {
            // Non-blocking bounded drain (P2 liveness fix): the old single
            // BLOCKING msgrcv hung the whole mining loop whenever the queue
            // went quiet. Poll with IPC_NOWAIT until the timeout budget is
            // spent; after the first message, keep draining only while the
            // queue keeps yielding (two consecutive empty polls end the
            // batch) so one tick cannot monopolize the loop.
            let deadline = std::time::Instant::now()
                .checked_add(std::time::Duration::from_millis(timeout_ms as u64))
                .expect("valid deadline");
            let mut out: Vec<AsicResult> = Vec::new();
            let mut consecutive_empty = 0u8;
            loop {
                match self.msgq.try_recv(Some(Direction::AsicToHost)) {
                    Ok(Some(pkg)) => {
                        consecutive_empty = 0;
                        let roll = self.roll_ctx.clone();
                        out.extend(Self::decode_one(&pkg, &roll)?);
                        if out.len() >= READ_RESPONSES_MAX_BATCH {
                            warn!(batch = out.len(), "read_responses hit the batch cap");
                            break;
                        }
                    }
                    Ok(None) => {
                        if !out.is_empty() {
                            consecutive_empty += 1;
                            if consecutive_empty >= 2 {
                                break; // queue drained
                            }
                        } else if std::time::Instant::now() >= deadline {
                            break; // nothing arrived within the budget
                        }
                        std::thread::sleep(std::time::Duration::from_millis(
                            READ_RESPONSES_POLL_INTERVAL_MS,
                        ));
                    }
                    Err(e) => return Err(AsicError::Serial(format!("msgrcv: {}", e))),
                }
            }
            Ok(out)
        }
    }

    impl AvalonShimDriver {
        /// Decode a single received mm_pkg into zero or more `AsicResult`s,
        /// reconstructing the rolled version + rolled ntime from the report's
        /// slot index and roll count BEFORE share verify.
        fn decode_one(pkg: &MmPkg, roll: &RollContext) -> Result<Vec<AsicResult>, AsicError> {
            match pkg.header.type_word.primary {
                Opcode::StatusNonce => {
                    let nonce = MinerNonce::decode(pkg.payload_valid()).ok_or_else(|| {
                        AsicError::InvalidResponse("STATUS_NONCE payload < 20 bytes".into())
                    })?;
                    // MinerNonce.valid (4-bit) is unresolved in the held-binary
                    // bitfield RE (assert-flag vs counter); PoW verification is
                    // the authoritative gate, so the field is carried, not
                    // trusted. Do not filter on it until capture pins semantics.
                    //
                    // Base fields resolve per the job the report echoes; an id
                    // with no resolvable base (nothing dispatched, or long
                    // evicted) is unreconstructable: drop loudly rather than
                    // rebuild on a guess.
                    let job_key = (nonce.job_id & 0xFF) as u8;
                    let Some((base_version, base_ntime)) = roll.bases.get(job_key) else {
                        warn!(
                            job = job_key,
                            "STATUS_NONCE echoed a job with no resolvable base — dropping record"
                        );
                        return Ok(Vec::new());
                    };
                    // Slot index -> shared candidate table -> the version the
                    // chip actually hashed. An index outside the configured
                    // table is a table/driver mismatch: drop the record loudly
                    // rather than submit a wrong-version share.
                    let rolled_version =
                        match reconstruct_rolled_version(base_version, roll.version_mask, nonce.mid_id) {
                            Some(v) => v,
                            None => {
                                warn!(
                                    mid_id = nonce.mid_id,
                                    slots = version_roll_table(roll.version_mask).len(),
                                    "STATUS_NONCE version-roll slot outside the configured table — dropping record"
                                );
                                return Ok(Vec::new());
                            }
                        };
                    // The chip rolls ntime on-die; the share header must be
                    // built from the rolled value.
                    let rolled_ntime = base_ntime.wrapping_add(nonce.ntime as u32);
                    Ok(vec![AsicResult::Nonce {
                        job_id: job_key,
                        nonce: nonce.nonce,
                        rolled_version,
                        rolled_ntime,
                        asic_nr: nonce.miner_id,
                        timestamp_us: now_us(),
                    }])
                }
                Opcode::StatusAsic => Ok(decode_status_asic(pkg)
                    .into_iter()
                    .map(register_to_result)
                    .collect()),
                _ => Ok(Vec::new()),
            }
        }
    }

    fn decode_status_asic(pkg: &MmPkg) -> Option<RegisterData> {
        // Replies carry the queried subtype back in the type word; the
        // payload leads with the telemetry word itself.
        let subtype = pkg.header.type_word.subtype?;
        if pkg.header.len < 4 {
            return None;
        }
        let value = u32::from_le_bytes([
            pkg.payload[0],
            pkg.payload[1],
            pkg.payload[2],
            pkg.payload[3],
        ]);
        let register_type = match subtype {
            x if x == StatusAsicSubtype::Pll as u8 => RegisterType::PllParam,
            // SAFETY: Temp/Volt were previously mapped to RegisterType::Hashrate
            // as a "best-fit placeholder". That mislabel meant a raw temperature
            // ADC word would reach any read_registers() consumer typed as
            // HASHRATE. They now use the honest DCENT-extension variants.
            x if x == StatusAsicSubtype::Temp as u8 => RegisterType::Temperature,
            x if x == StatusAsicSubtype::Volt as u8 => RegisterType::Voltage,
            _ => RegisterType::Invalid,
        };
        Some(RegisterData {
            register_type,
            asic_nr: 0,
            value,
        })
    }

    fn register_to_result(reg: RegisterData) -> AsicResult {
        AsicResult::Register {
            register_type: reg.register_type,
            asic_nr: reg.asic_nr,
            value: reg.value,
            timestamp_us: now_us(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use dcent_avalon_proto::mm_pkg::MINER_NONCE_SIZE;

        /// Reply type word as cg_miner would parse it: primary in the low
        /// byte, queried subtype echoed in the high byte.
        fn reply(primary: Opcode, subtype: Option<u8>) -> TypeWord {
            TypeWord {
                primary,
                subtype,
                direction: CodecDirection::MmToHost,
            }
        }

        /// Test roll context: BIP320 mask 0x1FFFE000, with the sample nonce's
        /// echoed job (0x1234_5678 & 0xFF = 0x78) dispatched at base version
        /// 0x2000_0000 / base ntime 0x6651_0000.
        fn test_roll_ctx() -> RollContext {
            let mut ctx = RollContext {
                version_mask: 0x1FFF_E000,
                bases: RollBases::default(),
            };
            ctx.bases.record(0x78, 0x2000_0000, 0x6651_0000);
            ctx
        }

        fn sample_status_nonce() -> MinerNonce {
            MinerNonce {
                job_id: 0x1234_5678,
                nonce2: 0x9ABC_DEF0,
                nonce: 0xDEAD_BEEF,
                asic_id: 0x1FF,
                miner_id: 0x2A,
                ntime: 0xA5,
                mid_id: 0x07,
                valid: 0x0E,
                last_job_nonce2: 0xCAFE_F00D,
            }
        }

        fn status_nonce_pkg(valid_len: usize, pad_to_nonce: bool) -> MmPkg {
            let wire = sample_status_nonce().encode();
            let mut pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &wire[..valid_len]).unwrap();
            if pad_to_nonce {
                pkg.payload[valid_len..MINER_NONCE_SIZE]
                    .copy_from_slice(&wire[valid_len..MINER_NONCE_SIZE]);
            }
            pkg
        }

        fn assert_short_status_nonce_rejected(pkg: &MmPkg) {
            let err = AvalonShimDriver::decode_one(pkg, &test_roll_ctx()).unwrap_err();
            match err {
                AsicError::InvalidResponse(message) => {
                    assert!(message.contains("STATUS_NONCE payload < 20 bytes"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        fn assert_status_nonce_decodes(pkg: &MmPkg) {
            let results = AvalonShimDriver::decode_one(pkg, &test_roll_ctx()).unwrap();
            assert_eq!(results.len(), 1);
            match &results[0] {
                AsicResult::Nonce {
                    job_id,
                    nonce,
                    rolled_version,
                    rolled_ntime,
                    asic_nr,
                    ..
                } => {
                    assert_eq!(*job_id, 0x78);
                    assert_eq!(*nonce, 0xDEAD_BEEF);
                    // mid_id 0x07 indexes the STOCK candidate list: single-bit
                    // slots ascend from bit 15, so slot 7 = bit 20 (bits 13/14
                    // never receive their own slot).
                    assert_eq!(*rolled_version, 0x2000_0000 | (1 << 20));
                    // ntime roll count 0xA5 added to the base ntime.
                    assert_eq!(*rolled_ntime, 0x6651_0000u32.wrapping_add(0xA5));
                    assert_eq!(*asic_nr, 0x2A);
                }
                other => panic!("unexpected result: {other:?}"),
            }
        }

        #[test]
        fn decode_one_rejects_status_nonce_len_zero_even_with_padded_tail() {
            let pkg = status_nonce_pkg(0, true);
            assert_short_status_nonce_rejected(&pkg);
        }

        #[test]
        fn decode_one_rejects_status_nonce_len_19_even_with_padded_tail() {
            let pkg = status_nonce_pkg(MINER_NONCE_SIZE - 1, true);
            assert_short_status_nonce_rejected(&pkg);
        }

        #[test]
        fn decode_one_accepts_status_nonce_len_20() {
            let pkg = status_nonce_pkg(MINER_NONCE_SIZE, false);
            assert_status_nonce_decodes(&pkg);
        }

        #[test]
        fn decode_one_accepts_status_nonce_full_payload() {
            let wire = sample_status_nonce().encode();
            let mut payload = [0xA5u8; MM_PKG_PAYLOAD_SIZE];
            payload[..MINER_NONCE_SIZE].copy_from_slice(&wire);
            let pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &payload).unwrap();

            assert_status_nonce_decodes(&pkg);
        }

        /// REGRESSION PIN (version-rolling, 2026-08-29): the old shim hardcoded
        /// rolled_version = 0 and no-opped the mask — every rolled share failed.
        /// Reconstruction must now select the hashed version from the slot
        /// table; a slot outside the table drops the record instead of guessing.
        #[test]
        fn status_nonce_rolls_version_and_ntime_from_the_slot_table() {
            let mut nonce = sample_status_nonce();
            nonce.mid_id = 0; // slot 0 = no roll
            nonce.ntime = 3;
            let pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &nonce.encode()).unwrap();
            let results = AvalonShimDriver::decode_one(&pkg, &test_roll_ctx()).unwrap();
            match &results[0] {
                AsicResult::Nonce {
                    rolled_version,
                    rolled_ntime,
                    ..
                } => {
                    assert_eq!(*rolled_version, 0x2000_0000 & !0x1FFF_E000);
                    assert_eq!(*rolled_ntime, 0x6651_0003);
                }
                other => panic!("expected a nonce, got {other:?}"),
            }

            // Full-mask slot.
            let mut nonce = sample_status_nonce();
            nonce.mid_id = 1;
            let pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &nonce.encode()).unwrap();
            let results = AvalonShimDriver::decode_one(&pkg, &test_roll_ctx()).unwrap();
            match &results[0] {
                AsicResult::Nonce { rolled_version, .. } => {
                    assert_eq!(*rolled_version, (0x2000_0000 & !0x1FFF_E000) | 0x1FFF_E000);
                }
                other => panic!("expected a nonce, got {other:?}"),
            }

            // Out-of-table slot: record dropped, not mis-submitted.
            let mut nonce = sample_status_nonce();
            nonce.mid_id = 0x3F;
            let pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &nonce.encode()).unwrap();
            assert!(AvalonShimDriver::decode_one(&pkg, &test_roll_ctx())
                .unwrap()
                .is_empty());
        }

        /// REGRESSION PIN (per-job bases, 2026-08-29): a nonce echoing an OLD
        /// job must reconstruct against that job's base fields, not the latest
        /// dispatch — and a job never dispatched is dropped, never guessed.
        #[test]
        fn status_nonce_reconstructs_against_the_echoed_jobs_base() {
            let mut ctx = RollContext {
                version_mask: 0x1FFF_E000,
                bases: RollBases::default(),
            };
            // Two dispatches with different bases; the sample nonce echoes
            // job 0x78 = the FIRST one.
            ctx.bases.record(0x78, 0x2000_0000, 0x6651_0000);
            ctx.bases.record(0x99, 0x2800_0000, 0x7000_0000);

            let nonce = sample_status_nonce(); // job 0x...78, mid_id 7, ntime 0xA5
            let pkg = MmPkg::new(reply(Opcode::StatusNonce, None), &nonce.encode()).unwrap();
            let results = AvalonShimDriver::decode_one(&pkg, &ctx).unwrap();
            match &results[0] {
                AsicResult::Nonce {
                    rolled_version, rolled_ntime, ..
                } => {
                    // Old job's base version masked + slot-7 single bit
                    // (bit 20 under the stock 15..=28 construction).
                    assert_eq!(*rolled_version, 0x2000_0000 | (1 << 20));
                    // Old job's base ntime + the roll count — NOT 0x7000_0000.
                    assert_eq!(*rolled_ntime, 0x6651_0000u32.wrapping_add(0xA5));
                }
                other => panic!("expected a nonce, got {other:?}"),
            }

            // A report echoing a job that was never dispatched (empty bases)
            // is unreconstructable and must be dropped.
            let empty = RollContext {
                version_mask: 0x1FFF_E000,
                bases: RollBases::default(),
            };
            assert!(AvalonShimDriver::decode_one(&pkg, &empty).unwrap().is_empty());
        }

        fn status_asic_pkg(subtype_byte: u8, value: u32) -> MmPkg {
            let mut payload = [0u8; 4];
            payload.copy_from_slice(&value.to_le_bytes());
            MmPkg::new(reply(Opcode::StatusAsic, Some(subtype_byte)), &payload).unwrap()
        }

        /// REGRESSION PIN (Wave 6 R4b): STATUS_ASIC Temp/Volt must decode as
        /// their honest telemetry types, NEVER as Hashrate. The pre-fix code
        /// mapped both to `RegisterType::Hashrate` ("best-fit placeholder"),
        /// which would surface a raw temperature ADC word as hashrate to any
        /// `read_registers()` consumer.
        #[test]
        fn status_asic_temp_and_volt_never_decode_as_hashrate() {
            for (subtype, expected) in [
                (StatusAsicSubtype::Pll, RegisterType::PllParam),
                (StatusAsicSubtype::Temp, RegisterType::Temperature),
                (StatusAsicSubtype::Volt, RegisterType::Voltage),
            ] {
                let pkg = status_asic_pkg(subtype as u8, 0x1234_5678);
                let reg = decode_status_asic(&pkg).expect("known subtype must decode");
                assert_eq!(reg.register_type, expected, "subtype {subtype:?}");
                assert_ne!(
                    reg.register_type,
                    RegisterType::Hashrate,
                    "telemetry word mislabelled as hashrate (subtype {subtype:?})"
                );
                assert_eq!(reg.value, 0x1234_5678);
            }
        }

        #[test]
        fn status_asic_short_payload_or_unknown_subtype_stays_closed() {
            // len < 4 (no telemetry word) → None, not a guess.
            let short =
                MmPkg::new(reply(Opcode::StatusAsic, Some(StatusAsicSubtype::Temp as u8)), &[])
                    .unwrap();
            assert!(decode_status_asic(&short).is_none());

            // Unknown subtype → Invalid, never a telemetry/hashrate type.
            let unknown = status_asic_pkg(0xEE, 0xDEAD_BEEF);
            assert_eq!(
                decode_status_asic(&unknown).unwrap().register_type,
                RegisterType::Invalid
            );
        }
    }

        /// 2026-08-29 interface extension: send_work now emits the complete
        /// 7408-byte mm_work (the tentative 81-byte scaffold is retired).
        /// Pin the builder: header assembly, vmask table placement, coinbase
        /// riding through, and symbol-verified total size.
        #[test]
        fn build_mm_work_produces_the_complete_symbol_sized_payload() {
            let job = MiningJob::new_full(
                0x5A,
                0x2000_0000,
                [0x11; 32],
                [0x22; 32],
                0x6651_0000,
                0x1703_2E1D,
                0x0304_0506,
            )
            .with_coinbase_parts(
                vec![0xCB; 48],
                vec![[0x33; 32], [0x44; 32]],
                0xBBAA_0201,
                41,
                4,
                Some([0xFF; 32]),
            );
            let work = build_mm_work(&job, 0x1FFF_E000).expect("complete job builds");
            let buf = work.encode().expect("encodes");
            assert_eq!(buf.len(), 7408);

            // Field placements match the symbol-verified offsets.
            assert_eq!(
                &buf[dcent_avalon_proto::mm_work::off::JOB_ID..dcent_avalon_proto::mm_work::off::JOB_ID + 4],
                &0x5Au32.to_le_bytes()
            );
            assert_eq!(
                &buf[dcent_avalon_proto::mm_work::off::COINBASE_LEN..dcent_avalon_proto::mm_work::off::COINBASE_LEN + 8],
                &48u64.to_le_bytes()
            );
            assert_eq!(buf[dcent_avalon_proto::mm_work::off::COINBASE], 0xCB);
            assert_eq!(
                &buf[dcent_avalon_proto::mm_work::off::NONCE2..dcent_avalon_proto::mm_work::off::NONCE2 + 4],
                &0xBBAA_0201u32.to_le_bytes()
            );
            assert_eq!(&buf[dcent_avalon_proto::mm_work::off::HEADER..dcent_avalon_proto::mm_work::off::HEADER + 4],
                       &0x2000_0000u32.to_le_bytes());
            assert_eq!(&buf[dcent_avalon_proto::mm_work::off::HEADER + 4..dcent_avalon_proto::mm_work::off::HEADER + 36], &[0x11; 32]);
            assert_eq!(&buf[dcent_avalon_proto::mm_work::off::HEADER + 76..dcent_avalon_proto::mm_work::off::HEADER + 80],
                       &0x0304_0506u32.to_le_bytes());
            assert_eq!(&buf[dcent_avalon_proto::mm_work::off::TARGET..dcent_avalon_proto::mm_work::off::TARGET + 32], &[0xFF; 32]);

            // The vmask table rides inside the job: slot 0 = base, slot 1 =
            // base|mask, as byte-swapped absolute words (stock construction).
            let slot = |i: usize| {
                u32::from_le_bytes(
                    buf[dcent_avalon_proto::mm_work::off::VMASK + i * 4..dcent_avalon_proto::mm_work::off::VMASK + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            };
            assert_eq!(slot(0), 0x2000_0000u32.swap_bytes());
            assert_eq!(slot(1), (0x2000_0000u32 | 0x1FFF_E000).swap_bytes());
            assert_eq!(slot(2), (0x2000_0000u32 | (1u32 << 15)).swap_bytes());
            assert_eq!(work.nmerkles, 2);
            assert_eq!(work.nonce2_offset, 41);
            assert_eq!(work.nonce2_size, 4);
            assert_eq!(work.job_id, 0x5A);
        }

        /// A job without coinbase parts still builds the complete SHAPE
        /// (the send path warns; the RT blob rejects) — the layout never
        /// silently regresses to the retired 81-byte scaffold.
        #[test]
        fn build_mm_work_without_coinbase_keeps_the_complete_shape() {
            let job = MiningJob::new_full(1, 0x2000_0000, [0; 32], [0; 32], 1, 1, 0);
            assert!(!job.has_coinbase_parts());
            let work = build_mm_work(&job, 0).expect("still builds");
            assert_eq!(work.encode().expect("encodes").len(), 7408);
            assert!(work.coinbase.is_empty());
            // Zero mask: slot 0 = base, slot 1 = base|0 = base (stock list
            // degenerates to [base, base] with no single-bit slots).
            assert_eq!(work.vmask[0], 0x2000_0000u32.swap_bytes());
            assert_eq!(work.vmask[1], 0x2000_0000u32.swap_bytes());
        }
}

#[cfg(unix)]
pub use unix_driver::AvalonShimDriver;

pub fn validate_avalon_frequency_mhz(
    target_freq: f32,
) -> Result<f32, dcentaxe_asic::common::AsicError> {
    let min = dcentaxe_asic::common::AsicModel::Avalon.min_frequency();
    let max = dcentaxe_asic::common::AsicModel::Avalon.max_frequency();
    if !target_freq.is_finite() || target_freq < min || target_freq > max {
        return Err(dcentaxe_asic::common::AsicError::InitFailed(format!(
            "Avalon frequency {target_freq:?} MHz outside supported envelope {min:.0}-{max:.0} MHz"
        )));
    }
    Ok(target_freq)
}

// ── Non-Unix stub so the crate compiles on Windows hosts during dev ──────────

#[cfg(not(unix))]
mod stub {
    use super::validate_avalon_frequency_mhz;
    use dcentaxe_asic::common::{AsicError, AsicResult, MiningJob, RegisterData};
    use dcentaxe_asic::AsicDriver;

    pub struct AvalonShimDriver;

    impl AvalonShimDriver {
        pub fn open_default() -> Result<Self, AsicError> {
            Err(AsicError::Serial(
                "AvalonShimDriver requires a Unix host (SysV msgq)".into(),
            ))
        }
    }

    impl AsicDriver for AvalonShimDriver {
        fn init(&mut self, _: f32, _: u8, _: f64) -> Result<u8, AsicError> {
            Err(AsicError::InitFailed("not supported on this target".into()))
        }
        fn send_work(&mut self, _: &MiningJob) -> Result<(), AsicError> {
            Err(AsicError::InitFailed("not supported on this target".into()))
        }
        fn process_work(&mut self, _: &[u8]) -> Result<Vec<AsicResult>, AsicError> {
            Ok(Vec::new())
        }
        fn set_frequency(&mut self, target_freq: f32) -> Result<(), AsicError> {
            validate_avalon_frequency_mhz(target_freq)?;
            Ok(())
        }
        fn set_version_mask(&mut self, _: u32) -> Result<(), AsicError> {
            Ok(())
        }
        fn set_difficulty(&mut self, _: f64) -> Result<(), AsicError> {
            Ok(())
        }
        fn set_max_baud(&mut self) -> Result<u32, AsicError> {
            Ok(0)
        }
        fn read_registers(&mut self) -> Result<Vec<RegisterData>, AsicError> {
            Ok(Vec::new())
        }
        fn chip_count(&self) -> u8 {
            0
        }
        fn current_frequency(&self) -> f32 {
            0.0
        }
        fn read_responses(&mut self, _: u16) -> Result<Vec<AsicResult>, AsicError> {
            Ok(Vec::new())
        }
    }
}

#[cfg(not(unix))]
pub use stub::AvalonShimDriver;

#[cfg(test)]
mod tests {
    use super::validate_avalon_frequency_mhz;
    use dcentaxe_asic::common::AsicModel;

    #[test]
    fn avalon_frequency_helper_rejects_out_of_range_values() {
        assert!(validate_avalon_frequency_mhz(99.9).is_err());
        assert!(validate_avalon_frequency_mhz(600.1).is_err());
        assert!(validate_avalon_frequency_mhz(f32::NAN).is_err());
    }

    #[test]
    fn avalon_frequency_helper_accepts_documented_envelope_and_default() {
        assert_eq!(
            validate_avalon_frequency_mhz(AsicModel::Avalon.min_frequency()).unwrap(),
            100.0
        );
        assert_eq!(
            validate_avalon_frequency_mhz(AsicModel::Avalon.default_frequency()).unwrap(),
            500.0
        );
        assert_eq!(
            validate_avalon_frequency_mhz(AsicModel::Avalon.max_frequency()).unwrap(),
            600.0
        );
    }
}

// ── BYTE-EXACT PRE-COLLAPSE BODY ENDS ON THE PREVIOUS LINE ──────────────────
//
// Everything below is NEW (2026-08-03 collapse). It compiles into BOTH consumer
// crates — which is precisely the property it asserts.

/// Repo-relative path of this shared source.
///
/// Each consumer crate asserts this constant against the file it `include_str!`s
/// from its own `include!` path, so a future session that re-forks the shim into
/// a local `src/` copy has to deliberately falsify the constant rather than
/// drift silently.
pub const SHARED_SHIM_SOURCE: &str = "shared/dcent-avalon-proto/shared/avalon_shim_driver.rs";

#[cfg(test)]
mod shared_shim_collapse_contract {
    use super::validate_avalon_frequency_mhz;

    /// GOLDEN VECTOR for the collapsed path. This module is compiled once per
    /// consumer crate, so an identical assertion runs in the industrial crate
    /// and in the home crate. If the two ever produced different results, one
    /// of these two test runs would fail.
    ///
    /// The vector pins the only publicly reachable behaviour of the shim that
    /// does not need a live SysV message queue: the frequency envelope guard.
    /// The decode paths (`decode_one`, `decode_status_asic`) are pinned by the
    /// pre-collapse tests in the body above, which are now likewise compiled
    /// into both crates from this one file.
    #[test]
    fn frequency_guard_golden_vector_is_identical_in_every_consumer() {
        // (input, accepted?) — envelope is AsicModel::Avalon's 100..=600 MHz.
        const VECTOR: [(f32, bool); 9] = [
            (f32::NAN, false),
            (f32::NEG_INFINITY, false),
            (f32::INFINITY, false),
            (-1.0, false),
            (99.9, false),
            (100.0, true),
            (500.0, true),
            (600.0, true),
            (600.1, false),
        ];
        for (input, accepted) in VECTOR {
            let got = validate_avalon_frequency_mhz(input);
            assert_eq!(
                got.is_ok(),
                accepted,
                "frequency guard disagreed with the golden vector at {input:?}"
            );
            if let Ok(v) = got {
                assert_eq!(
                    v, input,
                    "an accepted frequency must pass through unchanged"
                );
            }
        }
    }

    #[test]
    fn the_shared_source_path_constant_is_the_canonical_one() {
        assert_eq!(
            super::SHARED_SHIM_SOURCE,
            "shared/dcent-avalon-proto/shared/avalon_shim_driver.rs"
        );
    }
}
