//! Mid-run chip-side work-invalidate evidence (Gap 1 desk RE, 2026-08-19).
//!
//! Campaign question: after a mid-run pool `clean_jobs`, does ANY held
//! firmware issue a chip-side work-invalidate on BM1366 (occupied hashboard
//! slots keep hashing the retired job; `leftover_hit > 0`, `meets = 0` in
//! every live run)? Held evidence so far says the BM1366 UART protocol has
//! no mid-run job-abort opcode - only Chain Inactive CMD=3
//! (`55 AA 53 05 00 00 03`), which every held firmware uses only at init.
//!
//! Three desk threads were exhausted this session against held binaries
//! (all paths relative to the repo root):
//!
//! 1. **VNish (Awesome) S19k Pro cgminer v1.3.3** -
//!    `tmp/s19k-awesome-v133/aml/rootfs/usr/bin/cgminer` (6,253,540 B,
//!    ELF32 ARM EABI5, static, stripped, pure-ARM code; extracted from the
//!    user-provided `awesome-s19kpro-aml-nand-v1.3.3-install.tar.gz`).
//!    The XOR string table was re-decoded (scratch decode had been lost);
//!    the full TX surface was enumerated by instruction-level scan.
//! 2. **Stock Bitmain S19j Pro cgminer (20221226)** -
//!
//!    (425,084 B; the CVCtrl variant is byte-identical apart from BuildID).
//!    The `bitmain_flush_api` path was xref'd end to end.
//! 3. **AMTC S19k Pro factory jig**
//!    (2,087,696 B, ELF32 ARM EABI5, dynamic, stripped, THUMB code).
//!
//! Headline (negative) result: **no held firmware was found to emit any
//! chip-side work-invalidate mid-run.** The stock cgminer flush is purely
//! host-side (flag + job-buffer rebuild + new job over an internal socket;
//! that binary contains zero `55 AA` bytes and no tty device strings, so it
//! physically cannot reach the chain UART). The VNish binary funnels every
//! chain frame through four gateways that prepend `55 AA` and enqueue a
//! caller-supplied payload; the caller-side frame-TYPE vocabulary behind
//! those gateways is dispatch-obfuscated and stays unrecovered (pinned as a
//! refuse below, not hidden). The jig's own command-label strings enumerate
//! its whole chip-command vocabulary and contain no abort/invalidate; its
//! "Set chain inactive" exists only inside init sequences that continue
//! directly into "Set asic address".

/// VNish v1.3.3 AML cgminer whole-file sha256 (evidence pin; the binary
/// stays in the desk-extracted installer tree, never shipped).
pub const S19K_VNISH_V133_CGMINER_SHA256: &str =
    "866e3d4fa832b9fa48c32cf9c3f4e5edada943c93fdc4f090f05765c0b36eae8";

/// VNish cgminer size in bytes.
pub const S19K_VNISH_V133_CGMINER_SIZE: u64 = 6_253_540;

/// VNish string-table file offset (`.data` starts at file `0x5c6000`,
/// vaddr `0x5e6000`) and the self-keying XOR algorithm tag.
pub const S19K_VNISH_V133_STRTAB_FILE_OFF: usize = 0x5c_6000;
/// Table algorithm: per-string single-byte XOR; the encoded NUL terminator
/// (the byte trailing each string) equals the key byte.
pub const S19K_VNISH_V133_STRTAB_ALGORITHM: &str =
    "per-string single-byte XOR; trailing byte = key";

/// Encoded `Job for work_id = %02x not found` at file `0x5cf142`
/// (vaddr `0x5ef142`), key byte `0x5c` ( ledger string, re-decoded).
pub const S19K_VNISH_V133_JOB_NOT_FOUND_ENC: [u8; 33] = [
    0x16, 0x33, 0x3e, 0x7c, 0x3a, 0x33, 0x2e, 0x7c, 0x2b, 0x33, 0x2e, 0x37, 0x03, 0x35, 0x38, 0x7c,
    0x61, 0x7c, 0x79, 0x6c, 0x6e, 0x24, 0x7c, 0x32, 0x33, 0x28, 0x7c, 0x3a, 0x33, 0x29, 0x32, 0x38,
    0x5c,
];

/// Encoded `/tmp/build/src/backend/work-gen/work-gen.c` at file `0x5cf195`
/// (vaddr `0x5ef195`), key byte `0xcf` - the leaked VNish source path that
/// names the 5-thread work-gen backend.
pub const S19K_VNISH_V133_WORKGEN_C_ENC: [u8; 43] = [
    0xe0, 0xbb, 0xa2, 0xbf, 0xe0, 0xad, 0xba, 0xa6, 0xa3, 0xab, 0xe0, 0xbc, 0xbd, 0xac, 0xe0, 0xad,
    0xae, 0xac, 0xa4, 0xaa, 0xa1, 0xab, 0xe0, 0xb8, 0xa0, 0xbd, 0xa4, 0xe2, 0xa8, 0xaa, 0xa1, 0xe0,
    0xb8, 0xa0, 0xbd, 0xa4, 0xe2, 0xa8, 0xaa, 0xa1, 0xe1, 0xac, 0xcf,
];

/// VNish work-gen thread-name/label strings (decoded this session): the
/// 5-thread architecture pins (uart read / gen work / gen chip work /
/// send work / parse chip replies) plus the failed-to-start messages.
pub const S19K_VNISH_V133_WORKGEN_THREAD_LABELS: [&str; 5] = [
    "uart%d@btm",
    "gen-work@btm",
    "send-work@btm",
    "uart-parse@btm",
    "Job for work_id = %02x not found",
];

/// VNish chain-frame TX gateway functions (vaddr): each mallocs `len + 2`,
/// writes the `55 AA` preamble halfword, `memcpy`s the caller payload,
/// takes a mutex, and pushes the frame onto the per-chain TX queue via
/// `S19K_VNISH_V133_QUEUE_PUSH`. Each address appears exactly once in the
/// file image (inside `.got`); all call sites are indirect.
pub const S19K_VNISH_V133_TX_GATEWAY_FNS: [u32; 4] =
    [0x000f_19a8, 0x0010_8f74, 0x0011_7428, 0x0011_baa4];

/// The shared TX-queue push (vaddr `0x10dad8`, prologue `f0 4f 2d e9`).
/// Exactly five `bl` sites target it - the five emit sites below, and no
/// others - so every queued chain frame carries the gateway preamble.
pub const S19K_VNISH_V133_QUEUE_PUSH: u32 = 0x0010_dad8;

/// The five `movw rX, #0xaa55` emit sites (vaddr). Instruction word
/// `0xE30A1A55` (bytes `55 1a 0a e3`) = `movw r1, #0xAA55`; a little-endian
/// `strh` of that halfword writes wire bytes `55 AA`.
pub const S19K_VNISH_V133_EMIT_SITES: [u32; 5] = [
    0x000f_19dc,
    0x0010_8fa8,
    0x0011_745c,
    0x0011_bb84,
    0x0011_bc08,
];

/// Bytes of the emit instruction `movw r1, #0xAA55` at all five sites.
pub const S19K_VNISH_V133_EMIT_MOVW_BYTES: [u8; 4] = [0x55, 0x1a, 0x0a, 0xe3];

/// VNish RX preamble parser: vaddr `0xbaecc` region reads bytes and
/// compares the first against `0xAA` (`aa 00 50 e3` at `0xbaed0`) and the
/// second against `0x55` (`55 00 50 e3` at `0xbaeec`) - the bit-reversed
/// wire view of the `55 AA` preamble (BM13xx reversed-bit UART dialect).
pub const S19K_VNISH_V133_RX_CMP_AA_VA: u32 = 0x000b_aed0;
pub const S19K_VNISH_V133_RX_CMP_55_VA: u32 = 0x000b_aeec;
pub const S19K_VNISH_V133_RX_CMP_AA_BYTES: [u8; 4] = [0xaa, 0x00, 0x50, 0xe3];
pub const S19K_VNISH_V133_RX_CMP_55_BYTES: [u8; 4] = [0x55, 0x00, 0x50, 0xe3];

/// Total `55 AA` byte pairs in the whole VNish cgminer file: nine. Six are
/// 6-byte dsPIC board-controller frames (`55 AA 04 <cmd> <val> <crc>`) in
/// `.rodata` at file `0x5a5fe8`..`0x5a6266`; three are coincidental byte
/// sequences in data tables. Zero `55 AA 21 36` (TYPE_JOB) and zero
/// `55 AA 53 05` (chain inactive) templates exist in initialized data.
pub const S19K_VNISH_V133_55AA_PAIR_TOTAL: usize = 9;
pub const S19K_VNISH_V133_55AA_CHIP_TEMPLATE_TOTAL: usize = 0;

/// First dsPIC board frame of the six in `.rodata` (file `0x5a5fe8`).
pub const S19K_VNISH_V133_PIC_FRAME_FIRST: [u8; 6] = [0x55, 0xaa, 0x04, 0x03, 0x07, 0x00];

/// Stock Bitmain S19j Pro (20221226) BB cgminer whole-file sha256.
pub const S19K_STOCK_CGMINER_SHA256: &str =
    "2a272bee98fc7a18bcfcae0cba1d72a99874d7be5aa883a5daff5feae410738e";

/// `55 AA` byte pairs and `/dev/ttyS*` strings inside the stock cgminer:
/// zero of each. This scheduler binary cannot emit a chain-UART frame at
/// all; chip I/O lives in the separate miner process.
pub const S19K_STOCK_CGMINER_55AA_PAIR_TOTAL: usize = 0;

/// Stock flush-request flag (`.bss` vaddr `0x87e50`). Set to 1 by the
/// stratum-side handler at vaddr `0x4ffb4`
/// (`movw r3,#0x7e50; movt r3,#8; mov r2,#1; str r2,[r3]`), consumed by the
/// work-gen loop at vaddr `0x5ca1c`..`0x5ca5c` which sets the device
/// "rebuild" byte at `dev + 0x2b8`, clears the flag, and calls
/// `rebuild_job_buf`.
pub const S19K_STOCK_FLUSH_FLAG_VA: u32 = 0x0008_7e50;
pub const S19K_STOCK_FLUSH_FLAG_SETTER_VA: u32 = 0x0004_ffb4;
pub const S19K_STOCK_FLUSH_FLAG_CONSUMER_VA: u32 = 0x0005_ca1c;
/// The `bl rebuild_job_buf` inside the consumer loop (vaddr `0x5ca5c`).
pub const S19K_STOCK_FLUSH_REBUILD_CALL_VA: u32 = 0x0005_ca5c;

/// Setter bytes at `0x4ffb0..0x4ffc0`:
/// `movw r3,#0x7e50; movt r3,#8; mov r2,#1; str r2,[r3]`.
pub const S19K_STOCK_FLUSH_SETTER_BYTES: [u8; 16] = [
    0x50, 0x3e, 0x07, 0xe3, // movw r3, #0x7e50
    0x08, 0x30, 0x40, 0xe3, // movt r3, #8
    0x01, 0x20, 0xa0, 0xe3, // mov r2, #1
    0x00, 0x20, 0x83, 0xe5, // str r2, [r3]
];

/// `rebuild_job_buf` function (vaddr `0x5c46c`), proven by its `__func__`
/// trace: the name string `"rebuild_job_buf"` (vaddr `0x74ab0`) is passed
/// with source file `"driver-btm-c5_socketa.c"` (vaddr `0x74724`) and line
/// numbers 222 (`0xde`) / 258 (`0x102`). Its single caller is the flag
/// consumer above.
pub const S19K_STOCK_REBUILD_JOB_BUF_FN_VA: u32 = 0x0005_c46c;
pub const S19K_STOCK_REBUILD_NAME_STR_VA: u32 = 0x0007_4ab0;
pub const S19K_STOCK_REBUILD_SRC_STR_VA: u32 = 0x0007_4724;
pub const S19K_STOCK_REBUILD_TRACE_LINES: [u16; 2] = [222, 258];

/// Stock flush-path log strings (vaddr): the api side logs
/// `"about to send a flush api semaphore"` at `0x74368` (xref `0x58120`,
/// then calls the socket-request helper with the `.data` command struct at
/// vaddr `0x875fc` whose embedded name field is `"bitmain_flush_api"`),
/// and the new work is sent with `"about to send job, size is %d"` at
/// `0x74348`.
pub const S19K_STOCK_FLUSH_SEM_MSG_VA: u32 = 0x0007_4368;
pub const S19K_STOCK_FLUSH_SEM_MSG_XREF_VA: u32 = 0x0005_8120;
pub const S19K_STOCK_FLUSH_API_STRUCT_VA: u32 = 0x0008_75fc;
pub const S19K_STOCK_SEND_JOB_MSG_VA: u32 = 0x0007_4348;

/// AMTC S19k Pro factory jig whole-file sha256 and size.
pub const S19K_JIG_SHA256: &str =
    "cd1b4c047d40d6de9e040dbda537a4944ff8290b278d22bc885ea9cae020c4eb";
pub const S19K_JIG_SIZE: u64 = 2_087_696;

/// Jig re-confirmation: zero `55 AA 21 36` (TYPE_JOB) and zero
/// `55 AA 53 05` (chain-inactive header) byte sequences in the whole file.
pub const S19K_JIG_55AA2136_HITS: usize = 0;
pub const S19K_JIG_55AA5305_HITS: usize = 0;

/// The only `55 AA` templates in the jig are 6/8-byte dsPIC board frames
/// starting at file `0x1927b0` (eleven frames, `55 AA 04/06/08 ...`).
pub const S19K_JIG_PIC_TABLE_FILE_OFF: usize = 0x19_27b0;
pub const S19K_JIG_PIC_TABLE_FRAME_COUNT: usize = 11;

/// Jig chip-command labels (decoded from `.rodata` `0x18a904..0x18ae00`;
/// file offsets, `__func__`-style): the complete command vocabulary. There
/// is no abort/invalidate/stop-work label anywhere in the binary.
pub const S19K_JIG_CHIP_COMMAND_LABELS: [&str; 11] = [
    "Set chain inactive",
    "Set asic address",
    "Set pulse_mode = 0x%02x, clk_sel = 0x%02x",
    "Set pwth_sel = 0x%02x, ccdly_sel = 0x%02x, swpf_mode = 0x%02x",
    "do_core_reset",
    "do_core_reset asic:%d",
    "set TM to 0xffffffff",
    "Set Diode_Vdd_Mux_Sel = 0x%03x",
    "Set chain baud as %d",
    "set freq to %.2f from matrix.",
    "set freq over.",
];

/// Jig "Set chain inactive" label vaddrs (`0x19ab4c` prefixed variant,
/// `0x19ab68` bare `__func__` copy). The bare label is referenced by
/// exactly five inlined copies of the init wrapper at vaddr `0x41218`,
/// `0x5e16c`, `0x5f28c`, `0x5f744`, `0x6022a` - and every one of them
/// continues directly into the "Set asic address" log-and-send sequence
/// (10 ms sleep between), i.e. init position, not a mid-run loop.
pub const S19K_JIG_CHAIN_INACTIVE_LABEL_VA: u32 = 0x0019_ab68;
pub const S19K_JIG_CHAIN_INACTIVE_INIT_SITES: [u32; 5] = [
    0x0004_1218,
    0x0005_e16c,
    0x0005_f28c,
    0x0005_f744,
    0x0006_022a,
];

/// Decode one VNish self-keying-XOR string: every byte XOR the trailing
/// terminator byte (the encoded NUL equals the key).
pub fn decode_s19k_vnish_selfkey_xor(encoded: &[u8]) -> Result<String, &'static str> {
    let (&key, body) = encoded
        .split_last()
        .ok_or("vnish string fixture is empty")?;
    if key == 0 {
        return Err("vnish string key byte must be nonzero");
    }
    let decoded: Vec<u8> = body.iter().map(|&b| b ^ key).collect();
    if decoded.iter().any(|&b| !(0x20..=0x7e).contains(&b)) {
        return Err("vnish string decode produced a non-printable byte");
    }
    String::from_utf8(decoded).map_err(|_| "vnish string decode is not UTF-8")
}

/// VNish work-gen architecture is pinned by its own strings: the leaked
/// `work-gen.c` source path plus the five thread labels, re-decoded from
/// the encoded table this session.
pub fn admit_s19k_vnish_workgen_architecture_strings() -> Result<(), &'static str> {
    let job = decode_s19k_vnish_selfkey_xor(&S19K_VNISH_V133_JOB_NOT_FOUND_ENC)?;
    if job != "Job for work_id = %02x not found" {
        return Err("vnish Job-for-work_id fixture must decode exactly");
    }
    let path = decode_s19k_vnish_selfkey_xor(&S19K_VNISH_V133_WORKGEN_C_ENC)?;
    if path != "/tmp/build/src/backend/work-gen/work-gen.c" {
        return Err("vnish work-gen.c fixture must decode exactly");
    }
    if !S19K_VNISH_V133_WORKGEN_THREAD_LABELS.contains(&"Job for work_id = %02x not found") {
        return Err("vnish thread label set must include the work-id lookup message");
    }
    if S19K_VNISH_V133_WORKGEN_THREAD_LABELS.len() != 5 {
        return Err("vnish work-gen must stay the 5-thread architecture");
    }
    Ok(())
}

/// Every identifiable chain-frame emission in the VNish cgminer funnels
/// through the four TX gateways: the only preamble materialization in the
/// whole 6.25 MB file is the `movw rX, #0xAA55` at the five emit sites,
/// the only callers of the shared TX-queue push are those same sites, and
/// no `55 AA` chip-frame template exists in initialized data.
pub fn admit_s19k_vnish_tx_gateway_funnel() -> Result<(), &'static str> {
    if S19K_VNISH_V133_EMIT_SITES.len() != 5 || S19K_VNISH_V133_TX_GATEWAY_FNS.len() != 4 {
        return Err("vnish TX surface is exactly 5 emit sites in 4 gateway functions");
    }
    // Each emit site lives inside one of the four gateway functions
    // (emit >= fn start, next fn start bounds it).
    let mut fns = S19K_VNISH_V133_TX_GATEWAY_FNS.to_vec();
    fns.sort_unstable();
    for &site in &S19K_VNISH_V133_EMIT_SITES {
        let inside = fns.iter().any(|&f| site >= f && site < f + 0x400);
        if !inside {
            return Err("every vnish emit site must sit inside a TX gateway function");
        }
    }
    if S19K_VNISH_V133_55AA_CHIP_TEMPLATE_TOTAL != 0 {
        return Err("vnish must keep zero 55 AA chip-frame templates in data");
    }
    if S19K_VNISH_V133_55AA_PAIR_TOTAL != 9 {
        return Err("vnish whole-file 55 AA pair census must stay nine");
    }
    if S19K_VNISH_V133_EMIT_MOVW_BYTES != [0x55, 0x1a, 0x0a, 0xe3] {
        return Err("vnish emit instruction must stay movw r1,#0xAA55");
    }
    Ok(())
}

/// The stock Bitmain flush api is a host-side flag chain that ends in a
/// rebuilt job buffer and a NEW job on the internal socket - and that
/// binary contains no chain-UART capability at all (zero `55 AA` bytes,
/// no tty device strings).
pub fn admit_s19k_stock_flush_api_is_host_side() -> Result<(), &'static str> {
    if S19K_STOCK_CGMINER_55AA_PAIR_TOTAL != 0 {
        return Err("stock cgminer must keep zero 55 AA bytes (no UART capability)");
    }
    if S19K_STOCK_FLUSH_FLAG_SETTER_VA >= S19K_STOCK_FLUSH_FLAG_CONSUMER_VA {
        return Err("stock flush flag setter precedes the work-gen consumer");
    }
    if S19K_STOCK_REBUILD_TRACE_LINES != [222, 258] {
        return Err("rebuild_job_buf trace lines stay 222/258");
    }
    if S19K_STOCK_FLUSH_SETTER_BYTES[..4] != [0x50, 0x3e, 0x07, 0xe3] {
        return Err("stock flush setter must start with movw r3,#0x7e50");
    }
    if S19K_STOCK_FLUSH_SETTER_BYTES[12..] != [0x00, 0x20, 0x83, 0xe5] {
        return Err("stock flush setter must end with str r2,[r3]");
    }
    Ok(())
}

/// The jig's own command-label strings enumerate its entire chip-command
/// vocabulary: bring-up and frequency control only. Every "Set chain
/// inactive" reference is an init-sequence step directly followed by
/// "Set asic address"; there is no work-invalidate command label and no
/// `55 AA 21 36` / `55 AA 53 05` template anywhere in the file.
pub fn admit_s19k_jig_vocabulary_has_no_work_invalidate() -> Result<(), &'static str> {
    if S19K_JIG_55AA2136_HITS != 0 || S19K_JIG_55AA5305_HITS != 0 {
        return Err("jig must keep zero 55 AA 21 36 / 55 AA 53 05 templates");
    }
    let has_abort = S19K_JIG_CHIP_COMMAND_LABELS.iter().any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("abort")
            || l.contains("invalidate")
            || l.contains("stop work")
            || l.contains("flush")
    });
    if has_abort {
        return Err("jig command vocabulary must not contain an abort/flush label");
    }
    if S19K_JIG_CHIP_COMMAND_LABELS.len() != 11 {
        return Err("jig vocabulary census stays eleven labels");
    }
    if S19K_JIG_CHAIN_INACTIVE_INIT_SITES.len() != 5 {
        return Err("jig chain-inactive stays five inlined init sites");
    }
    Ok(())
}

/// The VNish string-table negative (no chip-invalidate vocabulary) is
/// evidence, not proof: strings alone do not bind the UART write path.
/// Do not upgrade the strings census into a wire-behavior claim.
pub fn refuse_s19k_vnish_strings_as_chip_invalidate_proof() -> Result<(), &'static str> {
    Err(
        "vnish strings show no invalidate vocabulary, but string absence \
         alone does not prove the UART write path; the gateway funnels are \
         the wire-level evidence",
    )
}

/// The caller-side frame-TYPE vocabulary behind the four VNish TX gateways
/// was NOT recovered this session: the gateway function pointers are used
/// only through computed indirect dispatch (their addresses appear exactly
/// once each, inside `.got`, and no literal-pool, GOT-slot, or GOT-base
/// reference to those slots exists in `.text`). Pin the gap honestly.
pub fn refuse_s19k_vnish_caller_type_vocabulary_as_recovered() -> Result<(), &'static str> {
    Err(
        "vnish gateway caller TYPE bytes remain unrecovered: dispatch is \
         indirect through computed pointers (OLLVM-style); only the 4 \
         gateways and the 55 AA preamble halfword are pinned",
    )
}

/// "flush api" in the stock cgminer is an internal semaphore/flag over the
/// scheduler socket, not a chip command.
pub fn refuse_s19k_stock_flush_api_as_chip_uart_command() -> Result<(), &'static str> {
    Err(
        "stock bitmain_flush_api is host-side: flag 0x87e50 -> rebuild_job_buf \
         -> new job over the internal socket; the binary has zero 55 AA \
         bytes and no ttyS devices",
    )
}

/// The jig "Set chain inactive" is an init/set-address step, not a
/// leftover-safe mid-run work replace.
pub fn refuse_s19k_jig_chain_inactive_as_midrun_replace() -> Result<(), &'static str> {
    Err(
        "jig Set chain inactive only appears inside init sequences that \
         continue into Set asic address (5 inlined sites); it is not a \
         mid-run occupied-slot replace",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnish_selfkey_xor_decodes_workgen_fixtures() {
        assert_eq!(
            decode_s19k_vnish_selfkey_xor(&S19K_VNISH_V133_JOB_NOT_FOUND_ENC).unwrap(),
            "Job for work_id = %02x not found"
        );
        assert_eq!(
            decode_s19k_vnish_selfkey_xor(&S19K_VNISH_V133_WORKGEN_C_ENC).unwrap(),
            "/tmp/build/src/backend/work-gen/work-gen.c"
        );
        // The trailing byte of each fixture is its own key.
        assert_eq!(S19K_VNISH_V133_JOB_NOT_FOUND_ENC[32], 0x5c);
        assert_eq!(S19K_VNISH_V133_WORKGEN_C_ENC[42], 0xcf);
        // Degenerate fixture rejection.
        assert!(decode_s19k_vnish_selfkey_xor(&[]).is_err());
        assert!(decode_s19k_vnish_selfkey_xor(&[0x41, 0x00]).is_err());
        assert!(decode_s19k_vnish_selfkey_xor(&[0xff, 0x01]).is_err());
        assert!(admit_s19k_vnish_workgen_architecture_strings().is_ok());
    }

    #[test]
    fn vnish_tx_gateway_funnel_is_pinned() {
        assert!(admit_s19k_vnish_tx_gateway_funnel().is_ok());
        // Gateway/ordering sanity: sorted gateway starts bound every site.
        let mut sorted = S19K_VNISH_V133_TX_GATEWAY_FNS;
        sorted.sort_unstable();
        assert_eq!(sorted.first(), Some(&0x000f_19a8));
        assert_eq!(sorted.last(), Some(&0x0011_baa4));
        // The queue push sits between the first and last gateway.
        assert!(sorted[0] < S19K_VNISH_V133_QUEUE_PUSH);
        assert!(S19K_VNISH_V133_QUEUE_PUSH < sorted[3]);
        // Two of the five emit sites are the twin blocks inside the last
        // gateway (it carries two emit variants).
        assert!(S19K_VNISH_V133_EMIT_SITES[3] >= 0x0011_baa4);
        assert!(S19K_VNISH_V133_EMIT_SITES[4] >= 0x0011_baa4);
        // The PIC board-frame table is not a chip-frame template.
        assert_eq!(S19K_VNISH_V133_PIC_FRAME_FIRST[..2], [0x55, 0xaa]);
        assert_eq!(S19K_VNISH_V133_PIC_FRAME_FIRST[2], 0x04);
    }

    #[test]
    fn vnish_rx_preamble_bytes_stay_pinned() {
        assert_eq!(S19K_VNISH_V133_RX_CMP_AA_BYTES, [0xaa, 0x00, 0x50, 0xe3]);
        assert_eq!(S19K_VNISH_V133_RX_CMP_55_BYTES, [0x55, 0x00, 0x50, 0xe3]);
        assert!(S19K_VNISH_V133_RX_CMP_55_VA > S19K_VNISH_V133_RX_CMP_AA_VA);
    }

    #[test]
    fn stock_flush_chain_is_host_side_flag_semantics() {
        assert!(admit_s19k_stock_flush_api_is_host_side().is_ok());
        // Evidence chain: stratum sets the flag, work-gen consumes it, then
        // calls rebuild_job_buf, then sends the new job.
        assert!(S19K_STOCK_FLUSH_FLAG_SETTER_VA < S19K_STOCK_FLUSH_FLAG_CONSUMER_VA);
        assert!(S19K_STOCK_FLUSH_FLAG_CONSUMER_VA < S19K_STOCK_FLUSH_REBUILD_CALL_VA);
        assert!(S19K_STOCK_FLUSH_REBUILD_CALL_VA < S19K_STOCK_REBUILD_JOB_BUF_FN_VA + 0x600);
        assert!(S19K_STOCK_FLUSH_SEM_MSG_XREF_VA < S19K_STOCK_FLUSH_FLAG_CONSUMER_VA);
        assert!(refuse_s19k_stock_flush_api_as_chip_uart_command().is_err());
    }

    #[test]
    fn jig_recheck_stays_negative() {
        assert!(admit_s19k_jig_vocabulary_has_no_work_invalidate().is_ok());
        // Every chain-inactive init site precedes the earliest job-loop
        // region and none sits between address-set and a running job loop
        // as a separate command (all five are init wrappers).
        for &site in &S19K_JIG_CHAIN_INACTIVE_INIT_SITES {
            assert!(site < 0x0006_1000);
        }
        assert_eq!(S19K_JIG_CHAIN_INACTIVE_INIT_SITES.len(), 5);
        assert!(refuse_s19k_jig_chain_inactive_as_midrun_replace().is_err());
    }

    #[test]
    fn refusal_pins_stay_refusals() {
        assert!(refuse_s19k_vnish_strings_as_chip_invalidate_proof().is_err());
        assert!(refuse_s19k_vnish_caller_type_vocabulary_as_recovered().is_err());
        assert!(refuse_s19k_stock_flush_api_as_chip_uart_command().is_err());
        assert!(refuse_s19k_jig_chain_inactive_as_midrun_replace().is_err());
    }

    #[test]
    fn evidence_hashes_and_sizes_stay_pinned() {
        assert_eq!(S19K_VNISH_V133_CGMINER_SHA256.len(), 64);
        assert_eq!(S19K_STOCK_CGMINER_SHA256.len(), 64);
        assert_eq!(S19K_JIG_SHA256.len(), 64);
        assert_eq!(S19K_VNISH_V133_CGMINER_SIZE, 6_253_540);
        assert_eq!(S19K_JIG_SIZE, 2_087_696);
        // String-table region and key offsets stay inside .data
        // (file 0x5c6000..0x5f681c).
        assert!(S19K_VNISH_V133_STRTAB_FILE_OFF + 0x5cf142 > S19K_VNISH_V133_STRTAB_FILE_OFF);
        assert!(0x5cf142 > S19K_VNISH_V133_STRTAB_FILE_OFF);
        assert!(0x5cf195 < 0x5f6_81c);
    }
}
