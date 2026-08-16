//! S19k Amlogic Track 1 — `/dev/uart_trans` job pack (desk 11d + 11e + 11f).
//!
//! Sources:
//! -  (§5.4 fill)
//! - `BM1366_WIRE_BRINGUP.md` § Desk pass 2026-08-11d / 11e / 11f
//!
//! Transport is open/mmap/ioctl on `/dev/uart_trans`, **not** raw ttyS write of
//! jobs. Kernel `pack_asic_work` emits the UART frame; userspace fills the mmap
//! ring (stride `0xA8`). This module is **pure pack + policy pins** — no open,
//! no ioctl, no energize, no mining engine.
//!
//! Desk 11e: **1** ring entry → **1** UART frame. Refuse host 4×/8× UART fan-out.
//! `job_id = slot << 3`.
//!
//! Desk 11f (CLOSED): `data[64]` is **not** mid0‖mid1 / 2×32 midstate pick.
//! Stock make-work always fills a **36+28 header-chunk**, then byte-rev 64B:
//! - `data[0:4]`  ← bbversion (job+0x10 / desc+0x24)
//! - `data[4:36]` ← prev_hash 32B
//! - `data[36:64]` ← merkle_root[0:28]
//! The count×0x20 host blob is **merkle branches**, not midstate slots.
//! `mid_auto_gen` is unused by make-work — refuse inventing a midstate-pair
//! index into `data[64]`. Frame/pack ABI (`55 AA 21 36…`) unchanged.
//! Runtime-try stays fail-closed until Lead clears transport ownership.
//!
//! Wire CLEAR_BRAIINS_TTY: Braiins Track-1 may opt into raw `/dev/ttyS1`+
//! `/dev/ttyS2` (required) and `/dev/ttyS3` (discover; `a lab unit` dmesg 0→9600
//! →115200) @ 3_000_000 8N1 (userspace writes full `55 AA` frames).
//! Stock `admit_job_tx_path` still refuses ttyS; use
//! `admit_job_tx_path_for_transport(false, …)` for Braiins only.
//! Never `/dev/ttyS0` (console). No uart_trans mmap on Braiins when the
//! node is missing. board#↔ttyS = discover-on-bench.

/// Userspace device path (bmminer_4cc0).
pub const UART_TRANS_PATH: &str = "/dev/uart_trans";
/// mmap work-ring element stride (`RAW_UART_WORK_FORMAT` size).
pub const UART_TRANS_RING_STRIDE: usize = 0xA8;
/// ioctl magic `'u'` family (numbers CLOSED in ABI note; bind uses these later).
pub const UART_TRANS_IOCTL_MAGIC: u8 = b'u';

pub const JOB_PREAMBLE_0: u8 = 0x55;
pub const JOB_PREAMBLE_1: u8 = 0xAA;
pub const JOB_CMD_TYPE: u8 = 0x21;
/// Length **field** (byte after 0x21). Do **not** invent 0x56 here.
pub const JOB_LEN_FIELD: u8 = 0x36;
/// BM1362 / ESP live-miss length field. Same 84-byte command size as S19k 0x36.
pub const BM1362_UART_TRANS_LEN_FIELD: u8 = 0x56;

/// Stock/BB `UartWork::from_command_frame` may queue either dialect.
/// Body size stays 84; only the length **field** differs.
pub fn admit_uart_trans_command_len_field(len_field: u8) -> Result<(), &'static str> {
    if len_field == JOB_LEN_FIELD || len_field == BM1362_UART_TRANS_LEN_FIELD {
        Ok(())
    } else {
        Err("uart_trans command length must be 0x36 (S19k CLOSED) or 0x56 (BM1362)")
    }
}
pub const JOB_RSVD2: u8 = 0x01;
/// `asic_work_t` body size / pack return (after preamble).
pub const JOB_BODY_LEN: usize = 0x56;
/// On-wire total including `55 AA`.
pub const JOB_WIRE_TOTAL: usize = 0x58;
/// CRC covers first 0x54 body bytes.
pub const JOB_CRC_LEN: usize = 0x54;
pub const JOB_DATA2_LEN: usize = 12;
pub const JOB_DATA_LEN: usize = 64;
/// MS8: one frame per ring entry — never host fan-out N UART frames.
pub const UART_FRAMES_PER_RING_ENTRY: usize = 1;
pub const FORBIDDEN_HOST_UART_FANOUT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartTransBindPins {
    pub path: &'static str,
    pub ring_stride: usize,
    pub frames_per_ring_entry: usize,
    pub refuse_raw_ttys_job_write: bool,
}

pub const UART_TRANS_BIND: UartTransBindPins = UartTransBindPins {
    path: UART_TRANS_PATH,
    ring_stride: UART_TRANS_RING_STRIDE,
    frames_per_ring_entry: UART_FRAMES_PER_RING_ENTRY,
    refuse_raw_ttys_job_write: true,
};

/// `bmminer_4cc0` `mmap(NULL, 0x20d0c, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)`.
/// 0xC header + 768 work × 0xA8 + 32 history × 0xA8 = 0x20D0C. ioctl wq is 768.
pub const UART_TRANS_MMAP_LEN: usize = 0x20_D0C;
pub const UART_TRANS_MMAP_HEADER: usize = 0xC;
/// Physical 0xA8 elements after the header (768 work + 32 history).
pub const UART_TRANS_RING_SLOTS: usize = 800;
pub const UART_TRANS_WQ_DEFAULT: usize = 0x300;
pub const UART_TRANS_WORK_SLOTS: usize = UART_TRANS_WQ_DEFAULT;
pub const UART_TRANS_HISTORY_SLOTS: usize = 32;
/// ko send-path snapshot: `map + 0x1F80C + slot*0xA8` (`0xC + 768*0xA8`).
pub const UART_TRANS_HISTORY_OFF: usize = 0x1F_80C;
/// `_IO('u', 5)` start send-work timer (`ioctl 0x7505`). Not BM1362 FLUSH_TX.
pub const UART_TRANS_IOCTL_START_TIMER: u32 = 0x7505;
/// `_IO('u', 6)` stop send-work timer (`ioctl 0x7506`). Not BM1362 FLUSH_RX.
pub const UART_TRANS_IOCTL_STOP_TIMER: u32 = 0x7506;
/// `_IO('u', 7)` clean / flush work (`uart_trans_clean_work`).
pub const UART_TRANS_IOCTL_CLEAN_WORK: u32 = 0x7507;
/// `_IOW('u', 1, int)` set chain-exist bits.
pub const UART_TRANS_IOCTL_SET_CHAIN: u32 = 0x4004_7501;
/// `_IOW('u', 2, int)` set work-queue count. Not BM1362 SET_BAUD.
pub const UART_TRANS_IOCTL_SET_WQ: u32 = 0x4004_7502;
/// `_IOW('u', 3, …)` timer / callback cookie (`g+0xb0`).
pub const UART_TRANS_IOCTL_SET_COOKIE: u32 = 0x4004_7503;
/// `_IOW('u', 8, int)` set baud → `tty_set_baud`.
pub const UART_TRANS_IOCTL_SET_BAUD: u32 = 0x4004_7508;
/// `_IOW('u', 9, int)` select chain.
pub const UART_TRANS_IOCTL_SELECT_CHAIN: u32 = 0x4004_7509;
/// `_IOW('u', 10, …)` `uart_trans_send_work_once`.
pub const UART_TRANS_IOCTL_SEND_ONCE: u32 = 0x4004_750A;

/// 4cc0 `uart_transceive.c` bind after open+mmap (ABI §1). Never executed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartTransHostBindStep {
    pub ioctl: u32,
    pub arg: u32,
}

pub const UART_TRANS_HOST_BIND_STEPS: [UartTransHostBindStep; 3] = [
    UartTransHostBindStep {
        ioctl: UART_TRANS_IOCTL_STOP_TIMER,
        arg: 0,
    },
    UartTransHostBindStep {
        ioctl: UART_TRANS_IOCTL_SET_CHAIN,
        arg: 0,
    },
    UartTransHostBindStep {
        ioctl: UART_TRANS_IOCTL_SET_WQ,
        arg: UART_TRANS_WQ_DEFAULT as u32,
    },
];

/// Admit the reconstructed 4cc0 host bind. Does not open `/dev`.
pub fn admit_uart_trans_host_bind_plan(
    mmap_len: usize,
    steps: &[UartTransHostBindStep],
) -> Result<(), &'static str> {
    admit_uart_trans_mmap_layout(mmap_len, UART_TRANS_RING_STRIDE, UART_TRANS_WQ_DEFAULT)?;
    if steps.len() < 3 {
        return Err("4cc0 bind is stop-timer, set-chain, set-wq=768");
    }
    if steps[0].ioctl != UART_TRANS_IOCTL_STOP_TIMER {
        return Err("first ioctl is 0x7506 stop-timer");
    }
    if steps[1].ioctl != UART_TRANS_IOCTL_SET_CHAIN {
        return Err("second ioctl is 0x40047501 set-chain");
    }
    if steps[2].ioctl != UART_TRANS_IOCTL_SET_WQ || steps[2].arg != 0x300 {
        return Err("third ioctl is 0x40047502 set-wq 0x300");
    }
    Ok(())
}

/// Live bind stays refused until AML 4cc0/ko bytes exist on this tree.
pub fn refuse_uart_trans_host_bind_execution() -> Result<(), &'static str> {
    Err("4cc0/ko absent on host tree; host-bind plan is reconstructed, not executed")
}

/// DWARF `RAW_UART_WORK_FORMAT` (168 / `0xA8`).
pub const UART_TRANS_ELEM_DATA_OFF: usize = 0;
pub const UART_TRANS_ELEM_DATA2_OFF: usize = 64;
pub const UART_TRANS_ELEM_SNO_OFF: usize = 76;
pub const UART_TRANS_ELEM_MERKLE_OFF: usize = 80;
pub const UART_TRANS_ELEM_NONCE2_OFF: usize = 112;
pub const UART_TRANS_ELEM_BBVERSION_OFF: usize = 120;
pub const UART_TRANS_ELEM_NBIT_OFF: usize = 124;
pub const UART_TRANS_ELEM_NTIME_OFF: usize = 128;
pub const UART_TRANS_ELEM_PREV_HASH_OFF: usize = 132;
pub const UART_TRANS_ELEM_POOL_JOB_ID_OFF: usize = 164;

/// Host-testable mmap/ioctl bind. Does not open `/dev/uart_trans`.
pub fn admit_uart_trans_mmap_layout(
    mmap_len: usize,
    stride: usize,
    wq_count: usize,
) -> Result<(), &'static str> {
    if mmap_len != UART_TRANS_MMAP_LEN {
        return Err("uart_trans mmap length must be 0x20d0c (4cc0)");
    }
    if stride != UART_TRANS_RING_STRIDE {
        return Err("uart_trans ring stride must be 0xA8");
    }
    if UART_TRANS_MMAP_HEADER + UART_TRANS_RING_SLOTS * UART_TRANS_RING_STRIDE != UART_TRANS_MMAP_LEN
    {
        return Err("mmap header+800*0xA8 must equal 0x20d0c");
    }
    if wq_count == 0 || wq_count > UART_TRANS_RING_SLOTS {
        return Err("work-queue count must fit the 800-slot ring");
    }
    if wq_count != UART_TRANS_WQ_DEFAULT {
        return Err("4cc0 set-wq ioctl uses 0x300 (768)");
    }
    Ok(())
}

/// 768 work slots from +0xC land on history 0x1F80C; 32 history slots fill mmap.
pub fn admit_uart_trans_history_layout() -> Result<(), &'static str> {
    if UART_TRANS_MMAP_HEADER + UART_TRANS_WORK_SLOTS * UART_TRANS_RING_STRIDE
        != UART_TRANS_HISTORY_OFF
    {
        return Err("history starts after 768 work slots from +0xC");
    }
    if UART_TRANS_HISTORY_OFF + UART_TRANS_HISTORY_SLOTS * UART_TRANS_RING_STRIDE
        != UART_TRANS_MMAP_LEN
    {
        return Err("32 history slots must fill mmap to 0x20d0c");
    }
    if UART_TRANS_WORK_SLOTS + UART_TRANS_HISTORY_SLOTS != UART_TRANS_RING_SLOTS {
        return Err("800 physical = 768 work + 32 history");
    }
    Ok(())
}

pub fn uart_trans_ring_slot_offset(index: usize) -> Result<usize, &'static str> {
    if index >= UART_TRANS_WORK_SLOTS {
        return Err("work slot index >= 768 (last 32 are history)");
    }
    Ok(UART_TRANS_MMAP_HEADER + index * UART_TRANS_RING_STRIDE)
}

pub fn uart_trans_history_slot_offset(index: usize) -> Result<usize, &'static str> {
    if index >= UART_TRANS_HISTORY_SLOTS {
        return Err("history slot index >= 32");
    }
    Ok(UART_TRANS_HISTORY_OFF + index * UART_TRANS_RING_STRIDE)
}

/// 4cc0 make-work: `write_idx++` then wrap at ioctl wq `0x300` (768), not 800.
pub fn uart_trans_next_write_idx(cur: usize) -> Result<usize, &'static str> {
    if cur >= UART_TRANS_WQ_DEFAULT {
        return Err("write_idx must stay inside the 768-slot work queue");
    }
    Ok((cur + 1) % UART_TRANS_WQ_DEFAULT)
}

/// Track-1 Braiins has no `/dev/uart_trans`. Do not mmap a missing node.
pub fn refuse_braiins_uart_trans_mmap(uart_trans_present: bool) -> Result<(), &'static str> {
    if uart_trans_present {
        return Err("Braiins Track-1: refuse uart_trans mmap; use raw ttyS1+ttyS2");
    }
    Ok(())
}

/// Bring-up note `mmap+8 + write_idx*0xA8` does not land on history 0x1F80C.
pub fn refuse_work_base_plus8_given_history() -> Result<(), &'static str> {
    let plus8_after_wq = 8 + UART_TRANS_WORK_SLOTS * UART_TRANS_RING_STRIDE;
    if plus8_after_wq == UART_TRANS_HISTORY_OFF {
        return Ok(());
    }
    Err("mmap+8 + 768*0xA8 = 0x1F808 != history 0x1F80C; work base is +0xC")
}

/// Capstone note that put work at mmap+8. Layout math refuses it.
pub const UART_TRANS_CAPSTONE_WORK_BASE: usize = 8;

/// History `0x1F80C − 768×0xA8` is the header. That is the work-ring base.
pub fn admit_uart_trans_work_base_from_history() -> Result<usize, &'static str> {
    let implied = UART_TRANS_HISTORY_OFF
        .checked_sub(UART_TRANS_WORK_SLOTS * UART_TRANS_RING_STRIDE)
        .ok_or("history offset smaller than 768*0xA8")?;
    if implied != UART_TRANS_MMAP_HEADER {
        return Err("history 0x1F80C − 768*0xA8 must be header 0xC");
    }
    if implied == UART_TRANS_CAPSTONE_WORK_BASE {
        return Err("history math must not imply mmap+8");
    }
    Ok(implied)
}

/// Held host tree has CV/VNish `uart_trans.ko`, not S19k `bmminer_4cc0`.
pub const UART_TRANS_4CC0_PRESENT_ON_HOST_TREE: bool = false;

///  independent re-search. No `bmminer_4cc0*` ELF. VNish S19k AML
/// nand tarball is `devicetree.dtb` + `uramdisk.image.gz` (uImage) +
/// `vmlinux.bin` only. Held `uart_trans.ko` is CVCtrl S19j Pro.
pub const UART_TRANS_4CC0_SEARCHED_HINTS: &[&str] = &[
    "",
    "",
    "",
    "",
    "",
    "",
];

/// Dry plan for the reconstructed 3-step bind. Does not open `/dev`.
pub fn format_uart_trans_host_bind_plan() -> String {
    format!(
        "schema=dcentos.uart-trans-bind/v1\nmmap=0x20d0c\nwork_base=0xC\nstep0=0x{stop:x}\nstep1=0x{chain:x}\nstep2=0x{wq:x}/0x300\nexecute=false\n4cc0_present={present}\nhashsource_s19x_4cc0=false\n",
        stop = UART_TRANS_IOCTL_STOP_TIMER,
        chain = UART_TRANS_IOCTL_SET_CHAIN,
        wq = UART_TRANS_IOCTL_SET_WQ,
        present = UART_TRANS_4CC0_PRESENT_ON_HOST_TREE,
    )
}

/// `0x40047508` is tty baud after bind, not one of the three bind ioctls.
pub fn refuse_uart_trans_set_baud_as_bind_step(ioctl: u32) -> Result<(), &'static str> {
    if ioctl == UART_TRANS_IOCTL_SET_BAUD {
        return Err("0x40047508 is tty_set_baud after bind; not the 3-step host bind");
    }
    Ok(())
}

/// History math vs Capstone `mmap+8` is not closed without 4cc0/ko bytes.
pub fn refuse_uart_trans_work_base_sot_without_4cc0() -> Result<(), &'static str> {
    if UART_TRANS_4CC0_PRESENT_ON_HOST_TREE {
        return Ok(());
    }
    Err("4cc0/ko absent; mmap+8 Capstone vs +0xC history math still contradictory")
}

/// CVCtrl `uart_trans.ko` is S19j Pro eMMC, not S19k AML 0x20d0c/0x1F80C.
pub fn refuse_held_cvctrl_uart_trans_as_s19k_aml_4cc0() -> Result<(), &'static str> {
    Err("held uart_trans.ko is CVCtrl S19j Pro; not S19k AML bmminer_4cc0 0x20d0c")
}

/// BM1362 comparative ioctl table must not be copied onto S19k AML.
pub fn refuse_bm1362_ioctl_as_s19k_aml() -> Result<(), &'static str> {
    // dcentrald-asic BM1362: 0x40047502=SET_BAUD, 0x7506=FLUSH_RX, 0x7505=FLUSH_TX.
    if UART_TRANS_IOCTL_SET_WQ == 0x4004_7502 && UART_TRANS_IOCTL_SET_BAUD == 0x4004_7508 {
        return Err("S19k 0x40047502 is set-wq; baud is 0x40047508 (not BM1362 SET_BAUD)");
    }
    Ok(())
}


/// Required Track-1 pair. `a lab unit` dmesg also wakes ttyS3 (see DISCOVER).
pub const BRAIINS_TTYS_CANDIDATES: &[&str] = &["/dev/ttyS1", "/dev/ttyS2"];
/// Hash UARTs bosminer actually termios-wakes on `a lab unit` (9600 then 115200).
/// Console is ttyS0 only (`inittab` + `console=ttyS0`). ttyS3 = meson uart3
/// `ff804000` irq 14 — a hash UART, not the console.
pub const BRAIINS_TTYS_DISCOVER: &[&str] = &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"];
pub const BRAIINS_TTYS_THIRD: &str = "/dev/ttyS3";
pub const BRAIINS_TTYS_BAUD: u32 = 3_000_000;
pub const BRAIINS_TTYS_FORBIDDEN: &[&str] = &["/dev/ttyS0"]; // never
/// First bosminer wake on `a lab unit` dmesg (T+45s): 0 → 9600 on S1+S2+S3.
pub const BOSMINER_UART_WAKE_BAUD: u32 = 9600;

/// Host pins for Braiins raw ttyS job TX (Wire CLEAR_BRAIINS_TTY).
/// board#↔ttyS mapping is discover-on-bench — do not hardcode board2=ttyS1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BraiinsRawTtySPins {
    pub candidate_paths: &'static [&'static str],
    pub baud: u32,
    pub data_bits: u8,
    pub parity: char,
    pub stop_bits: u8,
    pub write_full_wire_frame: bool,
    pub board_to_tty_discover: bool,
    pub refuse_uart_trans_when_missing: bool,
    pub frames_per_work: usize,
}

pub const BRAIINS_RAW_TTYS_PINS: BraiinsRawTtySPins = BraiinsRawTtySPins {
    candidate_paths: BRAIINS_TTYS_CANDIDATES,
    baud: BRAIINS_TTYS_BAUD,
    data_bits: 8,
    parity: 'N',
    stop_bits: 1,
    write_full_wire_frame: true,
    board_to_tty_discover: true,
    refuse_uart_trans_when_missing: true,
    frames_per_work: UART_FRAMES_PER_RING_ENTRY,
};

/// job_id on wire = slot<<3 (nonce lookup >>3).
pub const fn job_id_from_slot(slot: u8) -> u8 {
    slot.wrapping_shl(3)
}

pub const fn slot_from_job_id(job_id: u8) -> u8 {
    job_id >> 3
}

/// CRC16-ITU-T (poly 0x1021, init 0xffff) — Linux `crc_itu_t` bit algorithm.
pub fn crc16_itu_t(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (u16::from(b)) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Pack one on-wire UART job frame (desk 11d template).
///
/// `data2` = 12B header fragment; `data` = 64B **header-chunk** region
/// (desk 11f: 36+28, not a midstate pair). `sno` forced to 0 on this pack path.
pub fn pack_uart_trans_job(job_id: u8, data2: &[u8; 12], data: &[u8; 64]) -> [u8; JOB_WIRE_TOTAL] {
    let mut body = [0u8; JOB_BODY_LEN];
    body[0] = JOB_CMD_TYPE;
    body[1] = JOB_LEN_FIELD;
    body[2] = job_id;
    body[3] = JOB_RSVD2;
    // sno 4..7 left zero
    body[8..20].copy_from_slice(data2);
    body[20..84].copy_from_slice(data);
    let crc = crc16_itu_t(&body[..JOB_CRC_LEN]);
    body[84] = (crc >> 8) as u8;
    body[85] = (crc & 0xFF) as u8;

    let mut out = [0u8; JOB_WIRE_TOTAL];
    out[0] = JOB_PREAMBLE_0;
    out[1] = JOB_PREAMBLE_1;
    out[2..].copy_from_slice(&body);
    out
}

/// Refuse host UART fan-out (desk 11e). Only 1 frame per ring entry is legal.
pub fn admit_uart_frames_per_work(frames: usize) -> Result<(), &'static str> {
    if frames != UART_FRAMES_PER_RING_ENTRY {
        return Err("desk 11e: refuse host 4x/8x UART fan-out; 1 ring entry -> 1 UART frame");
    }
    Ok(())
}

/// Track 1 job TX must not use raw ttyS write of packed jobs.
pub fn admit_job_tx_path(path: &str) -> Result<(), &'static str> {
    if path == UART_TRANS_PATH {
        return Ok(());
    }
    if path.starts_with("/dev/ttyS") {
        return Err("Track 1: refuse raw ttyS job write; use /dev/uart_trans mmap ring");
    }
    Err("Track 1: unknown job TX path; expected /dev/uart_trans")
}


/// Braiins Track-1: ttyS1|ttyS2 required, ttyS3 discover (`a lab unit` dmesg wake).
/// Refuses ttyS0 (console) and uart_trans.
pub fn admit_braiins_job_tx_path(path: &str) -> Result<(), &'static str> {
    if path == "/dev/ttyS0" || BRAIINS_TTYS_FORBIDDEN.contains(&path) {
        return Err("CLEAR_BRAIINS_TTY: never /dev/ttyS0");
    }
    if path == UART_TRANS_PATH {
        return Err("CLEAR_BRAIINS_TTY: refuse uart_trans on Braiins raw ttyS path");
    }
    if BRAIINS_TTYS_DISCOVER.contains(&path) {
        return Ok(());
    }
    if path.starts_with("/dev/ttyS") {
        return Err("CLEAR_BRAIINS_TTY: ttyS not in ttyS1|ttyS2|ttyS3 discover set");
    }
    Err("CLEAR_BRAIINS_TTY: unknown job TX path; expected /dev/ttyS1, ttyS2, or ttyS3")
}

/// Dispatch job-TX path admit by transport.
/// `stock_uart_trans=true` keeps Track-2/stock refuse-raw-ttyS polarity.
/// `stock_uart_trans=false` is Braiins Track-1 opt-in (ttyS1|ttyS2 only).
pub fn admit_job_tx_path_for_transport(stock_uart_trans: bool, path: &str) -> Result<(), &'static str> {
    if stock_uart_trans {
        admit_job_tx_path(path)
    } else {
        admit_braiins_job_tx_path(path)
    }
}

/// Desk 11f: sizes for stock make-work `data[64]` fill (not midstate pair).
pub const JOB_DATA_BBVERSION_LEN: usize = 4;
pub const JOB_DATA_PREV_HASH_LEN: usize = 32;
/// bbversion (4) + prev_hash (32) — first 36B before merkle prefix.
pub const JOB_DATA_HEADER_CHUNK_LEN: usize = 36;
pub const JOB_DATA_MERKLE_PREFIX_LEN: usize = 28;
/// Host count×0x20 blob elements are merkle branches (20h each), not midstate slots.
pub const MERKLE_BRANCH_ENTRY_LEN: usize = 0x20;
/// mid_auto_gen is not consulted by stock make-work for data[64] fill.
pub const MAKE_WORK_CONSULTS_MID_AUTO_GEN: bool = false;

/// Assemble `data[64]` before byte-rev (desk 11f CLOSED).
///
/// Layout: bbversion[4] || prev_hash[32] || merkle_root[0:28].
pub fn fill_job_data_header_chunk(
    bbversion: &[u8; JOB_DATA_BBVERSION_LEN],
    prev_hash: &[u8; JOB_DATA_PREV_HASH_LEN],
    merkle_root_prefix28: &[u8; JOB_DATA_MERKLE_PREFIX_LEN],
) -> [u8; JOB_DATA_LEN] {
    let mut data = [0u8; JOB_DATA_LEN];
    data[..JOB_DATA_BBVERSION_LEN].copy_from_slice(bbversion);
    data[JOB_DATA_BBVERSION_LEN..JOB_DATA_HEADER_CHUNK_LEN].copy_from_slice(prev_hash);
    data[JOB_DATA_HEADER_CHUNK_LEN..].copy_from_slice(merkle_root_prefix28);
    data
}

/// Byte-reverse the full 64B `data[]` region (stock make-work after assemble).
pub fn byte_rev_job_data(data: &mut [u8; JOB_DATA_LEN]) {
    data.reverse();
}

/// Assemble + byte-rev — golden-test helper matching make-work host fill.
pub fn fill_job_data_header_chunk_byte_rev(
    bbversion: &[u8; JOB_DATA_BBVERSION_LEN],
    prev_hash: &[u8; JOB_DATA_PREV_HASH_LEN],
    merkle_root_prefix28: &[u8; JOB_DATA_MERKLE_PREFIX_LEN],
) -> [u8; JOB_DATA_LEN] {
    let mut data = fill_job_data_header_chunk(bbversion, prev_hash, merkle_root_prefix28);
    byte_rev_job_data(&mut data);
    data
}

/// Refuse inventing a midstate-pair / 2×32 pick into `data[64]` (desk 11f CLOSED).
pub fn refuse_midstate_pair_data_fill(_pair_index: usize) -> Result<(), &'static str> {
    Err(
        "desk 11f CLOSED: no 2x32 midstate pick; data[64]=bbversion||prev_hash||merkle[0:28] then byte-rev",
    )
}

/// Host mmap ring element. Kernel `pack_asic_work` copies only `data`+`data2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartTransRingElement {
    pub data: [u8; JOB_DATA_LEN],
    pub data2: [u8; JOB_DATA2_LEN],
    pub sno: u32,
    pub merkle_root: [u8; 32],
    pub nonce2: u64,
    pub bbversion: u32,
    pub nbit: u32,
    pub ntime: u32,
    pub prev_hash: [u8; 32],
    pub pool_job_id: u32,
}

/// Assemble `data2[12]` then byte-reverse (desk 11f / ABI §5.4).
pub fn fill_uart_trans_data2(
    merkle_root_suffix4: &[u8; 4],
    ntime_job_pkt: &[u8; 4],
    nbits_job_pkt: &[u8; 4],
) -> [u8; JOB_DATA2_LEN] {
    let mut data2 = [0u8; JOB_DATA2_LEN];
    data2[0..4].copy_from_slice(merkle_root_suffix4);
    data2[4..8].copy_from_slice(ntime_job_pkt);
    data2[8..12].copy_from_slice(nbits_job_pkt);
    data2.reverse();
    data2
}

/// Pack one `RAW_UART_WORK_FORMAT` (does not open `/dev/uart_trans`).
pub fn pack_uart_trans_ring_element(elem: &UartTransRingElement) -> [u8; UART_TRANS_RING_STRIDE] {
    let mut out = [0u8; UART_TRANS_RING_STRIDE];
    out[UART_TRANS_ELEM_DATA_OFF..UART_TRANS_ELEM_DATA2_OFF].copy_from_slice(&elem.data);
    out[UART_TRANS_ELEM_DATA2_OFF..UART_TRANS_ELEM_SNO_OFF].copy_from_slice(&elem.data2);
    out[UART_TRANS_ELEM_SNO_OFF..UART_TRANS_ELEM_MERKLE_OFF]
        .copy_from_slice(&elem.sno.to_le_bytes());
    out[UART_TRANS_ELEM_MERKLE_OFF..UART_TRANS_ELEM_NONCE2_OFF]
        .copy_from_slice(&elem.merkle_root);
    out[UART_TRANS_ELEM_NONCE2_OFF..UART_TRANS_ELEM_BBVERSION_OFF]
        .copy_from_slice(&elem.nonce2.to_le_bytes());
    out[UART_TRANS_ELEM_BBVERSION_OFF..UART_TRANS_ELEM_NBIT_OFF]
        .copy_from_slice(&elem.bbversion.to_le_bytes());
    out[UART_TRANS_ELEM_NBIT_OFF..UART_TRANS_ELEM_NTIME_OFF]
        .copy_from_slice(&elem.nbit.to_le_bytes());
    out[UART_TRANS_ELEM_NTIME_OFF..UART_TRANS_ELEM_PREV_HASH_OFF]
        .copy_from_slice(&elem.ntime.to_le_bytes());
    out[UART_TRANS_ELEM_PREV_HASH_OFF..UART_TRANS_ELEM_POOL_JOB_ID_OFF]
        .copy_from_slice(&elem.prev_hash);
    out[UART_TRANS_ELEM_POOL_JOB_ID_OFF..UART_TRANS_RING_STRIDE]
        .copy_from_slice(&elem.pool_job_id.to_le_bytes());
    out
}

/// Desk 11f CLOSED fill into one ring element. `sno` forced 0.
pub fn pack_uart_trans_ring_from_header_chunk(
    bbversion: &[u8; JOB_DATA_BBVERSION_LEN],
    prev_hash: &[u8; JOB_DATA_PREV_HASH_LEN],
    merkle_root: &[u8; 32],
    ntime: &[u8; 4],
    nbit: &[u8; 4],
    nonce2: u64,
    pool_job_id: u32,
) -> [u8; UART_TRANS_RING_STRIDE] {
    let mut merk28 = [0u8; JOB_DATA_MERKLE_PREFIX_LEN];
    merk28.copy_from_slice(&merkle_root[..JOB_DATA_MERKLE_PREFIX_LEN]);
    let mut merk4 = [0u8; 4];
    merk4.copy_from_slice(&merkle_root[JOB_DATA_MERKLE_PREFIX_LEN..]);
    let data = fill_job_data_header_chunk_byte_rev(bbversion, prev_hash, &merk28);
    let data2 = fill_uart_trans_data2(&merk4, ntime, nbit);
    pack_uart_trans_ring_element(&UartTransRingElement {
        data,
        data2,
        sno: 0,
        merkle_root: *merkle_root,
        nonce2,
        bbversion: u32::from_le_bytes(*bbversion),
        nbit: u32::from_le_bytes(*nbit),
        ntime: u32::from_le_bytes(*ntime),
        prev_hash: *prev_hash,
        pool_job_id,
    })
}

/// Reconstruct the UART frame the ko would emit from one ring element + slot.
pub fn uart_trans_wire_from_ring_element(
    slot: u8,
    elem: &[u8; UART_TRANS_RING_STRIDE],
) -> [u8; JOB_WIRE_TOTAL] {
    let mut data = [0u8; JOB_DATA_LEN];
    let mut data2 = [0u8; JOB_DATA2_LEN];
    data.copy_from_slice(&elem[UART_TRANS_ELEM_DATA_OFF..UART_TRANS_ELEM_DATA2_OFF]);
    data2.copy_from_slice(&elem[UART_TRANS_ELEM_DATA2_OFF..UART_TRANS_ELEM_SNO_OFF]);
    pack_uart_trans_job(job_id_from_slot(slot), &data2, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_pins_uart_trans_stride_a8() {
        assert_eq!(UART_TRANS_BIND.path, "/dev/uart_trans");
        assert_eq!(UART_TRANS_BIND.ring_stride, 0xA8);
        assert_eq!(UART_TRANS_BIND.frames_per_ring_entry, 1);
        assert!(UART_TRANS_BIND.refuse_raw_ttys_job_write);
        assert!(admit_uart_trans_mmap_layout(UART_TRANS_MMAP_LEN, 0xA8, UART_TRANS_WQ_DEFAULT).is_ok());
        assert!(admit_uart_trans_mmap_layout(0x20d0c, 0xA8, 0x300).is_ok());
        assert!(admit_uart_trans_mmap_layout(0x20d0c, 0xA8, 1).is_err());
        assert!(admit_uart_trans_history_layout().is_ok());
        assert_eq!(uart_trans_ring_slot_offset(0).unwrap(), 0xC);
        assert_eq!(uart_trans_ring_slot_offset(1).unwrap(), 0xC + 0xA8);
        assert_eq!(uart_trans_ring_slot_offset(767).unwrap(), 0xC + 767 * 0xA8);
        assert!(uart_trans_ring_slot_offset(768).is_err());
        assert!(uart_trans_ring_slot_offset(800).is_err());
        assert_eq!(uart_trans_history_slot_offset(0).unwrap(), 0x1F80C);
        assert_eq!(uart_trans_history_slot_offset(31).unwrap(), 0x1F80C + 31 * 0xA8);
        assert!(uart_trans_history_slot_offset(32).is_err());
        assert_eq!(uart_trans_next_write_idx(0).unwrap(), 1);
        assert_eq!(uart_trans_next_write_idx(767).unwrap(), 0);
        assert!(uart_trans_next_write_idx(768).is_err());
        assert_eq!(UART_TRANS_IOCTL_SET_CHAIN, 0x4004_7501);
        assert_eq!(UART_TRANS_IOCTL_SET_WQ, 0x4004_7502);
        assert_eq!(UART_TRANS_IOCTL_SET_COOKIE, 0x4004_7503);
        assert_eq!(UART_TRANS_IOCTL_START_TIMER, 0x7505);
        assert_eq!(UART_TRANS_IOCTL_STOP_TIMER, 0x7506);
        assert_eq!(UART_TRANS_IOCTL_CLEAN_WORK, 0x7507);
        assert_eq!(UART_TRANS_IOCTL_SET_BAUD, 0x4004_7508);
        assert_eq!(UART_TRANS_IOCTL_SELECT_CHAIN, 0x4004_7509);
        assert_eq!(UART_TRANS_IOCTL_SEND_ONCE, 0x4004_750A);
        assert!(refuse_braiins_uart_trans_mmap(true).is_err());
        assert!(refuse_braiins_uart_trans_mmap(false).is_ok());
        assert!(refuse_work_base_plus8_given_history().is_err());
        assert_eq!(admit_uart_trans_work_base_from_history().unwrap(), 0xC);
        assert!(admit_uart_trans_host_bind_plan(
            UART_TRANS_MMAP_LEN,
            &UART_TRANS_HOST_BIND_STEPS
        )
        .is_ok());
        assert!(refuse_uart_trans_host_bind_execution().is_err());
        assert_ne!(UART_TRANS_CAPSTONE_WORK_BASE, UART_TRANS_MMAP_HEADER);
        assert!(refuse_uart_trans_work_base_sot_without_4cc0().is_err());
        assert!(!UART_TRANS_4CC0_PRESENT_ON_HOST_TREE);
        assert!(refuse_held_cvctrl_uart_trans_as_s19k_aml_4cc0().is_err());
        let plan = format_uart_trans_host_bind_plan();
        assert!(plan.contains("schema=dcentos.uart-trans-bind/v1"));
        assert!(plan.contains("work_base=0xC"));
        assert!(plan.contains("execute=false"));
        assert!(plan.contains("hashsource_s19x_4cc0=false"));
        assert!(refuse_uart_trans_set_baud_as_bind_step(UART_TRANS_IOCTL_SET_BAUD).is_err());
        assert!(refuse_uart_trans_set_baud_as_bind_step(UART_TRANS_IOCTL_STOP_TIMER).is_ok());
        assert!(UART_TRANS_4CC0_SEARCHED_HINTS.contains(&""));
        assert!(UART_TRANS_4CC0_SEARCHED_HINTS
            .iter()
            .any(|p| p.contains("awesome-s19kpro-aml-nand")));
        assert!(refuse_bm1362_ioctl_as_s19k_aml().is_err());
        let deploy = include_str!("../../../scripts/dcentrald_s19k_tmp_deploy.sh");
        assert!(
            deploy.contains("/dev/uart_trans"),
            "tmp deploy must still refuse uart_trans on Braiins"
        );
        assert!(admit_job_tx_path("/dev/uart_trans").is_ok());
        assert!(admit_job_tx_path("/dev/ttyS2").is_err());
    }

    #[test]
    fn job_id_slot_shift() {
        assert_eq!(job_id_from_slot(0), 0);
        assert_eq!(job_id_from_slot(1), 0x08);
        assert_eq!(job_id_from_slot(2), 0x10);
        assert_eq!(slot_from_job_id(0x08), 1);
        assert_eq!(slot_from_job_id(0x10), 2);
    }

    #[test]
    fn pack_length_field_is_0x36_not_0x56() {
        let frame = pack_uart_trans_job(0x08, &[0u8; 12], &[0u8; 64]);
        assert_eq!(frame.len(), 0x58);
        assert_eq!(frame[0], 0x55);
        assert_eq!(frame[1], 0xAA);
        assert_eq!(frame[2], 0x21);
        assert_eq!(frame[3], 0x36);
        assert_ne!(frame[3], 0x56);
        assert_eq!(frame[4], 0x08);
        assert_eq!(frame[5], 0x01);
        // sno zero
        assert_eq!(&frame[6..10], &[0, 0, 0, 0]);
        // CRC16-ITU-T BE over zeroed body prefix (golden from host calc)
        assert_eq!(frame[86], 0x79);
        assert_eq!(frame[87], 0x6d);
        let body = &frame[2..];
        assert_eq!(crc16_itu_t(&body[..0x54]), 0x796d);
    }

    #[test]
    fn refuse_host_uart_fanout_8() {
        assert!(admit_uart_frames_per_work(1).is_ok());
        assert!(admit_uart_frames_per_work(8).is_err());
        assert!(admit_uart_frames_per_work(4).is_err());
    }

    #[test]
    fn desk_11f_header_chunk_fill_not_midstate_pair() {
        assert_eq!(
            JOB_DATA_BBVERSION_LEN + JOB_DATA_PREV_HASH_LEN,
            JOB_DATA_HEADER_CHUNK_LEN
        );
        assert_eq!(JOB_DATA_HEADER_CHUNK_LEN + JOB_DATA_MERKLE_PREFIX_LEN, JOB_DATA_LEN);
        assert_eq!(MERKLE_BRANCH_ENTRY_LEN, 0x20);
        assert!(!MAKE_WORK_CONSULTS_MID_AUTO_GEN);
        let bbv = [0xA1, 0xA2, 0xA3, 0xA4];
        let mut prev = [0u8; 32];
        prev[0] = 0xB0;
        prev[31] = 0xBF;
        let mut merk = [0u8; 28];
        merk[0] = 0xC0;
        merk[27] = 0xCF;
        let data = fill_job_data_header_chunk(&bbv, &prev, &merk);
        assert_eq!(&data[0..4], &bbv);
        assert_eq!(&data[4..36], &prev);
        assert_eq!(&data[36..64], &merk);
        let mut rev = data;
        byte_rev_job_data(&mut rev);
        assert_eq!(rev[0], 0xCF);
        assert_eq!(rev[63], 0xA1);
        assert_eq!(
            fill_job_data_header_chunk_byte_rev(&bbv, &prev, &merk),
            rev
        );
        assert!(refuse_midstate_pair_data_fill(0).is_err());
        assert!(refuse_midstate_pair_data_fill(1).is_err());
    }

    #[test]
    fn sizes_match_abi_note() {
        assert_eq!(JOB_BODY_LEN, 0x56);
        assert_eq!(JOB_WIRE_TOTAL, 0x58);
        assert_eq!(JOB_LEN_FIELD, 0x36);
        assert_eq!(BM1362_UART_TRANS_LEN_FIELD, 0x56);
        assert!(admit_uart_trans_command_len_field(JOB_LEN_FIELD).is_ok());
        assert!(admit_uart_trans_command_len_field(BM1362_UART_TRANS_LEN_FIELD).is_ok());
        assert!(admit_uart_trans_command_len_field(0x00).is_err());
        assert_eq!(JOB_DATA2_LEN, 12);
        assert_eq!(JOB_DATA_LEN, 64);
    }

    #[test]
    fn clear_braiins_ttys_admit_tty_s1_s2_refuse_others() {
        assert_eq!(BRAIINS_TTYS_CANDIDATES, &["/dev/ttyS1", "/dev/ttyS2"]);
        assert_eq!(BRAIINS_TTYS_BAUD, 3_000_000);
        assert_eq!(BRAIINS_TTYS_FORBIDDEN, &["/dev/ttyS0"]);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.baud, 3_000_000);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.data_bits, 8);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.parity, 'N');
        assert_eq!(BRAIINS_RAW_TTYS_PINS.stop_bits, 1);
        assert!(BRAIINS_RAW_TTYS_PINS.write_full_wire_frame);
        assert!(BRAIINS_RAW_TTYS_PINS.board_to_tty_discover);
        assert!(BRAIINS_RAW_TTYS_PINS.refuse_uart_trans_when_missing);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.frames_per_work, 1);
        assert!(admit_braiins_job_tx_path("/dev/ttyS1").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS2").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS3").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS0").is_err());
        assert!(admit_braiins_job_tx_path("/dev/uart_trans").is_err());
        assert!(admit_braiins_job_tx_path("/dev/ttyS4").is_err());
        // Stock polarity unchanged — still refuses ttyS1
        assert!(admit_job_tx_path("/dev/ttyS1").is_err());
        assert!(admit_job_tx_path("/dev/uart_trans").is_ok());
        assert!(UART_TRANS_BIND.refuse_raw_ttys_job_write);
        assert!(admit_job_tx_path_for_transport(true, "/dev/ttyS1").is_err());
        assert!(admit_job_tx_path_for_transport(true, "/dev/uart_trans").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS1").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS2").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS3").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS0").is_err());
        assert!(admit_job_tx_path_for_transport(false, "/dev/uart_trans").is_err());
        assert_eq!(
            BRAIINS_TTYS_DISCOVER,
            &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
        );
        assert_eq!(BOSMINER_UART_WAKE_BAUD, 9600);
        assert!(admit_job_tx_path("/dev/ttyS2").is_err());
        assert!(admit_job_tx_path("/dev/ttyS3").is_err());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS4").is_err());
    }

    #[test]
    fn wave106_ring_element_is_desk_11f_not_midstate_pair() {
        let bbv = [0xA1, 0xA2, 0xA3, 0xA4];
        let mut prev = [0u8; 32];
        prev[0] = 0xB0;
        prev[31] = 0xBF;
        let mut merkle = [0u8; 32];
        merkle[0] = 0xC0;
        merkle[27] = 0xCF;
        merkle[28] = 0xD0;
        merkle[29] = 0xD1;
        merkle[30] = 0xD2;
        merkle[31] = 0xD3;
        let ntime = [0xE0, 0xE1, 0xE2, 0xE3];
        let nbit = [0xF0, 0xF1, 0xF2, 0xF3];
        let elem = pack_uart_trans_ring_from_header_chunk(
            &bbv, &prev, &merkle, &ntime, &nbit, 0x1122_3344_5566_7788, 0xAABB_CCDD,
        );
        assert_eq!(elem.len(), 0xA8);
        assert_eq!(elem[0], 0xCF);
        assert_eq!(elem[63], 0xA1);
        assert_eq!(
            &elem[64..76],
            &[0xF3, 0xF2, 0xF1, 0xF0, 0xE3, 0xE2, 0xE1, 0xE0, 0xD3, 0xD2, 0xD1, 0xD0]
        );
        assert_eq!(&elem[76..80], &[0, 0, 0, 0]);
        assert_eq!(&elem[80..112], &merkle);
        assert_eq!(&elem[112..120], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&elem[120..124], &bbv);
        assert_eq!(&elem[124..128], &nbit);
        assert_eq!(&elem[128..132], &ntime);
        assert_eq!(&elem[132..164], &prev);
        assert_eq!(&elem[164..168], &0xAABB_CCDDu32.to_le_bytes());
        let wire = uart_trans_wire_from_ring_element(1, &elem);
        assert_eq!(&wire[0..4], &[0x55, 0xAA, 0x21, 0x36]);
        assert_eq!(wire[4], 0x08);
        assert_eq!(&wire[10..22], &elem[64..76]);
        assert_eq!(&wire[22..86], &elem[0..64]);
        assert_ne!(wire[3], 0x56);
        assert!(refuse_midstate_pair_data_fill(0).is_err());
    }

}
