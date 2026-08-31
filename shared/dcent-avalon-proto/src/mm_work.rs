// SPDX-License-Identifier: GPL-3.0-or-later
//
// mm_work — the SET_JOB payload of the mm_pkg protocol (2026-08-29 held
// evidence exhaustion: BENCH_CAPTURE_PLAN P1-2 static-RE deliverable).
//
// EVIDENCE STACK (all Canaan-origin facts, used as RE notes only — facts,
// never code, per the standing BUSL license rule):
//
// 1. The held stock 3S binary
//
//    linux/app/mm_miner` (RISC-V LP64, unstripped): its `litcore_set_job`
//    does `memcpy(&g_mm_work, pdata, len)` — the SET_JOB payload IS the
//    in-memory `mm_work` struct, byte for byte — and the symbol table pins
//    `g_mm_work` at exactly 7408 bytes.
// 2. The held Nano3s repo header (`cg_miner/mm_miner.h`) defines that
//    struct; hand-computed LP64 natural-alignment layout gives sizeof =
//    7408 — an exact match with the binary symbol (the industrial-tree
//    variant of the header lacks the `start`/`range` fields and computes
//    7400; the STOCK 3S binary matches the Nano3s variant).
// 3. `driver-avalon.c:518-525` fills `work.vmask[0..7]` from the pool's
//    version-roll candidate list — the 8-slot table rides INSIDE every
//    job (there is no separate vmask config opcode).
//
// H-MMWORK FALSIFICATION TARGET: the layout below is source+symbol-derived
// desk evidence, not a live capture. If a logic-analyzer capture of a stock
// SET_JOB disagrees, the capture wins and this module is corrected. Until
// then this codec is the best-evidence encoder for our shim and the
// decoder for offline replay of any captured SET_JOB stream.
//
// ENDIANNESS: the payload is a memcpy of the little-endian RISC-V in-memory
// struct, so every integer field is LITTLE-endian on the wire — EXCEPT the
// vmask words, which Canaan's cgminer byte-swaps to big-endian
// (`vmask_001[i] = bswap_32(version | candidate_i)`) BEFORE storing them,
// so a vmask slot holds the big-endian presentation of the absolute rolled
// version word.

/// Total serialized size of one `mm_work` (symbol-verified: `g_mm_work`).
pub const MM_WORK_SIZE: usize = 7408;

/// `coinbase[CVALON_P_COINBASE_SIZE]` capacity (6 KiB + 64 B).
pub const COINBASE_CAPACITY: usize = 6 * 1024 + 64;

/// `merkles[AVALON_P_MERKLES_COUNT][32]` capacity.
pub const MERKLES_CAPACITY: usize = 30;

/// Length beyond which `litcore_set_job` refuses the payload outright
/// (`len > sizeof(mm_work)` returns without touching `g_mm_work`).
pub const MAX_PAYLOAD_LEN: usize = MM_WORK_SIZE;

/// Field offsets of the wire layout (LP64 natural alignment).
pub mod off {
    pub const JOB_ID: usize = 0x0000; // u32
    pub const COINBASE_LEN: usize = 0x0008; // size_t (8 bytes, LP64)
    pub const COINBASE: usize = 0x0010; // [6208]
    pub const NONCE2: usize = 0x1850; // u32
    pub const NONCE2_OFFSET: usize = 0x1854; // i32
    pub const NONCE2_SIZE: usize = 0x1858; // i32
    pub const MERKLE_OFFSET: usize = 0x185C; // i32
    pub const NMERKLES: usize = 0x1860; // i32
    pub const MERKLES: usize = 0x1864; // [30][32]
    pub const HEADER: usize = 0x1C24; // [128]
    pub const TARGET: usize = 0x1CA4; // [32]
    pub const VMASK: usize = 0x1CC4; // [8] u32 (big-endian absolute words)
    pub const START: usize = 0x1CE4; // u32
    pub const RANGE: usize = 0x1CE8; // u32
    pub const WORK_RESTART: usize = 0x1CEC; // u8
}

/// Logical content of one SET_JOB, codec-side. Coinbase/merkle slices are
/// capacity-checked at encode time; `header` is the 80-byte block header
/// (the struct field is 128 bytes — the tail is zero-filled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmWork {
    pub job_id: u32,
    pub coinbase: Vec<u8>,
    pub nonce2: u32,
    pub nonce2_offset: i32,
    pub nonce2_size: i32,
    pub merkle_offset: i32,
    pub nmerkles: i32,
    pub merkles: Vec<[u8; 32]>,
    /// 80-byte block header (version..nonce).
    pub header: [u8; 80],
    /// 32-byte big-endian share target.
    pub target: [u8; 32],
    /// 8 version-roll table entries, each an ABSOLUTE rolled version word
    /// (base | candidate bits), byte-swapped to big-endian presentation by
    /// the stock builder. Build with [`stock_vmask_table`].
    pub vmask: [u32; 8],
    /// On-chip nonce-range start (stock field; 0 = whole range).
    pub start: u32,
    /// On-chip nonce-range size (stock field; 0 = whole range).
    pub range: u32,
    /// Nonzero restarts the big core's job ring (clears jobid history).
    pub work_restart: bool,
}

impl Default for MmWork {
    fn default() -> Self {
        Self {
            job_id: 0,
            coinbase: Vec::new(),
            nonce2: 0,
            nonce2_offset: 0,
            nonce2_size: 0,
            merkle_offset: 0,
            nmerkles: 0,
            merkles: Vec::new(),
            header: [0u8; 80],
            target: [0u8; 32],
            vmask: [0u32; 8],
            start: 0,
            range: 0,
            work_restart: false,
        }
    }
}

/// Build the stock 8-slot version-roll table as absolute, byte-swapped
/// words: slot 0 = base, slot 1 = base|full_mask, then base|single-bit for
/// each mask bit from bit 15 through bit 28 ascending (bits 13/14 never
/// receive their own slot; entries beyond 8 are dropped — the stock job
/// carries exactly the first 8 of its 16-entry candidate list).
pub fn stock_vmask_table(base_version: u32, mask: u32) -> [u32; 8] {
    let candidates: Vec<u32> = std::iter::once(0)
        .chain(std::iter::once(mask))
        .chain((15..=28).map(|bit| 1u32 << bit).filter(|bits| bits & mask != 0))
        .take(8)
        .collect();
    let mut table = [0u32; 8];
    for (slot, bits) in candidates.into_iter().enumerate() {
        // bswap_32(base | candidate): big-endian presentation in the slot.
        table[slot] = (base_version | bits).swap_bytes();
    }
    table
}

#[derive(Debug, thiserror::Error)]
pub enum MmWorkError {
    #[error("coinbase too large for mm_work: {0} > 6208")]
    CoinbaseTooLarge(usize),
    #[error("too many merkle branches for mm_work: {0} > 30")]
    TooManyMerkles(usize),
    #[error("nmerkles field {0} disagrees with the merkle branch count {1}")]
    MerkleCountMismatch(i32, usize),
}

impl MmWork {
    /// Encode into a zero-initialized 7408-byte wire buffer.
    pub fn encode(&self) -> Result<[u8; MM_WORK_SIZE], MmWorkError> {
        if self.coinbase.len() > COINBASE_CAPACITY {
            return Err(MmWorkError::CoinbaseTooLarge(self.coinbase.len()));
        }
        if self.merkles.len() > MERKLES_CAPACITY {
            return Err(MmWorkError::TooManyMerkles(self.merkles.len()));
        }
        if self.nmerkles != self.merkles.len() as i32 {
            return Err(MmWorkError::MerkleCountMismatch(
                self.nmerkles,
                self.merkles.len(),
            ));
        }
        let mut buf = [0u8; MM_WORK_SIZE];
        buf[off::JOB_ID..off::JOB_ID + 4].copy_from_slice(&self.job_id.to_le_bytes());
        buf[off::COINBASE_LEN..off::COINBASE_LEN + 8]
            .copy_from_slice(&(self.coinbase.len() as u64).to_le_bytes());
        buf[off::COINBASE..off::COINBASE + self.coinbase.len()]
            .copy_from_slice(&self.coinbase);
        buf[off::NONCE2..off::NONCE2 + 4].copy_from_slice(&self.nonce2.to_le_bytes());
        buf[off::NONCE2_OFFSET..off::NONCE2_OFFSET + 4]
            .copy_from_slice(&self.nonce2_offset.to_le_bytes());
        buf[off::NONCE2_SIZE..off::NONCE2_SIZE + 4]
            .copy_from_slice(&self.nonce2_size.to_le_bytes());
        buf[off::MERKLE_OFFSET..off::MERKLE_OFFSET + 4]
            .copy_from_slice(&self.merkle_offset.to_le_bytes());
        buf[off::NMERKLES..off::NMERKLES + 4]
            .copy_from_slice(&self.nmerkles.to_le_bytes());
        for (index, branch) in self.merkles.iter().enumerate() {
            let at = off::MERKLES + index * 32;
            buf[at..at + 32].copy_from_slice(branch);
        }
        buf[off::HEADER..off::HEADER + 80].copy_from_slice(&self.header);
        buf[off::TARGET..off::TARGET + 32].copy_from_slice(&self.target);
        for (slot, word) in self.vmask.iter().enumerate() {
            let at = off::VMASK + slot * 4;
            // The word is ALREADY in big-endian presentation (see
            // stock_vmask_table); store it little-endian so the wire bytes
            // read as the stock builder's bswap output.
            buf[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        buf[off::START..off::START + 4].copy_from_slice(&self.start.to_le_bytes());
        buf[off::RANGE..off::RANGE + 4].copy_from_slice(&self.range.to_le_bytes());
        buf[off::WORK_RESTART] = u8::from(self.work_restart);
        Ok(buf)
    }

    /// Decode a wire buffer back into the logical content. Capacity fields
    /// are taken from the buffer itself; oversizes fail closed.
    pub fn decode(buf: &[u8; MM_WORK_SIZE]) -> Self {
        let u32_at = |at: usize| {
            u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
        };
        let i32_at = |at: usize| i32::from_le_bytes(u32_at(at).to_le_bytes());
        let coinbase_len =
            usize::try_from(u64::from_le_bytes(buf[off::COINBASE_LEN..off::COINBASE_LEN + 8].try_into().unwrap()))
                .unwrap_or(usize::MAX)
                .min(COINBASE_CAPACITY);
        let nmerkles = i32_at(off::NMERKLES).clamp(0, MERKLES_CAPACITY as i32) as usize;
        let mut merkles = Vec::with_capacity(nmerkles);
        for index in 0..nmerkles {
            let at = off::MERKLES + index * 32;
            merkles.push(buf[at..at + 32].try_into().unwrap());
        }
        let mut vmask = [0u32; 8];
        for (slot, word) in vmask.iter_mut().enumerate() {
            *word = u32_at(off::VMASK + slot * 4);
        }
        MmWork {
            job_id: u32_at(off::JOB_ID),
            coinbase: buf[off::COINBASE..off::COINBASE + coinbase_len].to_vec(),
            nonce2: u32_at(off::NONCE2),
            nonce2_offset: i32_at(off::NONCE2_OFFSET),
            nonce2_size: i32_at(off::NONCE2_SIZE),
            merkle_offset: i32_at(off::MERKLE_OFFSET),
            nmerkles: i32_at(off::NMERKLES),
            merkles,
            header: buf[off::HEADER..off::HEADER + 80].try_into().unwrap(),
            target: buf[off::TARGET..off::TARGET + 32].try_into().unwrap(),
            vmask,
            start: u32_at(off::START),
            range: u32_at(off::RANGE),
            work_restart: buf[off::WORK_RESTART] != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MmWork {
        MmWork {
            job_id: 0x0102_0304,
            coinbase: vec![0xAB; 100],
            nonce2: 0x5566_7788,
            nonce2_offset: 64,
            nonce2_size: 4,
            merkle_offset: 2,
            nmerkles: 2,
            merkles: vec![[0x11; 32], [0x22; 32]],
            header: [0xCD; 80],
            target: [0xEF; 32],
            vmask: stock_vmask_table(0x2000_0000, 0x1FFF_E000),
            start: 0x1000,
            range: 0x2000,
            work_restart: true,
        }
    }

    /// The wire size is exactly the stock binary's `g_mm_work` symbol size
    /// (7408) and every field lands at its symbol/header-derived offset.
    #[test]
    fn layout_matches_the_symbol_verified_size_and_offsets() {
        let buf = sample().encode().unwrap();
        assert_eq!(buf.len(), 7408);
        assert_eq!(&buf[off::JOB_ID..off::JOB_ID + 4], &0x0102_0304u32.to_le_bytes());
        // coinbase_len rides as an 8-byte LP64 size_t at offset 8.
        assert_eq!(
            &buf[off::COINBASE_LEN..off::COINBASE_LEN + 8],
            &100u64.to_le_bytes()
        );
        assert_eq!(buf[off::COINBASE], 0xAB);
        assert_eq!(&buf[off::HEADER..off::HEADER + 4], &[0xCD; 4]);
        // header field is 128 bytes; the 80-byte header is zero-padded.
        assert_eq!(&buf[off::HEADER + 80..off::HEADER + 128], &[0u8; 48]);
        assert_eq!(&buf[off::TARGET..off::TARGET + 32], &[0xEF; 32]);
        assert_eq!(&buf[off::START..off::START + 4], &0x1000u32.to_le_bytes());
        assert_eq!(&buf[off::RANGE..off::RANGE + 4], &0x2000u32.to_le_bytes());
        assert_eq!(buf[off::WORK_RESTART], 1);
        // Tail padding to the 8-byte struct alignment stays zeroed.
        assert_eq!(&buf[off::WORK_RESTART + 1..], &[0u8; 3]);
    }

    #[test]
    fn encode_decode_round_trips() {
        let buf = sample().encode().unwrap();
        let decoded = MmWork::decode(&buf);
        assert_eq!(decoded, sample());
    }

    /// Stock vmask table (Canaan cgminer `set_vmask` + `get_vmask`):
    /// [base, base|mask, base|b15, base|b16, ...] as byte-swapped words,
    /// exactly 8 entries, bits 13/14 never getting their own slot.
    #[test]
    fn stock_vmask_table_shape() {
        let base = 0x2000_0000u32;
        let mask = 0x1FFF_E000u32;
        let table = stock_vmask_table(base, mask);
        assert_eq!(table.len(), 8);
        // Slot words are the big-endian presentation of the absolute version.
        assert_eq!(table[0], base.swap_bytes());
        assert_eq!(table[1], (base | mask).swap_bytes());
        assert_eq!(table[2], (base | (1 << 15)).swap_bytes());
        assert_eq!(table[3], (base | (1 << 16)).swap_bytes());
        assert_eq!(table[7], (base | (1 << 20)).swap_bytes());
        // No slot ever carries bits outside the mask (except slot 0 = base).
        for &word in &table[1..] {
            let absolute = word.swap_bytes();
            assert_eq!(absolute & !mask, base & !mask);
        }
        // A mask confined to bits 13/14 yields NO single-bit slots — the
        // stock loop starts at bit 15.
        let narrow = stock_vmask_table(base, 0x0000_3000);
        assert_eq!(narrow[0], base.swap_bytes());
        assert_eq!(narrow[1], (base | 0x3000).swap_bytes());
        assert_eq!(narrow[2..], [0u32; 6]);
    }

    #[test]
    fn oversize_inputs_fail_closed() {
        let mut work = sample();
        work.coinbase = vec![0u8; COINBASE_CAPACITY + 1];
        match work.encode() {
            Err(MmWorkError::CoinbaseTooLarge(size)) => {
                assert_eq!(size, COINBASE_CAPACITY + 1)
            }
            other => panic!("expected CoinbaseTooLarge, got {other:?}"),
        }
        let mut work = sample();
        work.merkles = vec![[0u8; 32]; MERKLES_CAPACITY + 1];
        work.nmerkles = (MERKLES_CAPACITY + 1) as i32;
        match work.encode() {
            Err(MmWorkError::TooManyMerkles(count)) => {
                assert_eq!(count, MERKLES_CAPACITY + 1)
            }
            other => panic!("expected TooManyMerkles, got {other:?}"),
        }
        let mut work = sample();
        work.nmerkles = 7;
        match work.encode() {
            Err(MmWorkError::MerkleCountMismatch(declared, actual)) => {
                assert_eq!((declared, actual), (7, 2))
            }
            other => panic!("expected MerkleCountMismatch, got {other:?}"),
        }
    }

    /// The payload is exactly what `litcore_set_job` memcpy's — so the
    /// encoded buffer is directly fragmentable via `MmPkg::fragment` as a
    /// SET_JOB (opcode 0x30) with no intermediate framing.
    #[test]
    fn encoded_payload_fragments_as_set_job() {
        use crate::mm_pkg::{Direction, MmPkg, Opcode, TypeWord};
        let buf = sample().encode().unwrap();
        let type_word = TypeWord {
            primary: Opcode::SetJob,
            subtype: None,
            direction: Direction::HostToMm,
        };
        let fragments = MmPkg::fragment(type_word, &buf).expect("fragmentable");
        // ceil(7408 / 256-byte payload fields) = 29 fragments.
        assert_eq!(fragments.len(), 29);
        assert_eq!(fragments.first().unwrap().header.idx, 0);
        assert_eq!(
            fragments.last().unwrap().header.num,
            u16::try_from(fragments.len()).unwrap()
        );
    }
}
