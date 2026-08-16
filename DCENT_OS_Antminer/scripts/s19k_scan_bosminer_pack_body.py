#!/usr/bin/env python3
"""Ghidra-free hunt for the real packed_struct pack() body.

Wave 1-12 only scanned MOVZ W0..W7. rustc temps are often W8..W15, so a
0x21/0x36 pair can hide in higher registers. This scan:

  * MOVZ all W0..W31 for 0x21 / 0x36 / 0x56 / 0x55 / 0xAA
  * MOVZ+STRB of the same Rd (length-field store)
  * ADRP+ADD xrefs to packing.rs / bm1398_6x.rs / command.rs / io.rs
  * packed_struct crate panic strings

Does not close T1 as fact. Prints offsets only.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

DEFAULT_REL = Path(
    ""
)


def load_segments(blob: bytes) -> list[tuple[int, int, int]]:
    assert blob[:4] == b"\x7fELF" and blob[4] == 2
    e_phoff = struct.unpack_from("<Q", blob, 32)[0]
    e_phentsize = struct.unpack_from("<H", blob, 54)[0]
    e_phnum = struct.unpack_from("<H", blob, 56)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", blob, off
        )
        if p_type == 1 and p_filesz:
            segs.append((p_offset, p_vaddr, p_filesz))
    return segs


def file_to_va(segs, file_off: int):
    for p_off, p_va, p_fsz in segs:
        if p_off <= file_off < p_off + p_fsz:
            return p_va + (file_off - p_off)
    return None


def va_to_file(segs, va: int):
    for p_off, p_va, p_fsz in segs:
        if p_va <= va < p_va + p_fsz:
            return p_off + (va - p_va)
    return None


def adrp_target(pc: int, word: int):
    if (word & 0x9F000000) != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def add_imm12(word: int):
    # ADD Xd, Xn, #imm12  (64-bit, no shift)  0x91000000
    if (word & 0xFFC00000) != 0x91000000:
        return None
    imm = (word >> 10) & 0xFFF
    rn = (word >> 5) & 0x1F
    rd = word & 0x1F
    return rn, rd, imm


def movz_w(word: int):
    if (word & 0xFF800000) != 0x52800000:
        return None
    return (word >> 5) & 0xFFFF, word & 0x1F


def strb_unsigned(word: int):
    # STRB Wt, [Xn, #imm12]  0x39000000
    if (word & 0xFFC00000) != 0x39000000:
        return None
    imm = (word >> 10) & 0xFFF
    rn = (word >> 5) & 0x1F
    rt = word & 0x1F
    return rt, rn, imm


def find_all(blob: bytes, pat: bytes, limit: int = 32) -> list[int]:
    out = []
    start = 0
    while len(out) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default=None)
    args = p.parse_args()
    path = Path(args.path) if args.path else None
    if path is None:
        here = Path(__file__).resolve()
        for root in [Path.cwd(), *here.parents]:
            cand = root / DEFAULT_REL
            if cand.is_file():
                path = cand
                break
    if path is None or not path.is_file():
        print("ERROR: bosminer.unpacked not found", file=__import__("sys").stderr)
        return 2

    blob = path.read_bytes()
    segs = load_segments(blob)
    print(f"FILE {path}")
    print(f"SIZE {len(blob)} PT_LOAD {len(segs)}")

    needles = {
        "packing.rs": b"packed_struct-0.10.1/src/packing.rs",
        "bm1398_6x.rs": b"bosminer-antminer/src/bm1398_6x.rs",
        "bm136x.rs": b"bosminer-antminer/src/bm136x.rs",
        "command.rs": b"bosminer-hal/src/command.rs",
        "io.rs": b"bosminer-hal/src/io.rs",
        "Unexpected size": b"BUG: Unexpected size",
        "Midstates work type": b"Midstates work type",
        "FRAME_BUFFER_SIZE": b"FRAME_BUFFER_SIZE",
        "Slice too small": b"Slice too small",
        "Not enough bits": b"Not enough bits",
        "Buffer too small": b"Buffer too small",
        "pack_to_slice": b"pack_to_slice",
        "PackedStruct": b"PackedStruct",
    }
    str_va = {}
    for name, pat in needles.items():
        offs = find_all(blob, pat)
        vas = []
        for off in offs[:4]:
            va = file_to_va(segs, off)
            vas.append((off, va))
        print(f"STR {name} hits={len(offs)} first={[(hex(o), hex(v) if v else None) for o, v in vas]}")
        if offs and file_to_va(segs, offs[0]) is not None:
            str_va[name] = file_to_va(segs, offs[0])

    p_off, p_va, p_fsz = segs[0]
    print(f"TEXT file={p_off:#x} va={p_va:#x} size={p_fsz:#x}")

    # ADRP page xrefs for packing.rs / bm1398_6x.rs
    for name in ("packing.rs", "bm1398_6x.rs", "command.rs", "io.rs"):
        va = str_va.get(name)
        if va is None:
            print(f"ADRP {name} SKIP no VA")
            continue
        page = va & ~0xFFF
        hits = []
        for i in range(0, p_fsz - 4, 4):
            word = struct.unpack_from("<I", blob, p_off + i)[0]
            tgt = adrp_target(p_va + i, word)
            if tgt == page:
                hits.append(p_va + i)
        print(f"ADRP_PAGE {name} page={page:#x} hits={len(hits)} first={[hex(x) for x in hits[:8]]}")

        # Refine: following ADD must land on the string VA (or +small rustc offset).
        exact = []
        for pc in hits:
            foff = va_to_file(segs, pc)
            if foff is None:
                continue
            nxt = struct.unpack_from("<I", blob, foff + 4)[0]
            add = add_imm12(nxt)
            if not add:
                continue
            _rn, _rd, imm = add
            landed = page + imm
            if abs(landed - va) <= 16:
                exact.append((pc, landed))
        print(f"ADRP_ADD_NEAR_STR {name} hits={len(exact)} first={[(hex(a), hex(b)) for a, b in exact[:8]]}")

    # MOVZ all registers
    want = {0x21: [], 0x36: [], 0x56: [], 0x55: [], 0xAA: [], 0x54: [], 0x58: []}
    for i in range(0, p_fsz - 4, 4):
        word = struct.unpack_from("<I", blob, p_off + i)[0]
        mz = movz_w(word)
        if not mz:
            continue
        imm, rd = mz
        if imm in want:
            want[imm].append((p_va + i, rd, p_off + i))
    for imm, hits in want.items():
        print(f"MOVZ_ALL #{imm:#x} hits={len(hits)}")

    def proximity(a_list, b_list, window: int) -> list[tuple]:
        out = []
        b_sorted = sorted(b_list, key=lambda t: t[0])
        bi = 0
        for a_pc, a_rd, a_off in a_list:
            while bi < len(b_sorted) and b_sorted[bi][0] < a_pc - window:
                bi += 1
            j = bi
            while j < len(b_sorted) and b_sorted[j][0] <= a_pc + window:
                out.append((a_pc, a_rd, b_sorted[j][0], b_sorted[j][1]))
                j += 1
        return out

    for window in (16, 32, 64):
        p36 = proximity(want[0x21], want[0x36], window)
        p56 = proximity(want[0x21], want[0x56], window)
        print(f"PROX_ALLREG mov#0x21~#0x36 window={window} pairs={len(p36)}")
        for a_pc, a_rd, b_pc, b_rd in p36[:12]:
            print(f"  21@{a_pc:#x} w{a_rd}  36@{b_pc:#x} w{b_rd}  delta={b_pc - a_pc}")
        print(f"PROX_ALLREG mov#0x21~#0x56 window={window} pairs={len(p56)}")
        for a_pc, a_rd, b_pc, b_rd in p56[:12]:
            print(f"  21@{a_pc:#x} w{a_rd}  56@{b_pc:#x} w{b_rd}  delta={b_pc - a_pc}")

    # MOVZ then STRB of same Rd within 16 insns
    store_hits = {0x21: [], 0x36: [], 0x56: [], 0x55: [], 0xAA: []}
    for imm, hits in want.items():
        if imm not in store_hits:
            continue
        for pc, rd, foff in hits:
            for k in range(1, 17):
                w = struct.unpack_from("<I", blob, foff + 4 * k)[0]
                st = strb_unsigned(w)
                if st and st[0] == rd:
                    store_hits[imm].append((pc, rd, st[2], p_va + (foff - p_off) + 4 * k))
                    break
        print(f"MOVZ_STRB #{imm:#x} hits={len(store_hits[imm])}")
        for pc, rd, imm12, st_pc in store_hits[imm][:8]:
            print(f"  movz@{pc:#x} w{rd} strb+{imm12} @{st_pc:#x}")

    # Same-function 0x21 STRB + 0x36 STRB within 64 B
    pair_store = 0
    for a_pc, a_rd, a_off12, a_st in store_hits[0x21]:
        for b_pc, b_rd, b_off12, b_st in store_hits[0x36]:
            if abs(a_st - b_st) <= 64:
                pair_store += 1
                print(
                    f"PACK_CANDIDATE 21_strb@{a_st:#x}+{a_off12} 36_strb@{b_st:#x}+{b_off12}"
                )
    pair56 = 0
    for a_pc, a_rd, a_off12, a_st in store_hits[0x21]:
        for b_pc, b_rd, b_off12, b_st in store_hits[0x56]:
            if abs(a_st - b_st) <= 64:
                pair56 += 1
                print(
                    f"FPGA_CANDIDATE 21_strb@{a_st:#x}+{a_off12} 56_strb@{b_st:#x}+{b_off12}"
                )
    print(f"PACK_CANDIDATE_COUNT 21+36={pair_store} 21+56={pair56}")
    print("T1_LENGTH_FIELD still DESK_PENDING unless a PACK_CANDIDATE is decompiled")
    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
