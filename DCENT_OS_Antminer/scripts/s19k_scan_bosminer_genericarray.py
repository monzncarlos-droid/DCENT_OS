#!/usr/bin/env python3
"""Wave-15: hunt packed_struct GenericArray / typenum sizes in bosminer.

Does not close T1. `U86` at 0xe80871 is an instruction collision.
"""
from __future__ import annotations

import argparse
from pathlib import Path

DEFAULT_REL = Path(
    ""
)


def find_all(blob: bytes, pat: bytes, limit: int = 8) -> list[int]:
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
        print("ERROR: bosminer.unpacked not found")
        return 2
    blob = path.read_bytes()
    print(f"FILE {path}")
    print(f"SIZE {len(blob)}")
    for n in (b"generic_array", b"GenericArray", b"U86", b"U88", b"packed_struct"):
        offs = find_all(blob, n)
        print(f"STR {n!r} hits={len(offs)} first={[hex(x) for x in offs[:4]]}")
    print("U86_AT_0xe80871 is LDURB collision 4d553836 not typenum")
    print("typenum hits are 'target type'+'number' collisions")
    print("T1_LENGTH_FIELD not closed as fact")
    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
