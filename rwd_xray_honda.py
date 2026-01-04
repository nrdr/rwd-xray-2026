#!/usr/bin/env python3
"""
rwd_xray_honda.py

Small, self-contained helper to:
  1) parse Honda "Z" (0x5A) RWD files (Civic/Clarity EPS style)
  2) deterministically decrypt -> .bin using 3-byte key + 3 cipher ops
  3) brute-force (ops, key order) using a known (RWD,BIN) pair to discover the ops

Why this exists:
- The original rwd-xray approach "cracks" by searching for a part-number string inside
  decrypted output, which is brittle. If you have a known BIN, it's way cleaner to
  solve by direct comparison.

Usage examples:
  # (A) Find ops for your Civic given known pair
  python3 rwd_xray_honda.py find-ops --rwd 39990-TBA-A11.rwd --bin 39990-TBA-A11.bin

  # (B) Convert an RWD to BIN once you know ops (example ops string "+^-")
  python3 rwd_xray_honda.py rwd2bin --rwd 39990-TRW-A020.rwd --ops "+^-"

Notes:
- This only implements the x5a ("Z\\r\\n") container used by the EPS rwds in your
  flasher repo; it does not implement x31 (Insight-style) containers.
"""
from __future__ import annotations

import argparse
import itertools
import struct
from pathlib import Path
from typing import Dict, List, Tuple

# -------- crypto (byte-wise substitution table derived from (keys, ops)) --------

def _op_fn(sym: str):
    if sym == '+':
        return lambda a, b: a + b
    if sym == '-':
        return lambda a, b: a - b
    if sym == '^':
        return lambda a, b: a ^ b
    if sym == '&':
        return lambda a, b: a & b
    if sym == '|':
        return lambda a, b: a | b
    if sym == '*':
        return lambda a, b: a * b
    if sym == '/':
        # integer division; beware of division by zero (we avoid keys==0 check below)
        return lambda a, b: a // b
    if sym == '%':
        return lambda a, b: a % b
    raise ValueError(f"Unsupported op: {sym!r}")

def build_decoder(keys: bytes, ops: str) -> List[int]:
    """
    Build decoder[cipher_byte] = plain_byte
    """
    if len(keys) != 3:
        raise ValueError(f"Expected 3 key bytes, got {len(keys)}")
    if len(ops) != 3:
        raise ValueError(f"Expected ops length 3 (e.g. '+^-'), got {ops!r}")
    k1, k2, k3 = keys[0], keys[1], keys[2]
    # avoid div/mod by zero in case someone tests / or % with key==0
    if ('/' in ops or '%' in ops) and 0 in (k1, k2, k3):
        raise ValueError("Ops include / or % but a key byte is 0; not supported.")
    op1, op2, op3 = (_op_fn(ops[0]), _op_fn(ops[1]), _op_fn(ops[2]))

    decoder = [0] * 256
    for cipher in range(256):
        plain = op3(op2(op1(cipher, k1), k2), k3) & 0xFF
        decoder[cipher] = plain

    # ensure bijection (so we can invert for encryption if desired later)
    if len(set(decoder)) != 256:
        raise ValueError(f"Decoder not bijective for keys={keys.hex()} ops={ops!r}")
    return decoder

def decrypt_bytes(enc: bytes, decoder: List[int]) -> bytes:
    return bytes(decoder[b] for b in enc)

# -------- x5a ("Z") container parsing --------

def parse_x5a(rwd: bytes) -> Tuple[List[Tuple[int, List[bytes]]], bytes, int, int, bytes, int]:
    """
    Returns:
      headers: [(header_id, [values...]), ...]  for 6 headers
      keys: 3 bytes
      fw_start: int
      fw_len: int
      fw_enc: bytes
      file_checksum_le: int (u32 little-endian at end)
    """
    if len(rwd) < 3 or rwd[0:3] != b'Z\r\n':
        raise ValueError("Not an x5a/Z RWD (expected b'Z\\r\\n' at start)")

    idx = 3
    headers: List[Tuple[int, List[bytes]]] = []
    for h_id in range(6):
        cnt = rwd[idx]
        idx += 1
        vals: List[bytes] = []
        for _ in range(cnt):
            ln = rwd[idx]
            idx += 1
            vals.append(rwd[idx:idx+ln])
            idx += ln
        headers.append((h_id, vals))

    # key lives in header 5, single value of length 3 (matches x5a.py in your repo)
    key_vals = headers[5][1]
    if len(key_vals) != 1 or len(key_vals[0]) != 3:
        raise ValueError("Header 5 does not contain a single 3-byte encryption key")
    keys = key_vals[0]

    # firmware block header: 4-byte start + 4-byte length (big-endian), then data
    fw_start = struct.unpack('!I', rwd[idx:idx+4])[0]
    fw_len = struct.unpack('!I', rwd[idx+4:idx+8])[0]
    idx += 8

    fw_enc = rwd[idx:idx+fw_len]
    idx += fw_len

    # file checksum is last 4 bytes, little-endian uint32 = sum(all prior bytes) & 0xFFFFFFFF
    if idx != len(rwd) - 4:
        raise ValueError(f"Unexpected trailing bytes: idx={idx}, len={len(rwd)}")
    file_checksum_le = struct.unpack('<I', rwd[-4:])[0]

    return headers, keys, fw_start, fw_len, fw_enc, file_checksum_le

# -------- CLI commands --------

def cmd_rwd2bin(args: argparse.Namespace) -> int:
    rwd_path = Path(args.rwd)
    rwd = rwd_path.read_bytes()
    headers, keys, fw_start, fw_len, fw_enc, _ = parse_x5a(rwd)

    decoder = build_decoder(keys, args.ops)
    fw_plain = decrypt_bytes(fw_enc, decoder)

    out_path = Path(args.out) if args.out else rwd_path.with_suffix(f".{hex(fw_start)}.bin")
    out_path.write_bytes(fw_plain)
    print(f"Wrote {out_path} (start=0x{fw_start:X}, len=0x{fw_len:X}, key={keys.hex()}, ops={args.ops!r})")
    return 0

def _maybe_match_bin(decrypted: bytes, bin_data: bytes) -> bool:
    """
    BINs in the wild are *usually* just the decrypted payload (len == fw_len).
    If your BIN includes padding to the base address, try suffix match too.
    """
    if decrypted == bin_data:
        return True
    if len(bin_data) > len(decrypted) and bin_data.endswith(decrypted):
        return True
    return False

def cmd_find_ops(args: argparse.Namespace) -> int:
    rwd = Path(args.rwd).read_bytes()
    bin_data = Path(args.bin).read_bytes()
    _, keys, _, _, fw_enc, _ = parse_x5a(rwd)

    alphabet = list(args.op_alphabet)
    print(f"Keys from RWD header5: {keys.hex()}")
    print(f"Searching ops from alphabet: {''.join(alphabet)}")

    best = None  # (ratio, ops_s, key_perm, offset, matched, compared)

    # Consider key order permutations (3! = 6)
    key_perms = list(itertools.permutations(keys, 3))
    # Consider ordered triples (allow repeats) to avoid missing cases
    op_triples = list(itertools.product(alphabet, repeat=3))

    for kp in key_perms:
        kbytes = bytes(kp)

        # avoid div/mod by zero keys unless user insists on / or %
        if any(op in "/%" and b == 0 for op, b in zip("///", kbytes)):
            pass

        for ops in op_triples:
            ops_s = "".join(ops)

            # If user included / or %, skip any op that would divide/mod by zero key
            if any(op in "/%" and kb == 0 for op, kb in zip(ops_s, kbytes)):
                continue

            try:
                decoder = build_decoder(kbytes, ops_s)
            except Exception:
                continue

            dec = decrypt_bytes(fw_enc, decoder) ## Note to ChatGPT: Not "decode?"

            # Exact match (BIN is raw decrypted payload)
            if dec == bin_data:
                print(f"Exact match found! ops={ops_s} key_order={kp}")
                return 0

            if not args.allow_partial:
                continue

            # Partial mode: locate dec payload inside a container BIN
            anchor_len = max(8, int(args.anchor_len))
            sample_len = max(256, int(args.sample_len))
            anchor = dec[:anchor_len]

            start = 0
            hits = 0
            while True:
                off = bin_data.find(anchor, start)
                if off == -1:
                    break
                hits += 1
                if hits > args.max_hits:
                    break

                cmp_len = min(sample_len, len(dec), len(bin_data) - off)
                if cmp_len <= 0:
                    break

                matched = sum(1 for i in range(cmp_len) if dec[i] == bin_data[off + i])
                ratio = matched / cmp_len

                if best is None or ratio > best[0]:
                    best = (ratio, ops_s, kp, off, matched, cmp_len)

                start = off + 1

    if args.allow_partial and best is not None:
        ratio, ops_s, kp, off, matched, cmp_len = best
        print("Best partial candidate:")
        print(f"  ops={ops_s} key_order={kp} bin_offset=0x{off:X}")
        print(f"  match={matched}/{cmp_len} ({ratio*100:.2f}%)")
        print("If this percentage is high (say >95%), your BIN likely includes a container/header and")
        print("the decrypted firmware payload starts at that offset.")
        return 1

    print("No exact match found.")
    print("If your BIN is not a raw decrypted payload, rerun with --allow-partial to search for a payload slice.")
    return 2

def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_r2b = sub.add_parser("rwd2bin", help="Decrypt an x5a/Z RWD into a .bin payload")
    ap_r2b.add_argument("--rwd", required=True)
    ap_r2b.add_argument("--ops", required=True, help="3-char ops string, e.g. '+^-'")
    ap_r2b.add_argument("--out", default=None)
    ap_r2b.set_defaults(func=cmd_rwd2bin)

    ap_find = sub.add_parser("find-ops", help="Discover (ops, key order) from a known (RWD,BIN) pair")
    ap_find.add_argument("--rwd", required=True)
    ap_find.add_argument("--bin", required=True)
    ap_find.add_argument("--op-alphabet", default="+-^&|*", help="Ops to consider (default: '+-^&|*')")
    ap_find.add_argument("--allow-partial", action="store_true",
                         help="If exact match fails, search for decrypted payload inside a container BIN")
    ap_find.add_argument("--anchor-len", type=int, default=64,
                         help="Anchor length used for locating payload inside BIN (default: 64)")
    ap_find.add_argument("--sample-len", type=int, default=4096,
                         help="Bytes to score per candidate when allow-partial is enabled (default: 4096)")
    ap_find.add_argument("--max-hits", type=int, default=8,
                         help="Max anchor occurrences to evaluate per candidate (default: 8)")
    ap_find.set_defaults(func=cmd_find_ops)

    args = ap.parse_args()
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())
