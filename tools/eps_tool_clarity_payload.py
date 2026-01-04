#!/usr/bin/env python3
"""
eps_tool_clarity_payload.py

Purpose:
- Build a Honda EPS .rwd file from a payload-only bin (0x4C000) using a *template* .rwd for header fields.
- This is the safest "stealth" path because it preserves the exact header structure the car already accepts.

Key idea:
- RWD = [header bytes] + [start_addr(4) + data_size(4)] + [encrypted_payload] + [file_checksum_le32]
- Your Clarity pulls give you the 0x4C000 payload region (often already encrypted).
- We reuse the header + start/len from a known-good stock RWD and only swap the payload.

Supports:
- Input payload .bin (exactly 0x4C000 bytes)
- Template .rwd (stock or known-good) from the same ECU
- Optional: verify that the new payload matches the template payload (to confirm "no change")

NOTE:
- This script does NOT patch tables yet. It's the "repack payload -> valid RWD" building block.
"""

import argparse
import struct
import hashlib
from pathlib import Path


PAYLOAD_LEN = 0x4C000
TRAILER_LEN = 4   # file checksum at end, little-endian uint32


def u32le(b: bytes) -> int:
    return struct.unpack("<I", b)[0]


def sum_u32(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser(description="Build Clarity EPS RWD from payload-only bin using a template RWD header.")
    ap.add_argument("-i", "--input", required=True, help="Payload-only bin (0x4C000 bytes). Usually encrypted payload.")
    ap.add_argument("-t", "--template", required=True, help="Template RWD (stock/known-good) from same ECU.")
    ap.add_argument("-o", "--output", default="user_payload_built.rwd", help="Output RWD path.")
    ap.add_argument("--verify-same", action="store_true",
                    help="Assert input payload is identical to template payload (true 'no change').")
    ap.add_argument("--print-hashes", action="store_true", help="Print MD5 of template payload, input payload, output rwd.")
    args = ap.parse_args()

    in_path = Path(args.input)
    tpl_path = Path(args.template)
    out_path = Path(args.output)

    payload = in_path.read_bytes()
    tpl = tpl_path.read_bytes()

    if len(payload) != PAYLOAD_LEN:
        raise SystemExit(f"Input payload must be {PAYLOAD_LEN} bytes (0x4C000). Got {len(payload)} (0x{len(payload):X}).")

    if len(tpl) < (PAYLOAD_LEN + TRAILER_LEN + 8):
        raise SystemExit("Template RWD is too small to contain header + start/len + payload + checksum.")

    # Template layout:
    # [header_bytes][start_len(8)][payload(0x4C000)][checksum(4)]
    tpl_checksum = u32le(tpl[-4:])
    tpl_payload = tpl[-(PAYLOAD_LEN + 4):-4]
    tpl_start_len = tpl[-(PAYLOAD_LEN + 4 + 8):-(PAYLOAD_LEN + 4)]
    tpl_header = tpl[:-(PAYLOAD_LEN + 4 + 8)]

    # Sanity: recompute template checksum
    recomputed_tpl_checksum = sum_u32(tpl_header + tpl_start_len + tpl_payload)
    if recomputed_tpl_checksum != tpl_checksum:
        raise SystemExit(
            "Template checksum mismatch. Template may not be a standard RWD, or file is corrupted.\n"
            f"  Template checksum:   0x{tpl_checksum:08X}\n"
            f"  Recomputed checksum: 0x{recomputed_tpl_checksum:08X}"
        )

    if args.verify_same:
        if payload != tpl_payload:
            raise SystemExit("verify-same failed: input payload differs from template payload.")
        else:
            print("verify-same OK: input payload == template payload")

    # Build output with the same header and start/len, new payload
    out_checksum = sum_u32(tpl_header + tpl_start_len + payload)
    out = tpl_header + tpl_start_len + payload + struct.pack("<I", out_checksum)
    out_path.write_bytes(out)

    if args.print_hashes:
        def md5(b: bytes) -> str:
            return hashlib.md5(b).hexdigest()
        print("Template payload MD5:", md5(tpl_payload))
        print("Input payload MD5:   ", md5(payload))
        print("Output RWD MD5:      ", md5(out))
        print("Output checksum:     ", f"0x{out_checksum:08X}")

    print(f"Built: {out_path} ({len(out)} bytes)")


if __name__ == "__main__":
    main()
