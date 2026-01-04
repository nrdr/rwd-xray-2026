#!/usr/bin/env python3
import struct
from pathlib import Path

# --- Load the Civic/CR-V decrypt lookup table from rwd-xray's tools/bin_to_rwd.py ---
def load_decrypt_table(bin_to_rwd_path: Path) -> dict[int, int]:
    txt = bin_to_rwd_path.read_text(encoding="utf-8", errors="ignore")
    # Extract the dict literal
    start = txt.find("default_decrypt_lookup_table = {")
    if start < 0:
        raise RuntimeError("Could not find default_decrypt_lookup_table in bin_to_rwd.py")
    end = txt.find("}", start)
    if end < 0:
        raise RuntimeError("Could not parse default_decrypt_lookup_table dict")
    snippet = txt[start:end+1]
    ns = {}
    exec(snippet, {}, ns)
    table = ns["default_decrypt_lookup_table"]
    if len(table) != 256:
        raise RuntimeError(f"Lookup table length is {len(table)}, expected 256")
    return table

# --- Parse x5a (Z\\r\\n) RWD and return (key, start, length, enc_payload) ---
def parse_x5a_rwd(rwd: bytes):
    if rwd[:3] != b"Z\r\n":
        raise ValueError("Not x5a (Z\\r\\n) RWD")

    i = 3
    headers = []
    for hid in range(6):
        cnt = rwd[i]; i += 1
        vals = []
        for _ in range(cnt):
            ln = rwd[i]; i += 1
            vals.append(rwd[i:i+ln]); i += ln
        headers.append(vals)

    # header5 typically contains the 3-byte key
    h5 = headers[5]
    if not h5 or len(h5[0]) != 3:
        raise RuntimeError(f"Header5 key not found / unexpected: {[v.hex() for v in h5]}")
    key = h5[0]

    start = struct.unpack("!I", rwd[i:i+4])[0]
    length = struct.unpack("!I", rwd[i+4:i+8])[0]
    i += 8

    # after reading start, length, and advancing i by 8:

    end = i + length
    if end > len(rwd):
        raise RuntimeError(f"Truncated: need {length} bytes of firmware, only have {len(rwd)-i}")

    enc = rwd[i:end]
    trailer = rwd[end:]  # may be empty or contain checksum/meta stuff
    return key, start, length, enc, trailer

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--rwd", required=True, help="Input x5a .rwd file")
    ap.add_argument("--bin-to-rwd", default="tools/bin_to_rwd.py",
                    help="Path to rwd-xray tools/bin_to_rwd.py (for lookup table)")
    ap.add_argument("--out", default=None, help="Output .bin path (default: <rwd>.full.bin)")
    ap.add_argument("--fill", default="FF", help="Fill byte for 0..start-1 (default: FF)")
    args = ap.parse_args()

    rwd_path = Path(args.rwd)
    out_path = Path(args.out) if args.out else rwd_path.with_suffix(".full.bin")

    table = load_decrypt_table(Path(args.bin_to_rwd))
    key, start, length, enc, trailer = parse_x5a_rwd(rwd_path.read_bytes())

    print(f"key={key.hex()} start=0x{start:X} len=0x{length:X}")
    print(f"enc_len=0x{len(enc):X} trailer_len=0x{len(trailer):X}")

    if trailer:
        Path(str(out_path) + ".trailer.bin").write_bytes(trailer)

    fill_byte = int(args.fill, 16) & 0xFF
    dec = bytes(table[b] for b in enc)

    full = bytes([fill_byte]) * start + dec
    out_path.write_bytes(full)

    print(f"key={key.hex()} start=0x{start:X} len=0x{length:X}")
    print(f"wrote {out_path} size=0x{len(full):X} ({len(full)} bytes) fill=0x{fill_byte:02X}")

if __name__ == "__main__":
    main()