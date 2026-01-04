#!/usr/bin/env python3
import struct
from pathlib import Path

def verify_sum32_le(buf: bytes) -> None:
    if len(buf) < 4:
        raise RuntimeError("File too short")
    expected = int.from_bytes(buf[-4:], "little")
    actual = sum(buf[:-4]) & 0xFFFFFFFF
    if actual != expected:
        raise RuntimeError(f"Checksum mismatch: actual=0x{actual:08X} expected=0x{expected:08X}")

def parse_x5a_rwd(buf: bytes):
    if buf[:3] != b"Z\r\n":
        raise RuntimeError("Not x5a (Z\\r\\n)")

    # RWD ends with sum32; everything before that is content
    verify_sum32_le(buf)
    content = buf[:-4]

    i = 3
    headers = []
    for _hid in range(6):
        cnt = content[i]; i += 1
        vals = []
        for _ in range(cnt):
            ln = content[i]; i += 1
            vals.append(content[i:i+ln]); i += ln
        headers.append(vals)

    start = struct.unpack("!I", content[i:i+4])[0]
    length = struct.unpack("!I", content[i+4:i+8])[0]
    i += 8

    end = i + length
    if end > len(content):
        raise RuntimeError(f"Truncated payload: need 0x{length:X}, have 0x{len(content)-i:X}")

    enc = content[i:end]
    trailer = content[end:]  # may exist (metadata etc.)
    return headers, start, length, enc, trailer

def build_from_headers(headers, start, enc, trailer):
    out = bytearray()
    out += b"Z\r\n"
    for vals in headers:
        out.append(len(vals))
        for v in vals:
            out.append(len(v))
            out += v
    out += struct.pack("!I", start)
    out += struct.pack("!I", len(enc))
    out += enc
    out += trailer
    chk = sum(out) & 0xFFFFFFFF
    out += chk.to_bytes(4, "little")
    return bytes(out)

def load_default_table(bin_to_rwd_py: Path):
    txt = bin_to_rwd_py.read_text(encoding="utf-8", errors="ignore")
    s = txt.find("default_decrypt_lookup_table = {")
    if s < 0:
        raise RuntimeError("default_decrypt_lookup_table not found")
    e = txt.find("}", s)
    snippet = txt[s:e+1]
    ns = {}
    exec(snippet, {}, ns)
    tbl = ns["default_decrypt_lookup_table"]
    if len(tbl) != 256:
        raise RuntimeError(f"Table len {len(tbl)} != 256")
    # decrypt: plain = tbl[enc]
    dec = [0] * 256
    for k, v in tbl.items():
        dec[k] = v
    # encrypt: inverse mapping
    inv = [0] * 256
    for enc_b, plain_b in enumerate(dec):
        inv[plain_b] = enc_b
    return dec, inv

def first_diff(a: bytes, b: bytes):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i, a[i], b[i]
    if len(a) != len(b):
        return n, None, None
    return None

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--rwd", required=True)
    ap.add_argument("--bin-to-rwd", default="tools/bin_to_rwd.py")
    ap.add_argument("--out-rwd", default="roundtrip.rwd")
    ap.add_argument("--out-fullbin", default="roundtrip.full.bin")
    ap.add_argument("--fill", default="FF")
    args = ap.parse_args()

    rwd = Path(args.rwd).read_bytes()
    headers, start, length, enc, trailer = parse_x5a_rwd(rwd)
    print(f"Parsed RWD: start=0x{start:X} len=0x{length:X} trailer=0x{len(trailer):X}")
    # header5 key (often headers[5][0])
    if headers[5]:
        print("Header5:", [v.hex() for v in headers[5]])

    dec_tbl, enc_tbl = load_default_table(Path(args.bin_to_rwd))

    # decrypt / encrypt round-trip using lookup table
    plain = bytes(dec_tbl[b] for b in enc)
    enc2  = bytes(enc_tbl[b] for b in plain)

    # rebuild RWD using SAME headers + SAME trailer (only firmware bytes rederived)
    rwd2 = build_from_headers(headers, start, enc2, trailer)
    Path(args.out_rwd).write_bytes(rwd2)

    # build full-view BIN (prefix 0..start-1 filled)
    fill = int(args.fill, 16) & 0xFF
    fullbin = bytes([fill]) * start + plain
    Path(args.out_fullbin).write_bytes(fullbin)

    d = first_diff(rwd, rwd2)
    if d is None:
        print("Round-trip RWD is byte-for-byte identical to original.")
    else:
        off, a, b = d
        print(f"❌ Diff at offset 0x{off:X}: orig={a} new={b}")
        print("Tip: if this diff is near the end, it’s usually checksum/trailer handling.")

    print(f"Wrote: {args.out_rwd} and {args.out_fullbin} (size 0x{len(fullbin):X})")

if __name__ == "__main__":
    main()