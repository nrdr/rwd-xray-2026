import struct
from pathlib import Path

rwd = Path("civic_stock.rwd").read_bytes()
assert rwd[:3] == b"Z\r\n"
idx = 3
headers = []
for h_id in range(6):
    cnt = rwd[idx]; idx += 1
    vals = []
    for _ in range(cnt):
        ln = rwd[idx]; idx += 1
        vals.append(rwd[idx:idx+ln]); idx += ln
    headers.append((h_id, vals))

print("Header counts:", [(hid, len(vals), [len(v) for v in vals]) for hid, vals in headers])
print("Header5 raw values:", [v.hex() for v in headers[5][1]])

fw_start = struct.unpack("!I", rwd[idx:idx+4])[0]
fw_len   = struct.unpack("!I", rwd[idx+4:idx+8])[0]
print(f"fw_start=0x{fw_start:X} fw_len=0x{fw_len:X} ({fw_len} bytes)")