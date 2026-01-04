#!/usr/bin/env python3
import sys, binascii

if len(sys.argv) < 2:
    print("Usage: python3 clarity_try_key_xor.py /path/to/39990-TRW-A020.rwd")
    sys.exit(1)

FP = sys.argv[1]
data = open(FP,"rb").read()

# security key from your snippet
key = b"\x01\x11\x01\x12\x11\x20"

def xor_repeating(bts, key):
    out = bytearray(len(bts))
    for i, x in enumerate(bts):
        out[i] = x ^ key[i % len(key)]
    return bytes(out)

x = xor_repeating(data, key)

data_offsets = [
    0x13638, #speed_clamp_lo
    0x1388e, #torque_table row 1
    0x138a0, #torque_table row 2
    0x138b2, #torque_table row 3
    0x138c4, #torque_table row 4
    0x138d6, #torque_table row 5
    0x138e8, #torque_table row 6
    0x138fa, #torque_table row 7
    0x13ae0, #filter_table row 0
    0x13bdc, #new_table row 0
]

def printable(s):
    return ''.join(chr(c) if 32<=c<127 else '.' for c in s)

for off in data_offsets:
    if off < len(x):
        seg = x[off:off+48]
        print("0x{0:X}: {1} | {2}".format(off,
              binascii.hexlify(seg).decode(),
              printable(seg)))
    else:
        print("0x{0:X} - out of range (file len 0x{1:X})".format(off, len(x)))