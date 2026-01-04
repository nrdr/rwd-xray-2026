#!/usr/bin/env python3
import os
import sys
import struct
import gzip
import binascii
import operator
import itertools
import importlib

def get_checksum(data: bytes) -> int:
    # Honda checksum: (-sum(bytes)) & 0xFF
    return (-sum(data)) & 0xFF

def write_firmware(data: bytes, file_name: str):
    with open(file_name, 'wb') as o:
        o.write(data)
    print(f'firmware: {file_name}')

def read_file(fn: str) -> bytes:
    f_name, f_ext = os.path.splitext(fn)
    open_fn = open
    if f_ext == ".gz":
        open_fn = gzip.open

    with open_fn(fn, 'rb') as f:
        return f.read()

def get_part_number_prefix(fn: str, short: bool = False) -> str:
    f_name, _ = os.path.splitext(fn)
    f_base = os.path.basename(f_name)
    part_num = f_base.replace('-', '').replace('_', '')
    prefix = part_num[0:5] + '-' + part_num[5:8]
    if not short:
        prefix += '-' + part_num[8:12]
    return prefix

def main():
    if len(sys.argv) < 2:
        print("usage: rwd-xray.py <file.rwd>")
        sys.exit(1)

    f_name = sys.argv[1]
    f_dir = os.path.dirname(f_name)
    f_base = os.path.basename(f_name).split('.')[0]
    f_raw = read_file(f_name)

    # Python 3: slice to get bytes, decode hex to str
    f_type = "x" + binascii.b2a_hex(f_raw[0:1]).decode()
    f_module = importlib.import_module(f"format.{f_type}")
    f_class = getattr(f_module, f_type)
    fw = f_class(f_raw)
    print(fw)

    # write out encrypted firmware block(s)
    fenc_name = os.path.join(f_dir, f_base + '.enc')
    with open(fenc_name, 'wb') as fenc:
        for fe in fw.firmware_encrypted:
            fenc.write(fe)

    # attempt to decrypt firmware
    part_number_prefix = get_part_number_prefix(f_name)
    firmware_candidates = fw.decrypt(part_number_prefix)

    if not firmware_candidates:
        print('failed on long part number, trying truncated part number ...')
        part_number_prefix = get_part_number_prefix(f_name, short=True)
        firmware_candidates = fw.decrypt(part_number_prefix)

    if not firmware_candidates:
        print("decryption failed!")
        print("(could not find a cipher that results in the part number being in the data)")
        sys.exit(1)

    checksums = {
        "39990-TRW-A020": [
            (0x01f1e, 0x07fff),
            (0x08000, 0x225ff),
            (0x23200, 0x271ff),
            (0x27200, 0x295ff),
        ],
    }

    if len(firmware_candidates) > 1:
        print("multiple sets of keys resulted in data containing the part number")

    firmware_good = []

    for idx, fc in enumerate(firmware_candidates):
        firmware = bytearray()

        # reconstruct full address space
        for block_idx in range(len(fc)):
            start = fw.firmware_blocks[block_idx]["start"]
            if len(firmware) < start:
                firmware.extend(b'\x00' * (start - len(firmware)))
            firmware.extend(fc[block_idx])

        # validate known checksums - BYPASS TEMP
        firmware_good.append(bytes(firmware))

    if len(firmware_good) > 1:
        print("which firmware file is correct? who knows!")

    # write out decrypted firmware
    for f_data in firmware_good:
        start_addr = fw.firmware_blocks[0]["start"]
        f_out = os.path.join(f_dir, f"{f_base}.{hex(start_addr)}.bin")
        write_firmware(f_data[start_addr:], f_out)

if __name__ == "__main__":
    main()