import sys
import struct
import operator
import itertools
import re


class Base:
    def __init__(self, data, headers, keys, addr_blocks, encrypted):
        self._file_format = data[0:1]
        self._file_headers = headers
        self._file_checksum = struct.unpack('<L', data[-4:])[0]
        self._firmware_blocks = addr_blocks
        self._firmware_encrypted = encrypted
        self._keys = keys

        self.validate_file_checksum(data)

    # ---------- properties ----------

    @property
    def file_format(self):
        return self._file_format

    @property
    def file_checksum(self):
        return self._file_checksum

    @property
    def file_headers(self):
        return self._file_headers

    @property
    def firmware_blocks(self):
        return self._firmware_blocks

    @property
    def firmware_encrypted(self):
        return self._firmware_encrypted

    @property
    def keys(self):
        return self._keys

    # ---------- checksum ----------

    def calc_checksum(self, data: bytes) -> int:
        # Honda byte checksum
        return (-sum(data)) & 0xFF

    def validate_file_checksum(self, data: bytes):
        calculated = sum(data[:-4]) & 0xFFFFFFFF
        assert calculated == self.file_checksum, "file checksum mismatch"

    # ---------- cipher helpers ----------

    def _get_decoder(self, key1, key2, key3, op1, op2, op3):
        """
        Build a byte->byte decoder table.
        Returns None if transform is not bijective.
        """
        decoder = {}
        values = set()

        for e in range(256):
            d = op3(op2(op1(e, key1), key2), key3) & 0xFF
            decoder[e] = d
            values.add(d)

        return decoder if len(values) == 256 else None

    # ---------- decrypt ----------

    def decrypt(self, search_value: str):
        """
        Decrypt firmware blocks.
        NOTE: For Clarity, we DO NOT require the part number
        to appear inside the firmware payload.
        """

        print("decrypting (search disabled for this ECU)")

        operators = [
            {'fn': operator.xor,      'sym': '^'},
            {'fn': operator.and_,     'sym': '&'},
            {'fn': operator.or_,      'sym': '|'},
            {'fn': operator.add,      'sym': '+'},
            {'fn': operator.sub,      'sym': '-'},
            {'fn': operator.mul,      'sym': '*'},
            {'fn': operator.floordiv, 'sym': '/'},
            {'fn': operator.mod,      'sym': '%'},
        ]

        keys = [{'val': k, 'sym': f'k{i}'} for i, k in enumerate(self._keys)]
        assert len(keys) == 3, "exactly three keys currently required!"

        firmware_candidates = []
        display_ciphers = []
        attempted_decoders = []

        key_perms = itertools.permutations(keys)
        op_perms = itertools.product(operators, repeat=3)

        for k1, k2, k3 in key_perms:
            for o1, o2, o3 in op_perms:
                decoder = self._get_decoder(
                    k1['val'], k2['val'], k3['val'],
                    o1['fn'], o2['fn'], o3['fn']
                )

                if decoder is None or decoder in attempted_decoders:
                    continue

                attempted_decoders.append(decoder)

                # Decrypt firmware blocks (bytes -> bytes)
                candidate = [
                    bytes(decoder[b] for b in block)
                    for block in self._firmware_encrypted
                ]

                # Accept candidate; checksum validation happens later
                firmware_candidates.append(candidate)
                display_ciphers.append(
                    f"(((i {o1['sym']} {k1['sym']}) "
                    f"{o2['sym']} {k2['sym']}) "
                    f"{o3['sym']} {k3['sym']}) & 0xFF"
                )

                sys.stdout.write('X')
                sys.stdout.flush()

        print()
        for cipher in display_ciphers:
            print(f"cipher: {cipher}")

        return firmware_candidates

    # ---------- debug ----------

    def __str__(self):
        info = [
            f"file format: {self.file_format}",
            f"file checksum: {hex(self.file_checksum)}",
            "headers:",
        ]
        info.extend(str(h) for h in self._file_headers)
        info.append("keys:")
        info.extend(
            f"k{i} = {hex(self._keys[i])}"
            for i in range(len(self._keys))
        )
        info.append("address blocks:")
        info.extend(
            f"start = {hex(b['start'])} len = {hex(b['length'])}"
            for b in self._firmware_blocks
        )

        return '\n'.join(info)
