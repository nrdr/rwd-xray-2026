# make_full_fw.py
with open("user_payload.bin", "rb") as f:
    payload = f.read()

assert len(payload) == 0x4C000, "Payload size wrong"

full_fw = bytearray(0x4000)  # fake bootloader (zeros)
full_fw += payload

with open("user.bin", "wb") as f:
    f.write(full_fw)

print("Built full firmware:", hex(len(full_fw)))