import struct
import binascii

def byte_array_to_hex(byte_array):
    return ''.join(f"{byte:02x}" for byte in byte_array)

def string_to_hex(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have an even length.")

    return bytes.fromhex(hex_string)

def load_server_public_key(server_public_key_obf):
    server_public_key = bytearray(32)

    for i in range(16):
        v16 = server_public_key_obf[31 - 2 * i + 32]
        v17 = (server_public_key_obf[2 * i + 1] ^ v16) | (v16 ^ server_public_key_obf[2 * i])
        rotated_v17 = ((v17 << (11 - (i & 7))) | (v17 >> (((i & 7) - 11) & 0xF))) & 0xFFFF
        value = rotated_v17 ^ server_public_key_obf[31 - i + 32]
        struct.pack_into('<H', server_public_key, 2 * i, value)

    return server_public_key

if __name__ == "__main__":
    server_public_key_str = (
        "  " # PUT OBFUSCATED KEY PART1(64)
        "  " # PUT OBFUSCATED KEY PART2(64)
        "  " # PUT OBFUSCATED KEY PART3(64)
        "  " # PUT OBFUSCATED KEY PART4(64)
    )

    server_public_key_obf = string_to_hex(server_public_key_str)
    server_public_key_obf2 = struct.unpack('<' + 'H' * (len(server_public_key_obf) // 2), server_public_key_obf)

    server_public_key = load_server_public_key(server_public_key_obf2)

    print("Result:", byte_array_to_hex(server_public_key))
