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

def find_and_extract_key(file_path):
    target_sequence = bytes.fromhex("1A D5 00 00 00 00 00")
    key_length = 256
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        index = data.find(target_sequence)
        if index == -1:
            raise ValueError("Target sequence not found in the file.")
        start_index = index - key_length
        if start_index < 0:
            raise ValueError("Not enough data before the target sequence.")
        obfuscated_key = data[start_index:index][:key_length]
        obfuscated_key = obfuscated_key.lstrip(b'\x00')
        hex_key = ''.join(f'{byte:02X}' for byte in obfuscated_key)
        chunks = [hex_key[i:i + 64] for i in range(0, len(hex_key), 64)]
        combined_key = ''.join(chunks)
        print(f"Obfuscated key found: {combined_key}")
        return combined_key
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")

if __name__ == "__main__":
    file_path = './lib/libg.so'
    combined_key = find_and_extract_key(file_path)
    server_public_key_str = combined_key
    server_public_key_obf = string_to_hex(server_public_key_str)
    server_public_key_obf2 = struct.unpack('<' + 'H' * (len(server_public_key_obf) // 2), server_public_key_obf)
    server_public_key = load_server_public_key(server_public_key_obf2)
    print(f"Deobfuscated Key: {byte_array_to_hex(server_public_key)}")
