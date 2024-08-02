from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import itertools

def try_decrypt_with_iv(ciphertext, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data
    except (ValueError, KeyError):
        return None

def find_correct_iv(ciphertext, keys, known_plaintext=None):
    iv_patterns = [
        b'\x00' * 16,           # All zeros
        b'\x01' * 16,           # All ones
        b'\xff' * 16,           # All 255
        # Add other IV patterns here if known
    ]
    
    for key in keys:
        print(f"Trying key: {key.hex()}")
        for iv in iv_patterns:
            decrypted_data = try_decrypt_with_iv(ciphertext, key, iv)
            if decrypted_data:
                if known_plaintext and known_plaintext in decrypted_data:
                    print(f"Correct IV found with key {key.hex()} and IV {iv.hex()}")
                    return decrypted_data, iv
                else:
                    print(f"Decryption seems successful with key {key.hex()} and IV {iv.hex()}")
                    return decrypted_data, iv
    
    print("No valid IV found.")
    return None, None

# Example usage
keys = [bytes.fromhex('your_key_1'), bytes.fromhex('your_key_2')]  # Replace with actual keys
ciphertext_path = 'path_to_encrypted_file'

with open(ciphertext_path, 'rb') as f:
    ciphertext = f.read()

# Optional: If you know part of the original plaintext, provide it here
known_plaintext = b'%PDF'  # For example, for a PDF file

decrypted_data, found_iv = find_correct_iv(ciphertext, keys, known_plaintext)

if decrypted_data:
    with open('decrypted_file_output.pdf', 'wb') as f:
        f.write(decrypted_data)
    print(f"Decryption successful, IV: {found_iv.hex()}")
else:
    print("Failed to decrypt the file.")
