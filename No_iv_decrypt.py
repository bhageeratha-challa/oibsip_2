from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_without_iv(ciphertext, key):
    # Use a zero IV as a placeholder
    zero_iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, zero_iv)
    decrypted_data = cipher.decrypt(ciphertext)
    
    # Remove padding if possible
    try:
        decrypted_data = unpad(decrypted_data, AES.block_size)
    except ValueError:
        # Padding might be incorrect or missing; proceed without unpadding
        pass
    
    return decrypted_data

def try_multiple_keys(ciphertext, keys):
    for i, key in enumerate(keys):
        print(f"Trying key {i+1}/{len(keys)}: {key.hex()}")
        decrypted_data = decrypt_without_iv(ciphertext, key)
        
        # Here we assume the decrypted data has some known structure
        # If it's a PDF, DOCX, etc., you can check for expected file headers
        if decrypted_data[:4] in [b'%PDF', b'PK\x03\x04']:  # Example for PDF and DOCX
            print(f"Key {i+1} seems to work! Saving decrypted file.")
            output_path = f'decrypted_file_output_{i+1}.ext'  # Change the extension accordingly
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            return key, output_path
    
    print("No valid key found.")
    return None, None

# Example usage
keys = [
    bytes.fromhex('your_key_1'), 
    bytes.fromhex('your_key_2'), 
    # Add more keys here
]
ciphertext_path = 'path_to_encrypted_file'

with open(ciphertext_path, 'rb') as f:
    ciphertext = f.read()

# Attempt decryption with each key
found_key, output_path = try_multiple_keys(ciphertext, keys)

if found_key:
    print(f"Decryption successful with key: {found_key.hex()}. File saved as {output_path}.")
else:
    print("Failed to decrypt the file with any of the provided keys.")
