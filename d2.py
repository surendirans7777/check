from Crypto.Cipher import AES
import base64

# Key: [ID+testss+secret+secret]
key_string = "[ID+testss+secret+secret]"
key_bytes = key_string.encode('utf-8')[:16]

# Ciphertext (Base64-encoded for illustration purposes)
ciphertext = "5Ogq7biGj7s/Upcy9VDjHw=="

# Step 1: Create the AES cipher object
cipher = AES.new(key_bytes, AES.MODE_ECB)

# Step 2: Decode the Base64-encoded ciphertext
ciphertext_bytes = base64.b64decode(ciphertext)

# Step 3: Decrypt the ciphertext
plaintext_bytes = cipher.decrypt(ciphertext_bytes)

# Step 4: Remove padding (if present)
plaintext_bytes = plaintext_bytes.rstrip(b'\x00')

try:
    # Try to decode as UTF-8
    plaintext = plaintext_bytes.decode('utf-8')
    print(f"Decrypted message: {plaintext}")
except UnicodeDecodeError:
    # If decoding fails, print the plaintext bytes in hex
    print(f"Decrypted bytes: {plaintext_bytes.hex()}")
