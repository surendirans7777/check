import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def derive_key(request_id, secret_key, key_length=32):
    """
    Derive the AES key from the request_id and secret_key using SHA-256 hashing.

    Args:
        request_id (str): The request ID.
        secret_key (str): The secret key.
        key_length (int, optional): The desired length of the key in bytes. Defaults to 32 bytes (256 bits).

    Returns:
        bytes: The derived key.
    """
    key_data = request_id.encode() + secret_key.encode()
    hashed_key = hashlib.sha256(key_data).digest()
    return hashed_key[:key_length]

def encrypt_aes(plaintext, key):
    """
    Encrypt data using AES in CBC mode with a random Initialization Vector (IV).

    Args:
        plaintext (bytes): The plaintext data to be encrypted.
        key (bytes): The AES key.

    Returns:
        bytes: The encrypted data (including the IV).
    """
    iv = os.urandom(AES.block_size)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_aes(encrypted_data, key):
    """
    Decrypt data encrypted with AES in CBC mode.

    Args:
        encrypted_data (bytes): The encrypted data (including the IV).
        key (bytes): The AES key.

    Returns:
        bytes: The decrypted data.
    """
    iv = encrypted_data[:AES.block_size]  # Extract the IV from the encrypted data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_ciphertext = encrypted_data[AES.block_size:]
    decrypted_data = cipher.decrypt(padded_ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data

# Example usage
request_id = "some_request_id"
secret_key = "your_secret_key"
plaintext = b"This is a secret message!"

# Derive the key
key = derive_key(request_id, secret_key, key_length=32)

# Encrypt the plaintext
encrypted_data = encrypt_aes(plaintext, key)
print("Encrypted data:", encrypted_data)

# Decrypt the encrypted data
decrypted_data = decrypt_aes(encrypted_data, key)
print("Decrypted data:", decrypted_data.decode())
