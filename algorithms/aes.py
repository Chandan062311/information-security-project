# aes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(plaintext, key):
    key_bytes = key.encode('utf-8').ljust(16, b'\0')[:16]
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    plaintext_padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext.hex()

def decrypt(ciphertext_hex, key):
    key_bytes = key.encode('utf-8').ljust(16, b'\0')[:16]
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext.decode('utf-8')