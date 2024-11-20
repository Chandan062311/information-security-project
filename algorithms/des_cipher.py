# des_cipher.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def encrypt(plaintext, key):
    key_bytes = key.encode('utf-8').ljust(8, b'\0')[:8]
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    plaintext_padded = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext.hex()

def decrypt(ciphertext_hex, key):
    key_bytes = key.encode('utf-8').ljust(8, b'\0')[:8]
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, DES.block_size)
    return plaintext.decode('utf-8')