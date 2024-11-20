# modified_algo.py
from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def derive_keys(key):
    # Hash the key using SHA256
    sha256_hash = SHA256.new(data=key.encode('utf-8')).digest()
    # AES key: first 16 bytes, DES key: next 8 bytes
    aes_key = sha256_hash[:16]
    des_key = sha256_hash[16:24]
    return aes_key, des_key

def encrypt(plaintext, key):
    aes_key, des_key = derive_keys(key)
    # Encrypt with AES
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
    aes_encrypted = aes_cipher.encrypt(padded_text)
    # Encrypt with DES
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    padded_aes = pad(aes_encrypted, DES.block_size)
    des_encrypted = des_cipher.encrypt(padded_aes)
    return des_encrypted.hex()

def decrypt(ciphertext_hex, key):
    aes_key, des_key = derive_keys(key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    # Decrypt with DES
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    des_decrypted = unpad(des_cipher.decrypt(ciphertext), DES.block_size)
    # Decrypt with AES
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = aes_cipher.decrypt(des_decrypted)
    plaintext = unpad(decrypted_padded, AES.block_size)
    return plaintext.decode('utf-8')