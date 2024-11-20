# rsa_cipher.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt(plaintext, public_key_str):
    public_key = RSA.import_key(public_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return ciphertext.hex()

def decrypt(ciphertext_hex, private_key_str):
    private_key = RSA.import_key(private_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')