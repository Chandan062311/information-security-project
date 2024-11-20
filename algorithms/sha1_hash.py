# sha1_hash.py
import hashlib

def hash_text(text):
    sha1 = hashlib.sha1()
    sha1.update(text.encode('utf-8'))
    return sha1.hexdigest()