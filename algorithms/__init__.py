# algorithms/__init__.py

from .caesar_cipher import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from .aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from .des_cipher import encrypt as des_encrypt, decrypt as des_decrypt
from .rsa_cipher import encrypt as rsa_encrypt, decrypt as rsa_decrypt, generate_keys
from .sha1_hash import hash_text as sha1_hash
from .modified_algo import encrypt as modified_encrypt, decrypt as modified_decrypt