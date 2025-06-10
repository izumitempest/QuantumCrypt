# quantumcrypt/utils/key_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def save_key(key, filename, password=None):
    if password:
        # Derive a key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
        )
        key_enc_key = kdf.derive(password.encode())
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key_enc_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(key) + encryptor.finalize()
        with open(filename, "wb") as f:
            f.write(nonce + encryptor.tag + kdf._salt + encrypted_key)
    else:
        with open(filename, "wb") as f:
            f.write(key)

def load_key(filename, password=None):
    with open(filename, "rb") as f:
        data = f.read()
    if password:
        nonce, tag, salt, encrypted_key = data[:12], data[12:28], data[28:44], data[44:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_enc_key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key_enc_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_key) + decryptor.finalize()
    return data