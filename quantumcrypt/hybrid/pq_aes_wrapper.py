# quantumcrypt/hybrid/pq_aes_wrapper.py
from quantumcrypt.core import kyber
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def hybrid_encrypt(message, public_key):
    # Use Kyber to encrypt a random AES key
    aes_key = os.urandom(32)  # 256-bit key
    ciphertext, shared_secret = kyber.encrypt(public_key)
    
    # Derive a consistent AES key from shared_secret for decryption
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-GCM
        salt=None,
        info=b"QuantumCryptHybrid",
    )
    derived_key = hkdf.derive(shared_secret)
    
    # Use AES-GCM to encrypt the message
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)
    
    return ciphertext, shared_secret, nonce, encrypted_message

def hybrid_decrypt(ciphertext, secret_key, nonce, encrypted_message):
    # Recover shared secret via Kyber
    shared_secret = kyber.decrypt(ciphertext, secret_key)
    
    # Derive the same AES key from shared_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-GCM
        salt=None,
        info=b"QuantumCryptHybrid",
    )
    derived_key = hkdf.derive(shared_secret)
    
    # Decrypt message with AES-GCM
    aesgcm = AESGCM(derived_key)
    message = aesgcm.decrypt(nonce, encrypted_message, None)
    return message.decode()