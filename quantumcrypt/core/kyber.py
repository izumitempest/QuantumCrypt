# quantumcrypt/core/kyber.py
import oqs

def generate_keypair():
    with oqs.KeyEncapsulation('Kyber512') as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key

def encrypt(public_key):
    with oqs.KeyEncapsulation('Kyber512') as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

def decrypt(ciphertext, secret_key):
    with oqs.KeyEncapsulation('Kyber512') as kem:
        kem.import_secret_key(secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
