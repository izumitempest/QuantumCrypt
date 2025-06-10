# quantumcrypt/core/mceliece.py
import oqs
import base64

def generate_keypair():
    kem = oqs.KeyEncapsulation("Classic-McEliece-348864")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return base64.b64encode(public_key), base64.b64encode(secret_key)

def encrypt(public_key):
    kem = oqs.KeyEncapsulation("Classic-McEliece-348864")
    public_key = base64.b64decode(public_key)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return base64.b64encode(ciphertext), base64.b64encode(shared_secret)

def decrypt(ciphertext, secret_key):
    kem = oqs.KeyEncapsulation("Classic-McEliece-348864", secret_key=base64.b64decode(secret_key))
    ciphertext = base64.b64decode(ciphertext)
    shared_secret = kem.decap_secret(ciphertext)
    return base64.b64encode(shared_secret)