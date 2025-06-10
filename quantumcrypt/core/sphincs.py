# quantumcrypt/core/sphincs.py
import oqs
import base64

def generate_signature_keypair():
    sig = oqs.Signature("SPHINCS+-SHA2-256s-simple")  # Higher security variant
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return base64.b64encode(public_key), base64.b64encode(secret_key)

def sign(message, secret_key):
    sig = oqs.Signature("SPHINCS+-SHA2-256s-simple", secret_key=base64.b64decode(secret_key))
    signature = sig.sign(message.encode())
    return base64.b64encode(signature)

def verify(message, signature, public_key):
    sig = oqs.Signature("SPHINCS+-SHA2-256s-simple")
    public_key = base64.b64decode(public_key)
    signature = base64.b64decode(signature)
    return sig.verify(message.encode(), signature, public_key)