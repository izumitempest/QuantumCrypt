# quantumcrypt/tests/test_sphincs.py
from quantumcrypt.core import sphincs

def test_sphincs_sign_verify():
    pub, priv = sphincs.generate_signature_keypair()
    message = "Hello, QuantumCrypt!"
    signature = sphincs.sign(message, priv)
    assert sphincs.verify(message, signature, pub)