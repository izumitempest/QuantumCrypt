# quantumcrypt/tests/test_kyber.py
from quantumcrypt.core import kyber

def test_kyber_enc_dec():
    pub, priv = kyber.generate_keypair()
    assert pub and priv
    ciphertext, shared = kyber.encrypt(pub)
    assert ciphertext and shared
    shared2 = kyber.decrypt(ciphertext, priv)
    assert shared == shared2