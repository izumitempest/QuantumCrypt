# quantumcrypt/tests/test_mceliece.py
from quantumcrypt.core import mceliece

def test_mceliece_enc_dec():
    pub, priv = mceliece.generate_keypair()
    ciphertext, shared = mceliece.encrypt(pub)
    shared2 = mceliece.decrypt(ciphertext, priv)
    assert shared == shared2