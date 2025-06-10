# tests/test_kyber.py
from quantumcrypt.core import kyber

def test_keypair_generation():
    pub, priv = kyber.generate_keypair()
    assert pub and priv and len(pub) > 10
