# quantumcrypt/tests/test_hybrid.py
from quantumcrypt.hybrid import pq_aes_wrapper
from quantumcrypt.core import kyber

def test_hybrid_enc_dec():
    pub, priv = kyber.generate_keypair()
    message = "Hello, QuantumCrypt!"
    ciphertext, shared, nonce, enc_msg = pq_aes_wrapper.hybrid_encrypt(message, pub)
    decrypted = pq_aes_wrapper.hybrid_decrypt(ciphertext, priv, nonce, enc_msg)
    assert decrypted == message