# quantumcrypt/tests/test_key_utils.py
from quantumcrypt.utils import key_utils
from quantumcrypt.core import kyber

def test_key_storage():
    pub, priv = kyber.generate_keypair()
    key_utils.save_key(priv, "test_priv.key", password="secret")
    loaded_key = key_utils.load_key("test_priv.key", password="secret")
    assert loaded_key == priv