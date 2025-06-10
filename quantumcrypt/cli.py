# quantumcrypt/cli.py
import click
import base64
import os
from quantumcrypt.core import kyber, sphincs
from quantumcrypt.hybrid import pq_aes_wrapper

@click.group()
def cli():
    """QuantumCrypt: Post-quantum encryption and signing tool"""
    pass

@cli.command()
@click.option("--output-pub", type=click.Path(), help="File to save public key")
@click.option("--output-priv", type=click.Path(), help="File to save secret key")
def generate(output_pub, output_priv):
    """Generate a Kyber768 keypair"""
    pub, priv = kyber.generate_keypair()
    click.echo(f"Public Key: {pub.decode()}")
    click.echo(f"Secret Key: {priv.decode()}")
    if output_pub:
        with open(output_pub, "wb") as f:
            f.write(pub)
        click.echo(f"Saved public key to {output_pub}")
    if output_priv:
        with open(output_priv, "wb") as f:
            f.write(priv)
        click.echo(f"Saved secret key to {output_priv}")

@cli.command()
@click.option("--output-pub", type=click.Path(), help="File to save public key")
@click.option("--output-priv", type=click.Path(), help="File to save secret key")
def generate_signature(output_pub, output_priv):
    """Generate a SPHINCS+-SHA2-256s-simple keypair"""
    pub, priv = sphincs.generate_signature_keypair()
    click.echo(f"Public Key: {pub.decode()}")
    click.echo(f"Secret Key: {priv.decode()}")
    if output_pub:
        with open(output_pub, "wb") as f:
            f.write(pub)
        click.echo(f"Saved public key to {output_pub}")
    if output_priv:
        with open(output_priv, "wb") as f:
            f.write(priv)
        click.echo(f"Saved secret key to {output_priv}")

@cli.command()
@click.argument("message")
@click.option("--key", required=True, help="Base64-encoded or file path to secret key")
@click.option("--output", type=click.Path(), help="File to save signature")
def sign(message, key, output):
    """Sign a message with SPHINCS+-SHA2-256s-simple"""
    secret_key = base64.b64decode(key) if not os.path.exists(key) else open(key, "rb").read()
    signature = sphincs.sign(message, secret_key)
    click.echo(f"Signature: {signature.decode()}")
    if output:
        with open(output, "wb") as f:
            f.write(signature)
        click.echo(f"Saved signature to {output}")

@cli.command()
@click.argument("message")
@click.argument("signature")
@click.option("--key", required=True, help="Base64-encoded or file path to public key")
def verify(message, signature, key):
    """Verify a SPHINCS+-SHA2-256s-simple signature"""
    public_key = base64.b64decode(key) if not os.path.exists(key) else open(key, "rb").read()
    signature = base64.b64decode(signature) if not os.path.exists(signature) else open(signature, "rb").read()
    verified = sphincs.verify(message, signature, public_key)
    click.echo(f"Signature Valid: {verified}")

@cli.command()
@click.argument("message")
@click.option("--key", required=True, help="Base64-encoded or file path to public key")
@click.option("--output", type=click.Path(), help="File to save encrypted data")
def hybrid_encrypt(message, key, output):
    """Encrypt a message using Kyber768 + AES-GCM"""
    public_key = base64.b64decode(key) if not os.path.exists(key) else open(key, "rb").read()
    ciphertext, shared, nonce, enc_msg = pq_aes_wrapper.hybrid_encrypt(message, public_key)
    click.echo(f"Ciphertext: {ciphertext.decode()}")
    click.echo(f"Nonce: {base64.b64encode(nonce).decode()}")
    click.echo(f"Encrypted Message: {base64.b64encode(enc_msg).decode()}")
    if output:
        with open(output, "wb") as f:
            f.write(ciphertext + b"\n" + base64.b64encode(nonce) + b"\n" + base64.b64encode(enc_msg))
        click.echo(f"Saved encrypted data to {output}")

@cli.command()
@click.argument("ciphertext")
@click.argument("nonce")
@click.argument("encrypted_message")
@click.option("--key", required=True, help="Base64-encoded or file path to secret key")
def hybrid_decrypt(ciphertext, nonce, encrypted_message, key):
    """Decrypt a message using Kyber768 + AES-GCM"""
    secret_key = base64.b64decode(key) if not os.path.exists(key) else open(key, "rb").read()
    nonce = base64.b64decode(nonce)
    encrypted_message = base64.b64decode(encrypted_message)
    message = pq_aes_wrapper.hybrid_decrypt(ciphertext, secret_key, nonce, encrypted_message)
    click.echo(f"Decrypted Message: {message}")

if __name__ == "__main__":
    cli()