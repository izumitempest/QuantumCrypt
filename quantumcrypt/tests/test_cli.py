# quantumcrypt/tests/test_cli.py
from click.testing import CliRunner
from quantumcrypt.cli import cli

def test_cli_generate():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate"])
    assert result.exit_code == 0
    assert "Public Key" in result.output
    assert "Secret Key" in result.output

def test_cli_sign_verify():
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Generate keys
        result = runner.invoke(cli, ["generate_signature", "--output-pub", "pub.key", "--output-priv", "priv.key"])
        print(result.output)  # Debug output
        print(result.exception)  # Debug exception
        assert result.exit_code == 0
        # Sign
        result = runner.invoke(cli, ["sign", "Hello", "--key", "priv.key", "--output", "sig.bin"])
        assert result.exit_code == 0
        # Verify
        result = runner.invoke(cli, ["verify", "Hello", "sig.bin", "--key", "pub.key"])
        assert result.exit_code == 0
        assert "Signature Valid: True" in result.output