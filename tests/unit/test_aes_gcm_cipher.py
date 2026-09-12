from dataclasses import FrozenInstanceError, fields, replace
import secrets

import pytest

import src.infrastructure.security.aes_gcm_cipher as cipher_module
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.security.errors import SecretCipherError
from src.ports.security import EncryptedSecret


def make_key() -> bytes:
    return secrets.token_bytes(32)


def test_valid_32_byte_key_is_accepted():
    cipher = AesGcmSecretCipher(make_key())

    assert cipher is not None


@pytest.mark.parametrize("key_size", [0, 16, 31, 33])
def test_invalid_key_length_is_rejected(key_size: int):
    with pytest.raises(
        SecretCipherError,
        match="key must be exactly 32 bytes",
    ):
        AesGcmSecretCipher(secrets.token_bytes(key_size))


def test_encrypt_decrypt_round_trip_returns_original_bytes():
    cipher = AesGcmSecretCipher(make_key())
    plaintext = b"temporary test credential"

    encrypted = cipher.encrypt(plaintext)

    assert cipher.decrypt(encrypted) == plaintext


def test_same_plaintext_is_encrypted_with_fresh_nonce_and_output():
    cipher = AesGcmSecretCipher(make_key())
    plaintext = b"temporary test credential"

    first = cipher.encrypt(plaintext)
    second = cipher.encrypt(plaintext)

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert first != second


def test_encrypted_nonce_is_exactly_12_bytes():
    cipher = AesGcmSecretCipher(make_key())

    encrypted = cipher.encrypt(b"temporary test credential")

    assert len(encrypted.nonce) == 12


def test_tampered_ciphertext_fails_closed():
    cipher = AesGcmSecretCipher(make_key())
    encrypted = cipher.encrypt(b"temporary test credential")
    tampered = replace(
        encrypted,
        ciphertext=(
            encrypted.ciphertext[:-1]
            + bytes([encrypted.ciphertext[-1] ^ 1])
        ),
    )

    with pytest.raises(
        SecretCipherError,
        match="secret authentication failed",
    ):
        cipher.decrypt(tampered)


def test_wrong_key_fails_closed():
    encrypted = AesGcmSecretCipher(make_key()).encrypt(
        b"temporary test credential"
    )
    wrong_cipher = AesGcmSecretCipher(make_key())

    with pytest.raises(
        SecretCipherError,
        match="secret authentication failed",
    ):
        wrong_cipher.decrypt(encrypted)


def test_encrypted_representation_exposes_no_plaintext_secret_field():
    assert {field.name for field in fields(EncryptedSecret)} == {
        "version",
        "nonce",
        "ciphertext",
    }


def test_encrypted_representation_is_immutable():
    encrypted = AesGcmSecretCipher(make_key()).encrypt(
        b"temporary test credential"
    )

    with pytest.raises(FrozenInstanceError):
        encrypted.nonce = secrets.token_bytes(12)


def test_plaintext_is_not_stored_as_ciphertext():
    cipher = AesGcmSecretCipher(make_key())
    plaintext = b"temporary test credential"

    encrypted = cipher.encrypt(plaintext)

    assert encrypted.ciphertext != plaintext
    assert plaintext not in encrypted.ciphertext


def test_encrypted_secret_rejects_invalid_nonce_length():
    with pytest.raises(ValueError, match="nonce must be exactly 12 bytes"):
        EncryptedSecret(
            version=1,
            nonce=secrets.token_bytes(11),
            ciphertext=secrets.token_bytes(16),
        )


def test_encrypted_secret_rejects_empty_ciphertext():
    with pytest.raises(ValueError, match="ciphertext cannot be empty"):
        EncryptedSecret(
            version=1,
            nonce=secrets.token_bytes(12),
            ciphertext=b"",
        )


def test_cipher_module_contains_no_module_level_key_or_nonce_bytes():
    module_byte_values = [
        value
        for value in vars(cipher_module).values()
        if isinstance(value, bytes)
    ]

    assert module_byte_values == []
