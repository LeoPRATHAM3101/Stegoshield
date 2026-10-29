"""Cryptographic layer: scrypt key derivation + AES-256-GCM (authenticated encryption).

One password -> 64 bytes of key material:
  * first 32 bytes : AES-256-GCM key (confidentiality + integrity)
  * last  32 bytes : seed for the keyed pixel permutation (where bits are hidden)
"""
import os
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
OVERHEAD = NONCE_LEN + TAG_LEN  # bytes added on top of the (compressed) message

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Return (aes_key, permutation_seed) derived from the password."""
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = Scrypt(salt=salt, length=64, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def encrypt(plaintext: bytes, aes_key: bytes) -> bytes:
    """Compress, then encrypt. Output = nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE_LEN)
    compressed = zlib.compress(plaintext, 9)
    return nonce + AESGCM(aes_key).encrypt(nonce, compressed, None)


def decrypt(blob: bytes, aes_key: bytes) -> bytes:
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        compressed = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError(
            "Authentication failed: wrong password, or no hidden data in this image."
        ) from None
    return zlib.decompress(compressed)
