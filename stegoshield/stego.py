"""Core steganography engine: keyed, encrypted LSB embedding in lossless images.

Layout of hidden data (1 bit per RGB channel value, LSB):

  [ header: salt(16) + blob_length(4) ]  -> first 160 channel values, sequential
  [ blob: nonce || AES-GCM ciphertext ]  -> scattered over the REST of the image
                                            in an order only the password holder
                                            can reproduce (keyed permutation)

There is no magic number / signature, so nothing in the file says "stego here".
"""
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

from . import crypto

HEADER_BYTES = crypto.SALT_LEN + 4
HEADER_BITS = HEADER_BYTES * 8


class CapacityError(ValueError):
    pass


# ---------------------------------------------------------------- image I/O
def load_image(path: str) -> np.ndarray:
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    return np.array(img)


def save_png(arr: np.ndarray, path: str) -> str:
    if not path.lower().endswith(".png"):
        path += ".png"  # LSB data only survives lossless formats
    Image.fromarray(arr).save(path, format="PNG")
    return path


# ------------------------------------------------------------- bit plumbing
def _write_bits(flat: np.ndarray, idx: np.ndarray, data: bytes) -> None:
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    flat[idx] = (flat[idx] & 0xFE) | bits


def _read_bits(flat: np.ndarray, idx: np.ndarray) -> bytes:
    return np.packbits(flat[idx] & 1).tobytes()


def _keyed_positions(seed: bytes, n_slots: int, count: int) -> np.ndarray:
    """First `count` entries of a password-keyed permutation of range(n_slots).

    Uses an AES-CTR keystream as random sort keys, so the result is
    cryptographically derived and identical across NumPy versions/platforms.
    """
    stream = Cipher(algorithms.AES(seed), modes.CTR(b"\x00" * 16)).encryptor()
    keys = np.frombuffer(stream.update(b"\x00" * (8 * n_slots)), dtype=np.uint64)
    return np.argsort(keys, kind="stable")[:count]


# ----------------------------------------------------------------- capacity
def capacity(arr: np.ndarray) -> dict:
    n_values = arr.shape[0] * arr.shape[1] * 3
    max_blob = (n_values - HEADER_BITS) // 8
    return {
        "channel_values": n_values,
        "max_blob_bytes": max_blob,
        # compression may make the real usable message larger than this
        "approx_max_message_bytes": max(0, max_blob - crypto.OVERHEAD),
    }


# ---------------------------------------------------------------------- API
def hide(cover_path: str, out_path: str, message: bytes, password: str) -> dict:
    arr = load_image(cover_path)
    rgb = arr[..., :3].copy()
    flat = rgb.reshape(-1)
    n = flat.size

    salt = crypto.new_salt()
    aes_key, seed = crypto.derive_keys(password, salt)
    blob = crypto.encrypt(message, aes_key)

    if len(blob) * 8 > n - HEADER_BITS:
        raise CapacityError(
            f"Message too large: needs {len(blob)} bytes, image holds "
            f"{(n - HEADER_BITS) // 8} bytes. Use a bigger cover image."
        )

    header = salt + len(blob).to_bytes(4, "big")
    _write_bits(flat, np.arange(HEADER_BITS), header)

    pos = _keyed_positions(seed, n - HEADER_BITS, len(blob) * 8) + HEADER_BITS
    _write_bits(flat, pos, blob)

    arr[..., :3] = rgb
    saved = save_png(arr, out_path)
    return {
        "output": saved,
        "message_bytes": len(message),
        "embedded_bytes": len(blob),
        "bits_changed_max": len(blob) * 8 + HEADER_BITS,
        "utilisation_pct": round(100 * (len(blob) * 8 + HEADER_BITS) / n, 4),
    }


def reveal(stego_path: str, password: str) -> bytes:
    arr = load_image(stego_path)
    flat = arr[..., :3].reshape(-1)
    n = flat.size

    header = _read_bits(flat, np.arange(HEADER_BITS))
    salt = header[: crypto.SALT_LEN]
    length = int.from_bytes(header[crypto.SALT_LEN :], "big")
    if length < crypto.OVERHEAD or length * 8 > n - HEADER_BITS:
        raise ValueError("No hidden data found in this image.")

    aes_key, seed = crypto.derive_keys(password, salt)
    pos = _keyed_positions(seed, n - HEADER_BITS, length * 8) + HEADER_BITS
    blob = _read_bits(flat, pos)
    return crypto.decrypt(blob, aes_key)
