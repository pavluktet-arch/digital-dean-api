import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES

KEY_BYTES = {
    "aes-gcm": 32,
    "aes-cbc": 32,
}

BACKENDS = ("aes-gcm", "aes-cbc")


class CryptoProfileError(Exception):
    """Базовий виняток для помилок шифрування."""
    pass


def validate_profile(algorithm: str, key: bytes, nonce: bytes) -> str:
    """Перевіряє правильність алгоритму, довжини ключа (32 байти) та nonce (12 байтів)."""
    alg_lower = algorithm.lower()
    if alg_lower not in KEY_BYTES:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if len(key) != KEY_BYTES[alg_lower]:
        raise ValueError(f"Invalid key length: expected {KEY_BYTES[alg_lower]} bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"Invalid nonce length: expected 12 bytes, got {len(nonce)}")
    return alg_lower