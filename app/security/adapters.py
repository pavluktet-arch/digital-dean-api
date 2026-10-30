from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from app.security.profiles import validate_profile, CryptoProfileError


class CiphertextError(CryptoProfileError):
    """Виняток для помилок розшифрування або пошкодженого шифротексту/тегу."""
    pass


def seal_bytes(backend: str, algorithm: str, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Шифрує дані та повертає (ciphertext, tag)."""
    validate_profile(algorithm, key, nonce)
    alg_lower = algorithm.lower()

    try:
        if alg_lower == "aes-gcm":
            aesgcm = AESGCM(key)
            full_ct = aesgcm.encrypt(nonce, data, aad)
            return full_ct[:-16], full_ct[-16:]

        elif alg_lower == "aes-cbc":
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext, tag
    except Exception as e:
        raise CryptoProfileError(f"Encryption error: {e}")

    raise ValueError(f"Unsupported backend or algorithm: {backend}/{algorithm}")


def open_bytes(backend: str, algorithm: str, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """Розшифровує дані та перевіряє автентичність."""
    validate_profile(algorithm, key, nonce)
    alg_lower = algorithm.lower()

    try:
        if alg_lower == "aes-gcm":
            aesgcm = AESGCM(key)
            full_ct = ciphertext + tag
            return aesgcm.decrypt(nonce, full_ct, aad)

        elif alg_lower == "aes-cbc":
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            cipher.update(aad)
            return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise CiphertextError(f"Decryption or authentication failed: {e}")

    raise ValueError(f"Unsupported backend or algorithm: {backend}/{algorithm}")