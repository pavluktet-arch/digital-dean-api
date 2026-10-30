from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM


class CiphertextError(Exception):
    """Помилка при розшифруванні/автентифікації шифротексту."""
    pass


def seal_bytes(*args, **kwargs) -> tuple[bytes, bytes]:
    # Отримуємо аргументи
    if len(args) >= 6:
        backend, algorithm, key, nonce, message, aad = args[:6]
    else:
        backend = kwargs.get("backend", "cryptography")
        algorithm = kwargs.get("algorithm", kwargs.get("profile", "aes-256-gcm"))
        key = kwargs.get("key", b"")
        nonce = kwargs.get("nonce", b"")
        message = kwargs.get("message", kwargs.get("data", kwargs.get("plaintext", b"")))
        aad = kwargs.get("aad", kwargs.get("context", b""))

    try:
        alg = str(algorithm).lower()
        if "chacha" in alg:
            raw = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
        elif "ccm" in alg:
            raw = AESCCM(key).encrypt(nonce, message, aad)
        else:
            raw = AESGCM(key).encrypt(nonce, message, aad)
        return raw[:-16], raw[-16:]
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}") from e


def open_bytes(*args, **kwargs) -> bytes:
    if len(args) >= 7:
        backend, algorithm, key, nonce, ct, tag, aad = args[:7]
    else:
        backend = kwargs.get("backend", "cryptography")
        algorithm = kwargs.get("algorithm", kwargs.get("profile", "aes-256-gcm"))
        key = kwargs.get("key", b"")
        nonce = kwargs.get("nonce", b"")
        ct = kwargs.get("ct", kwargs.get("ciphertext", b""))
        tag = kwargs.get("tag", b"")
        aad = kwargs.get("aad", kwargs.get("context", b""))

    try:
        combined = ct + tag
        alg = str(algorithm).lower()
        if "chacha" in alg:
            return ChaCha20Poly1305(key).decrypt(nonce, combined, aad)
        elif "ccm" in alg:
            return AESCCM(key).decrypt(nonce, combined, aad)
        else:
            return AESGCM(key).decrypt(nonce, combined, aad)
    except Exception as e:
        raise CiphertextError("Decryption or authentication failed") from e