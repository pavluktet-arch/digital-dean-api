import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import Suite, KEM, KDF, AEAD

from app.security.asymmetric.profiles import CONTEXT, PROFILES, KEY_PROFILES


class DecryptionError(Exception):
    """Помилка при розшифруванні повідомлення."""
    pass


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private, private.public_key()
    elif key_profile == "rsa-3072":
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        return private, private.public_key()
    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
        return private, private.public_key()
    elif key_profile == "p256":
        private = ec.generate_private_key(ec.SECP256R1())
        return private, private.public_key()
    else:
        raise ValueError(f"Unknown key profile: {key_profile}")


def encrypt(profile: str, public_key: object, message: bytes, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported profile")

    if profile == "rsa2048-oaep":
        if len(message) > 190:
            raise ValueError("Message too long for RSA-2048 OAEP")
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=context,
        )
        return public_key.encrypt(message, oaep)

    elif profile == "rsa3072-oaep":
        if len(message) > 318:
            raise ValueError("Message too long for RSA-3072 OAEP")
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=context,
        )
        return public_key.encrypt(message, oaep)

    elif profile == "rsa3072-oaep-aes256gcm":
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=context,
        )
        wrapped_key = public_key.encrypt(aes_key, oaep)
        cipher = AESGCM(aes_key)
        ciphertext = cipher.encrypt(nonce, message, context)
        return wrapped_key + nonce + ciphertext

    elif profile == "hpke-x25519-aes256gcm":
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
        return suite.encrypt(message, public_key, info=context)

    elif profile == "hpke-p256-aes256gcm":
        suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
        return suite.encrypt(message, public_key, info=context)

    else:
        raise ValueError(f"Unknown profile: {profile}")


def decrypt(profile: str, private_key: object, envelope: bytes, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported profile")

    try:
        if profile == "rsa2048-oaep":
            if len(envelope) != 256:
                raise DecryptionError("Invalid envelope size for RSA 2048")
            oaep = padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=context,
            )
            return private_key.decrypt(envelope, oaep)

        elif profile == "rsa3072-oaep":
            if len(envelope) != 384:
                raise DecryptionError("Invalid envelope size for RSA 3072")
            oaep = padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=context,
            )
            return private_key.decrypt(envelope, oaep)

        elif profile == "rsa3072-oaep-aes256gcm":
            wrapped_key_len = 384
            nonce_len = 12
            min_len = wrapped_key_len + nonce_len + 16
            if len(envelope) < min_len:
                raise DecryptionError("Envelope too short")

            wrapped_key = envelope[:wrapped_key_len]
            nonce = envelope[wrapped_key_len:wrapped_key_len + nonce_len]
            ciphertext = envelope[wrapped_key_len + nonce_len:]

            oaep = padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=context,
            )
            aes_key = private_key.decrypt(wrapped_key, oaep)
            cipher = AESGCM(aes_key)
            return cipher.decrypt(nonce, ciphertext, context)

        elif profile == "hpke-x25519-aes256gcm":
            suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
            return suite.decrypt(envelope, private_key, info=context)

        elif profile == "hpke-p256-aes256gcm":
            suite = Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
            return suite.decrypt(envelope, private_key, info=context)

        else:
            raise ValueError(f"Unknown profile: {profile}")

    except Exception as e:
        if isinstance(e, DecryptionError):
            raise
        raise DecryptionError("Decryption failed") from e