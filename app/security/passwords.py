import hashlib
import hmac
import secrets
from typing import Tuple, Union
from pydantic import SecretStr

ITERATIONS = 600_000
KEY_LEN = 32
SALT_BYTES = 16
DERIVED_BYTES = 32

def password_bytes(password: Union[str, SecretStr], registration: bool = False, for_registration: bool = False) -> bytes:
    is_reg = registration or for_registration

    if isinstance(password, SecretStr):
        pwd_str = password.get_secret_value()
    elif isinstance(password, str):
        pwd_str = password
    else:
        raise ValueError("Password must be a string")
    
    if "\x00" in pwd_str:
        raise ValueError("Null bytes not allowed in password")

    try:
        encoded = pwd_str.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError("Invalid unicode password") from e

    if is_reg:
        char_len = len(pwd_str)
        if char_len < 15 or char_len > 128:
            raise ValueError("Password character length must be between 15 and 128")
        if len(encoded) > 512:
            raise ValueError("Password UTF-8 bytes must not exceed 512")

    return encoded

def make_password_record(password: Union[str, SecretStr]) -> Tuple[str, str]:
    pwd_bytes = password_bytes(password, registration=True)
    
    salt_raw = secrets.token_bytes(SALT_BYTES)
    salt_hex = salt_raw.hex()

    derived = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_raw, ITERATIONS, dklen=KEY_LEN)
    password_record = f"pbkdf2_sha256${ITERATIONS}${derived.hex()}"
    
    return password_record, salt_hex

def verify_password(password_candidate: Union[str, SecretStr], password_record: str, salt_hex: str) -> bool:
    if isinstance(password_candidate, SecretStr):
        password_candidate = password_candidate.get_secret_value()

    if not isinstance(password_candidate, str) or not isinstance(password_record, str) or not isinstance(salt_hex, str):
        return False

    parts = password_record.split("$")
    if len(parts) != 3:
        return False

    algo, iter_str, hash_hex = parts
    if algo != "pbkdf2_sha256":
        return False

    if any(c.isupper() for c in hash_hex) or any(c.isupper() for c in salt_hex):
        return False

    try:
        iterations = int(iter_str)
    except ValueError:
        return False

    if iterations != ITERATIONS:
        return False

    if len(hash_hex) != 64 or len(salt_hex) != 32:
        return False

    try:
        expected_hash = bytes.fromhex(hash_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError:
        return False

    try:
        pwd_bytes = password_bytes(password_candidate, registration=False)
    except ValueError:
        return False

    candidate_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, iterations, dklen=KEY_LEN)
    return hmac.compare_digest(candidate_hash, expected_hash)