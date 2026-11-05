import hashlib
from typing import Callable, Any, Literal, Dict, NamedTuple, List

PAYLOAD_SIZES = (64, 1024, 65536, 1048576)

CHECK_NAMES = (
    "known-abc",
    "known-empty",
    "unicode-utf8",
    "determinism",
    "digest-length",
    "stream-equivalence",
)

AlgorithmID = Literal["sha256", "sha512", "sha3-256", "blake2b-256", "blake2s-256", "md5", "sha1"]
Mode = Literal["whole", "chunked"]

class ProfileMetadata(NamedTuple):
    algorithm: str
    digest_bytes: int
    available: bool = True
    reason: str = None

PROFILES: Dict[str, ProfileMetadata] = {
    "sha256": ProfileMetadata("sha256", 32),
    "sha512": ProfileMetadata("sha512", 64),
    "sha3-256": ProfileMetadata("sha3-256", 32),
    "blake2b-256": ProfileMetadata("blake2b-256", 32),
    "blake2s-256": ProfileMetadata("blake2s-256", 32),
    "md5": ProfileMetadata("md5", 16),
    "sha1": ProfileMetadata("sha1", 20),
}

HASH_PROFILES = PROFILES

def get_hash_constructor(profile_id: str) -> Callable[..., Any]:
    if profile_id == "sha256":
        return lambda d=b"": hashlib.sha256(d)
    elif profile_id == "sha512":
        return lambda d=b"": hashlib.sha512(d)
    elif profile_id == "sha3-256":
        return lambda d=b"": hashlib.sha3_256(d)
    elif profile_id == "blake2b-256":
        return lambda d=b"": hashlib.blake2b(d, digest_size=32)
    elif profile_id == "blake2s-256":
        return lambda d=b"": hashlib.blake2s(d, digest_size=32)
    elif profile_id == "md5":
        return lambda d=b"": hashlib.md5(d, usedforsecurity=False)
    elif profile_id == "sha1":
        return lambda d=b"": hashlib.sha1(d, usedforsecurity=False)
    else:
        raise ValueError(f"Unknown hash profile: {profile_id}")

def make_hasher(profile_id: str) -> Any:
    constructor = get_hash_constructor(profile_id)
    return constructor()

def probe_profiles() -> List[Dict[str, Any]]:
    results = []
    # Перевіряємо обов'язкові сучасні алгоритми
    required_algos = {"sha256", "sha512", "sha3-256", "blake2b-256", "blake2s-256"}
    for p in PROFILES:
        try:
            make_hasher(p)
            results.append({
                "algorithm": p,
                "available": True,
                "implementation": str(get_hash_constructor(p)().__class__),
                "reason": None
            })
        except Exception as e:
            if p in required_algos:
                raise RuntimeError(f"Required profile {p} unavailable: {e}")
            results.append({
                "algorithm": p,
                "available": False,
                "implementation": None,
                "reason": "not_available_in_environment"
            })
    return results

def synthetic_payload(size: int) -> bytes:
    base = b"synthetic export"
    repeats = (size // len(base)) + 1
    return (base * repeats)[:size]