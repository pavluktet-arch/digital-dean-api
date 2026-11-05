from typing import Callable
from app.security.hashing.profiles import get_hash_constructor

def prepare_operation(profile_id: str, data: bytes, mode: str = "whole", chunk_size: int = 16384) -> Callable[[], bytes]:
    constructor = get_hash_constructor(profile_id)
    if mode == "whole":
        def op() -> bytes:
            state = constructor()
            state.update(data)
            return state.digest()
        return op
    elif mode == "chunked":
        parts = tuple(data[i:i + chunk_size] for i in range(0, len(data), chunk_size))
        def op() -> bytes:
            state = constructor()
            for part in parts:
                state.update(part)
            return state.digest()
        return op
    else:
        raise ValueError(f"Unknown mode: {mode}")

def hash_bytes(profile_id: str, data: bytes, mode: str = "whole") -> bytes:
    op = prepare_operation(profile_id, data, mode)
    return op()

def hamming_bits(left: bytes, right: bytes) -> int:
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("Arguments must be bytes")
    if len(left) != len(right) or len(left) == 0:
        raise ValueError("Bytes must be non-empty and equal in length")
    
    # Використовуємо bin(x ^ y).count("1") замість int.bit_count() для сумісності з Python 3.9
    return sum(bin(x ^ y).count("1") for x, y in zip(left, right))