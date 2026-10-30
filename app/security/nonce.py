import threading


class NonceSequence:
    """Синхронізований монотонний лічильник nonce."""

    def __init__(self, limit: int = 1000):
        self.limit = limit
        self._counter = 0
        self._lock = threading.Lock()

    def next(self) -> bytes:
        with self._lock:
            if self._counter >= self.limit:
                raise RuntimeError("Nonce sequence limit reached")
            self._counter += 1
            # Форматуємо лічильник як 12-байтне значення у big-endian
            return self._counter.to_bytes(12, byteorder="big")