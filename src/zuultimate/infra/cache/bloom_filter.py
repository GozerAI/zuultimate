"""In-process bloom filter for token deny list pre-screening."""

import hashlib
import time


class DenyListBloomFilter:
    """
    In-process bloom filter for token deny list pre-screening.
    Rebuilt from Redis deny list periodically.

    False positive rate: ~0.1% at 3M expected items with 50M bits and 7 hashes.
    False negative rate: 0% (bloom filters never produce false negatives).

    Usage:
      if bloom.might_be_denied(jti):
          # Maybe denied -- confirm with Redis
          confirmed = await redis.check_deny_list(jti)
      else:
          # Definitely NOT denied -- skip Redis check entirely
          pass
    """

    DEFAULT_SIZE = 50_000_000  # 50M bits ~ 6.25 MB
    DEFAULT_HASH_COUNT = 7  # optimal for 0.1% FPR at ~3M items

    def __init__(
        self,
        size: int = DEFAULT_SIZE,
        hash_count: int = DEFAULT_HASH_COUNT,
    ):
        self._size = size
        self._hash_count = hash_count
        self._bits = bytearray(size // 8 + 1)
        self.last_rebuilt: float = 0.0
        self.item_count: int = 0

    def _get_bit_positions(self, item: str) -> list[int]:
        """Generate hash_count bit positions using double-hashing technique."""
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        positions = []
        for i in range(self._hash_count):
            pos = (h1 + i * h2) % self._size
            positions.append(pos)
        return positions

    def add(self, item: str) -> None:
        """Add item to bloom filter."""
        for pos in self._get_bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self._bits[byte_idx] |= 1 << bit_idx
        self.item_count += 1

    def might_contain(self, item: str) -> bool:
        """Check if item might be in the filter. False = definitely not present."""
        for pos in self._get_bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def clear(self) -> None:
        """Reset the filter."""
        self._bits = bytearray(self._size // 8 + 1)
        self.item_count = 0

    async def rebuild_from_redis(self, redis) -> None:
        """
        Rebuild filter from Redis deny list keys.
        Called periodically by background task.
        """
        new_filter = DenyListBloomFilter(self._size, self._hash_count)
        # Scan Redis for deny list keys and populate
        # Pattern: jti:deny:* (existing pattern from posture revocation)
        try:
            raw_redis = getattr(redis, "_redis", None)
            if raw_redis is None:
                return
            cursor = 0
            while True:
                cursor, keys = await raw_redis.scan(
                    cursor, match="jti:deny:*", count=1000
                )
                for key in keys:
                    jti = (
                        key.decode().split(":", 2)[-1]
                        if isinstance(key, bytes)
                        else key.split(":", 2)[-1]
                    )
                    new_filter.add(jti)
                if cursor == 0:
                    break
        except Exception:
            return  # Keep existing filter on error

        # Atomic swap
        self._bits = new_filter._bits
        self.item_count = new_filter.item_count
        self.last_rebuilt = time.time()
