"""JAM's continuous XOR stream, independently expressed from PANAMA's equations.

The state and buffer transformations follow PANAMA as specified in CRYPTREC's
MULTI-S01 specification, section 2.3.2. JAM uses the same little-endian 256-bit
value for PANAMA's key and diversification input.
"""

from __future__ import annotations

import struct


_WORD_MASK = (1 << 32) - 1


def _rotate_left(word: int, distance: int) -> int:
    return ((word << distance) | (word >> (32 - distance))) & _WORD_MASK


class Jam:
    """A continuous XOR stream using a 256-bit JAM session key."""

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)) or len(key) != 32:
            raise ValueError("JAM cipher key must be exactly 32 bytes")
        self._state = [0] * 17
        self._stages = [[0] * 8 for _ in range(32)]
        self._pending = b""
        self._offset = 0
        words = struct.unpack("<8I", key)
        self._advance(words)
        self._advance(words)
        for _ in range(32):
            self._advance()

    def _advance(self, input_words=None) -> None:
        """Apply the four state layers and the buffer recurrence in parallel."""
        before = self._state
        stages = self._stages
        injected = stages[4] if input_words is None else input_words
        feedback = before[1:9] if input_words is None else input_words

        nonlinear = [
            (before[i] ^ (before[(i + 1) % 17] | ~before[(i + 2) % 17]))
            & _WORD_MASK
            for i in range(17)
        ]
        dispersed = [
            _rotate_left(nonlinear[(7 * i) % 17], (i * (i + 1) // 2) % 32)
            for i in range(17)
        ]
        after = [
            dispersed[i] ^ dispersed[(i + 1) % 17] ^ dispersed[(i + 4) % 17]
            for i in range(17)
        ]
        after[0] ^= 1
        for i in range(8):
            after[i + 1] ^= injected[i]
            after[i + 9] ^= stages[16][i]

        shifted = [[stages[31][i] ^ feedback[i] for i in range(8)]] + stages[:31]
        shifted[25] = [
            stages[24][i] ^ stages[31][(i + 2) % 8] for i in range(8)
        ]
        self._state = after
        self._stages = shifted

    def _next_block(self) -> bytes:
        block = struct.pack("<8I", *self._state[9:17])
        self._advance()
        return block

    def crypt(self, data: bytes) -> bytes:
        result = bytearray(len(data))
        consumed = 0
        while consumed < len(data):
            if self._offset == len(self._pending):
                self._pending = self._next_block()
                self._offset = 0
            count = min(len(data) - consumed, len(self._pending) - self._offset)
            for i in range(count):
                result[consumed + i] = data[consumed + i] ^ self._pending[self._offset + i]
            consumed += count
            self._offset += count
        return bytes(result)
