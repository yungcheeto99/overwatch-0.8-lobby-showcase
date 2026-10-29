"""Read the supported owned client's process clock for pending-party timers."""
from __future__ import annotations

import math
from pathlib import Path
import struct

from .client import LaunchResult, _Windows, validate_owned_client

_CLOCK_RVA = 0x179F118
_MAX_CLOCK_MS = (1 << 63) - 1


def decode_clock(value):
    if not isinstance(value, bytes) or len(value) != 8:
        return None
    seconds = struct.unpack("<d", value)[0]
    milliseconds = seconds * 1000
    if not math.isfinite(milliseconds) or not 0 <= milliseconds <= _MAX_CLOCK_MS:
        return None
    result = int(milliseconds)
    return result if result <= _MAX_CLOCK_MS else None


class NativeLobbyClock:
    """Separate read-only handle; no process suspension or memory writes."""

    def __init__(self, result: LaunchResult, game: Path):
        validate_owned_client(result, game)
        self.result, self.api = result, _Windows()
        self.handle = self.api.open_child(result.process, write=False)
        try:
            self.base, size = self.api.module(self.handle, Path(game).resolve())
            if _CLOCK_RVA + 8 > size:
                raise ValueError("Native lobby clock is outside the verified image")
        except BaseException:
            self.api.close(self.handle)
            self.handle = None
            raise

    def sample(self):
        if not self.handle or self.result.process.poll() is not None:
            return None
        try:
            return decode_clock(self.api.read(self.handle, self.base + _CLOCK_RVA, 8))
        except OSError:
            return None

    def close(self):
        if self.handle:
            self.api.close(self.handle)
            self.handle = None
