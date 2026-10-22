"""Build-24919 player voice preferences (20802 / 22200..22202)."""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
import struct

from .protocol import ProtocolError


@dataclass(frozen=True)
class VoicePreferences:
    playback_volume: float = 1
    microphone_volume: float = 1
    other_volume: float = 1
    audio_flags: int = 0
    channel_flags: int = 7
    chat_filter: bool = False
    player_flags: bytes = bytes(4)

    def encode(self):
        # JAM packs the six adjacent bools through nested structures. Bits
        # 2/3/4 enable native Team, Group and push-to-talk preferences.
        flags = self.audio_flags | self.channel_flags << 2 | self.chat_filter << 5
        return struct.pack('<fffB', self.playback_volume, self.microphone_volume,
                           self.other_volume, flags) + self.player_flags

    def apply(self, offset, body):
        """Decode one complete update while preserving the other preferences."""
        if not isinstance(body, bytes):
            raise ProtocolError('player voice preferences must be bytes')
        if offset == 0:
            if len(body) < 17:
                raise ProtocolError('truncated player audio preferences')
            volumes = struct.unpack_from('<fff', body)
            if not all(math.isfinite(value) for value in volumes):
                raise ProtocolError('voice volumes must be finite')
            audio = _bits(body[12], 3)
            count = struct.unpack_from('<I', body, 13)[0]
            if count > 128:
                raise ProtocolError('too many player audio preferences')
            if len(body) != 17 + count * 17:
                raise ProtocolError('invalid player audio preferences length')
            for position in range(17, len(body), 17):
                _bits(body[position], 7)
            return replace(self, playback_volume=volumes[0], microphone_volume=volumes[1],
                           other_volume=volumes[2], audio_flags=audio, player_flags=body[13:])
        if offset not in (1, 2):
            raise ValueError('unknown player voice preference update')
        if len(body) != 1:
            raise ProtocolError('invalid player voice preference length')
        if offset == 1:
            return replace(self, channel_flags=_bits(body[0], 7))
        return replace(self, chat_filter=bool(_bits(body[0], 1)))


def _bits(value, allowed):
    if value & ~allowed:
        raise ProtocolError('invalid packed player preference flags')
    return value
