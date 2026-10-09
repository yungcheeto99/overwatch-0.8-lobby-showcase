"""Bounded JAM framing, signed state and packet observations for the beta.

The first payload bytes select a wire family and its message offset. Each
direction's JAM cipher stays alive across the state, frame headers and payloads.
"""

from collections.abc import Mapping
import hashlib
import hmac
import ipaddress
import struct

HELLO_CLIENT = b"HELLO PRO CLIENT\x00"
HELLO_SERVER = b"HELLO PRO SERVER\x00"
DEFAULT_MAX_FRAME_SIZE = 1024 * 1024
STATE_BLOB_SIZE = 292
KEY_SLOTS = ("mac1", "mac2", "c2s", "s2c")
# Current 1.74 registration flag 8 moves the message offset behind a u32.
# This is deliberately not automatically applied to unknown 0.8 families.
PREFIXED_FAMILIES_174 = frozenset((0xBCD57A46, 0xBDDBF58A))

# Fixed HMAC key for the signed state block.
BLOB_KEY = bytes.fromhex(
    "3586f3628a631b705712405b8acc71d40fd1670cc1b03ea384974a6fb1a76196"
    "b142f0b72310ea8116d00a4c352f09acdbfb50a63ec5153e62e4d67fe09beecc"
)


class ProtocolError(ValueError):
    """A value cannot be represented by the selected protocol hypothesis."""


def _bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProtocolError(f"{name} must be bytes")
    return bytes(value)


def _uint(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << bits):
        raise ProtocolError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def derive_keys(client_nonce: bytes, server_nonce: bytes, key_slots=None) -> dict[str, bytes]:
    """Derive independent proofs and direction keys with HMAC-SHA256.

    Each optional slot is exactly 64 bytes. Unspecified slots use 64 zero bytes
    (equivalent under HMAC to a 32-byte all-zero key). ``mac1``
    and ``s2c`` sign client+server; ``mac2`` and ``c2s`` sign server+client.
    The mapping may override any subset; proof and cipher slots stay separate.
    """
    client_nonce = _bytes(client_nonce, "client_nonce")
    server_nonce = _bytes(server_nonce, "server_nonce")
    if len(client_nonce) != 32 or len(server_nonce) != 32:
        raise ProtocolError("client_nonce and server_nonce must each be exactly 32 bytes")
    if key_slots is None:
        key_slots = {}
    if not isinstance(key_slots, Mapping):
        raise ProtocolError("key_slots must be a mapping of slot names to 64-byte keys")
    if set(key_slots) - set(KEY_SLOTS):
        raise ProtocolError("unknown key slot; expected mac1, mac2, c2s, or s2c")
    result = {}
    for slot in KEY_SLOTS:
        key = _bytes(key_slots.get(slot, bytes(64)), f"key_slots[{slot!r}]")
        if len(key) != 64:
            raise ProtocolError(f"key_slots[{slot!r}] must be exactly 64 bytes")
        message = client_nonce + server_nonce if slot in ("mac1", "s2c") else server_nonce + client_nonce
        result[slot] = hmac.new(key, message, hashlib.sha256).digest()
    return result


def _state_parts(seq: int, host: str, port: int, beta: bool) -> tuple[bytearray, bytes]:
    """Encode the documented state fields and the independent 36-byte trailer."""
    seq = _uint(seq, 32, "seq")
    port = _uint(port, 16, "port")
    try:
        address = ipaddress.IPv4Address(host).packed
    except (ipaddress.AddressValueError, ValueError, TypeError) as exc:
        raise ProtocolError("state blob host must be an IPv4 address") from exc

    core = bytearray(256) if beta else bytearray(range(256))
    core[0] = 1 if beta else 2
    core[1:5] = address
    struct.pack_into("<H", core, 5, port)
    authenticated_fields = core[:176] + core[208:]
    core[176:208] = hmac.new(BLOB_KEY, authenticated_fields, hashlib.sha256).digest()

    trailer = bytearray(36)
    for position in (0, 16):
        struct.pack_into("<I", trailer, position, seq)
    struct.pack_into("<H", trailer, 5, 5)
    trailer[7] = 1
    struct.pack_into("<H", trailer, 8, 0xBEEF)
    struct.pack_into("<H", trailer, 21, 13)
    trailer[23] = 1
    struct.pack_into("<H", trailer, 26, port)
    trailer[28:32] = address
    struct.pack_into("<I", trailer, 32, 1)
    return core, bytes(trailer)


def build_state_blob(seq: int, host: str, port: int) -> bytes:
    """Build the shared signed state and structured 36-byte peer/channel trailer."""
    core, trailer = _state_parts(seq, host, port, beta=False)
    return bytes(core) + trailer


def build_beta_state_blob(seq: int, host: str, port: int, private_key) -> bytes:
    """Beta's RSA-encoded state with type-1 IPv4 and the shared HMAC.

    The first 256 bytes are a raw, little-endian RSA signature. The client
    recovers that block before checking the HMAC and its remote endpoint.
    The final 36 bytes remain outside RSA, inside the continuous JAM stream.
    """
    from .local_rsa import sign_state_core

    core, trailer = _state_parts(seq, host, port, beta=True)
    return sign_state_core(bytes(core), private_key) + trailer


def _frame_limit(max_frame_size: int) -> int:
    _uint(max_frame_size, 24, "max_frame_size")
    if max_frame_size < 2:
        raise ProtocolError("max_frame_size must be at least 2")
    return max_frame_size


def pack_frame(payload: bytes, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
    """Prefix a payload with its three-byte big-endian length, before encryption."""
    payload = _bytes(payload, "payload")
    maximum = _frame_limit(max_frame_size)
    if not 2 <= len(payload) <= maximum:
        raise ProtocolError(f"frame payload size must be between 2 and {maximum} bytes")
    return len(payload).to_bytes(3, "big") + payload


class FrameDecoder:
    """Split plaintext into complete frames, preserving an incomplete tail.

    Call ``cipher.crypt(received_bytes)`` before ``feed``. Invalid lengths fail
    as soon as their full three-byte header arrives; the decoder then remains
    failed because guessing a new stream boundary would corrupt observations.
    """

    def __init__(self, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE):
        self.max_frame_size = _frame_limit(max_frame_size)
        self._pending = bytearray()
        self._failed = False

    @property
    def pending(self) -> bytes:
        return bytes(self._pending)

    def feed(self, plaintext: bytes) -> list[bytes]:
        plaintext = _bytes(plaintext, "plaintext")
        if self._failed:
            raise ProtocolError("frame decoder has failed; start a new connection")
        self._pending.extend(plaintext)
        frames = []
        position = 0
        while len(self._pending) - position >= 3:
            size = int.from_bytes(self._pending[position:position + 3], "big")
            if not 2 <= size <= self.max_frame_size:
                self._failed = True
                raise ProtocolError(f"frame payload size {size} is outside 2..{self.max_frame_size}")
            end = position + 3 + size
            if len(self._pending) < end:
                break
            frames.append(bytes(self._pending[position + 3:end]))
            position = end
        if position:
            del self._pending[:position]
        return frames


def parse_announcement(payload: bytes) -> list[int]:
    """Read an exact [00 00][u32 count][u32 family CRCs] announcement.

    Family index 1 is the first entry; index 0 is control. Reject trailing or
    truncated data, and counts that cannot fit the one-byte wire index.
    """
    payload = _bytes(payload, "payload")
    if len(payload) < 2 or payload[:2] != b"\x00\x00":
        raise ProtocolError("payload is not a 0000 control announcement")
    if len(payload) < 6:
        raise ProtocolError("announcement is missing its u32 count")
    count = struct.unpack_from("<I", payload, 2)[0]
    if count > 255:
        raise ProtocolError("announcement has more than 255 wire families")
    expected_size = 6 + 4 * count
    if len(payload) != expected_size:
        raise ProtocolError(f"announcement size is {len(payload)}; count {count} requires {expected_size}")
    return list(struct.unpack_from(f"<{count}I", payload, 6))


def describe_payload(payload: bytes, *, wire_families=None) -> dict:
    """Return JSON-friendly observations without claiming an unknown 0.8 schema.

    ``msgid_hex`` is the two observed header bytes, not an absolute schema ID.
    A ``counter_candidate`` means only that bytes 2..5 can be read as a u32.
    Optional wire->CRC mapping enables extra 1.74 prefix-layout observations;
    the raw first-byte-pair description remains available for comparison.
    """
    payload = _bytes(payload, "payload")
    result = {"length": len(payload), "wire_index": None, "message_offset": None, "msgid_hex": None}
    if len(payload) < 2:
        result["error"] = "payload is shorter than the two-byte header"
        return result
    wire, offset = payload[:2]
    result.update(wire_index=wire, message_offset=offset, msgid_hex=payload[:2].hex())
    if wire == 0 and offset == 0:
        try:
            families = parse_announcement(payload)
            result["announcement_families"] = families
            result["announcement_families_hex"] = [f"{crc:08x}" for crc in families]
            result["announcement_count"] = len(families)
        except ProtocolError as error:
            result["announcement_error"] = str(error)
    elif wire != 0 and len(payload) >= 6:
        result["counter_candidate"] = struct.unpack_from("<I", payload, 2)[0]
    if wire_families is not None and wire in wire_families:
        crc = wire_families[wire]
        result["family_crc_hex"] = f"{crc:08x}"
        if crc in PREFIXED_FAMILIES_174:
            if len(payload) >= 6:
                result["prefix_u32_candidate"] = struct.unpack_from("<I", payload, 1)[0]
                result["prefixed_message_offset_candidate"] = payload[5]
            else:
                result["prefix_layout_error"] = "1.74 prefixed family requires a six-byte header"
    return result
