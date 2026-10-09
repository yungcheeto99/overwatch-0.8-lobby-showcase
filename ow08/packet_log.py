"""Bounded, beta-specific packet descriptions for human-readable consoles.

Wire schemas are from build 24919's JamMessageInfo tables and verified
receivers. Generic field names retain
unknown semantics; this module never treats arbitrary bytes as a counter or
applies retail routing prefixes. It observes packets without changing them.
"""
from __future__ import annotations

import json
import math
import os
import re
import struct
import sys

from .protocol import ProtocolError, parse_announcement


MAX_ITEMS = 4096
DISPLAY_ITEMS = 16
MAX_STRING_BYTES = 4096
CONSOLE_ITEMS = 5
CONSOLE_STRING = 160
CONSOLE_DEPTH = 6


def console_color(stream=None):
    """Enable optional ANSI cues on terminals, respecting NO_COLOR and TERM."""
    stream = sys.stdout if stream is None else stream
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
        return _enable_windows_vt(stream) if os.name == "nt" else True
    except (AttributeError, OSError, ValueError):
        return False


def _enable_windows_vt(stream):
    """Enable ANSI interpretation only on a verified Windows console handle."""
    try:
        import ctypes
        from ctypes import wintypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetConsoleMode.restype = wintypes.BOOL
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetConsoleMode.restype = wintypes.BOOL
        mode = wintypes.DWORD()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(mode.value & 4 or kernel.SetConsoleMode(handle, mode.value | 4))
    except (AttributeError, ImportError, OSError, ValueError):
        return False


def colorize(value, kind="function", *, color=False):
    """Color a trusted label only; packet/user values are escaped separately."""
    codes = {"in": 36, "out": 32, "id": 34, "function": 35,
             "error": 31, "warning": 33, "dim": 90}
    code = codes.get(kind)
    return f"\x1b[{code}m{value}\x1b[0m" if color and code else str(value)


def console_data(data):
    """Return bounded console data without modifying structured capture data.

    Raw hex previews, including nested protobuf previews, are omitted. Actual
    bytes become length summaries. Decoded text and unknown-purpose labels stay
    visible; identifiers use compact little-endian words rather than raw bytes.
    """
    def clean(value, key="", depth=0):
        if isinstance(value, (bytes, bytearray, memoryview)):
            return {"length": len(value)}
        if depth >= CONSOLE_DEPTH and isinstance(value, (dict, list, tuple)):
            return {"console_limit": "nested data", "count": len(value)}
        if isinstance(value, dict):
            result = {}
            entries = list(value.items())
            for name, child in entries:
                label = str(name)
                lower = label.lower()
                if ((lower == "hex" or lower.endswith("_hex"))
                        and lower not in ("family_crc_hex", "guid_hex", "id_hex")):
                    continue
                if lower in ("omitted_raw_bytes", "omitted_bytes"):
                    continue
                if lower == "omitted_items" and not child:
                    continue
                if len(result) >= 12:
                    result["console_limit"] = "additional fields omitted"
                    break
                if lower == "items" and isinstance(child, (list, tuple)):
                    result[label] = [clean(item, key, depth + 1) for item in child[:CONSOLE_ITEMS]]
                    omitted = max(0, len(child) - CONSOLE_ITEMS) + value.get("omitted_items", 0)
                    if omitted:
                        result["omitted_items"] = omitted
                elif lower != "omitted_items" or "omitted_items" not in result:
                    result[label] = clean(child, label, depth + 1)
            return result
        if isinstance(value, (list, tuple)):
            result = [clean(item, key, depth + 1) for item in value[:CONSOLE_ITEMS]]
            if len(value) > CONSOLE_ITEMS:
                result.append({"omitted_items": len(value) - CONSOLE_ITEMS})
            return result
        if isinstance(value, str):
            identifier = (key in ("id", "id_hex") or key.endswith("_id") or key.startswith("id16")
                          or re.match(r"id\d?_purpose_unknown$", key))
            if identifier and re.fullmatch(r"[0-9a-fA-F]{32}", value):
                low, high = struct.unpack("<QQ", bytes.fromhex(value))
                return "0" if not low and not high else f"{low:X}:{high:X}"
            if len(value) > CONSOLE_STRING:
                return value[:CONSOLE_STRING] + f"... (+{len(value) - CONSOLE_STRING} chars)"
            return value
        if isinstance(value, int) and not isinstance(value, bool) and "guid" in key:
            return f"0x{value:016X}"
        return value

    return clean(data)


class InspectionLimit(ValueError):
    """A potentially valid body exceeds the console decoder's work budget."""


class Reader:
    def __init__(self, data):
        self.data = data
        self.position = 0
        self.bool_byte = 0
        self.bool_bit = 8

    def take(self, size):
        self.bool_bit = 8
        end = self.position + size
        if end > len(self.data):
            raise ProtocolError(f"truncated body at byte {self.position}: need {size} bytes")
        value = self.data[self.position:end]
        self.position = end
        return value

    def boolean(self):
        if self.bool_bit == 8:
            self.bool_byte = self.take(1)[0]
            self.bool_bit = 0
        value = bool(self.bool_byte & (1 << self.bool_bit))
        self.bool_bit += 1
        return value

    def string(self):
        self.bool_bit = 8
        end = self.data.find(b"\0", self.position)
        if end < 0:
            raise ProtocolError(f"unterminated UTF-8 string at byte {self.position}")
        if end - self.position > MAX_STRING_BYTES:
            raise InspectionLimit("string exceeds console inspection limit")
        try:
            value = self.data[self.position:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError(f"invalid UTF-8 string at byte {self.position}") from error
        self.position = end + 1
        return value

    def value(self, schema):
        if schema == "bool":
            return self.boolean()
        if schema == "string":
            return self.string()
        if schema == "id16":
            return self.take(16).hex()
        if schema in ("blob", "bytes"):
            size = self.value("u32")
            value = self.take(size)
            return {"length": size, "hex": value[:64].hex(), "omitted_bytes": max(0, size - 64)}
        if isinstance(schema, str):
            fmt = {"u8": "B", "u32": "I", "i32": "i", "u64": "Q", "f32": "f"}[schema]
            value = struct.unpack("<" + fmt, self.take(struct.calcsize(fmt)))[0]
            # JSON must remain valid for arbitrary packet bytes.
            return value if not isinstance(value, float) or math.isfinite(value) else str(value)
        if isinstance(schema, tuple) and schema[0] == "array":
            count = self.value("u32")
            if count > MAX_ITEMS:
                raise InspectionLimit(f"array count {count} exceeds console inspection limit")
            items = []
            for index in range(count):
                value = self.value(schema[1])
                if index < DISPLAY_ITEMS:
                    items.append(value)
            return {"count": count, "items": items, "omitted_items": max(0, count - DISPLAY_ITEMS)}
        return {name: self.value(kind) for name, kind in schema}

    def finish(self):
        if self.position != len(self.data):
            raise ProtocolError(f"unexpected {len(self.data) - self.position} trailing body bytes")


def array(schema):
    return ("array", schema)


CHANNEL = [("type", "i32"), ("id", "id16")]
MEMBER = [("name", "string"), ("account_id", "id16")]
JOINED = [("flags_purpose_unknown", [("bit0", "bool"), ("bit1", "bool"), ("bit2", "bool")]),
          ("channel", CHANNEL)]
PARTY_MEMBER = [("name", "string"), ("leader", "bool"), ("status", "u8"),
                ("portrait_guid", "u64"), ("u64_purpose_unknown", "u64"),
                ("account_id", "id16"), ("id16_purpose_unknown", "id16")]
PRESENCE_FIELD = [("key_protobuf", "blob"), ("value_protobuf", "blob"), ("operation", "u32")]
PRESENCE = [("fields", array(PRESENCE_FIELD)), ("account_id", "id16"), ("parent_id", "id16")]
FRIEND = [("u32_purpose_unknown", "u32"), ("metadata_bits", "u64"), ("account_id", "id16")]
# Complex optional profile-state records are descriptor-verified, although
# their gameplay/statistics purposes remain unknown. Menu profiles use none.
PROFILE_METADATA = [("u32_0_purpose_unknown", "u32"), ("u32_1_purpose_unknown", "u32"),
                    ("u64_purpose_unknown", "u64"), ("id_purpose_unknown", "id16")]
PROFILE_VALUES = ([("u8_purpose_unknown", "u8")]
                  + [(f"i32_{i}_purpose_unknown", "i32") for i in range(3)]
                  + [(f"f32_{i}_purpose_unknown", "f32") for i in range(2)])
PROFILE_ENTRY = ([("flags_purpose_unknown", [(f"bit{i}", "bool") for i in range(3)]),
                  ("u8_0_purpose_unknown", "u8"), ("u8_1_purpose_unknown", "u8"),
                  ("u32_0_purpose_unknown", "u32")]
                 + [(f"i32_{i}_purpose_unknown", "i32") for i in range(4)]
                 + [(f"values_{i}_purpose_unknown", array("u32")) for i in range(2)]
                 + [("u32_1_purpose_unknown", "u32"), ("u32_2_purpose_unknown", "u32"),
                    ("id_purpose_unknown", "id16")])
PROFILE_STATE = [("u32_purpose_unknown", "u32"), ("i32_purpose_unknown", "i32"),
                 ("values_purpose_unknown", array(PROFILE_VALUES)),
                 ("metadata_purpose_unknown", PROFILE_METADATA),
                 ("metadata0_purpose_unknown", array(PROFILE_METADATA)),
                 ("metadata1_purpose_unknown", array(PROFILE_METADATA)),
                 ("entries_purpose_unknown", array(PROFILE_ENTRY))]
FRIEND_PROFILE = [("name", "string"), ("u32_purpose_unknown", "u32"), ("portrait_guid", "u64"),
                  ("account_id", "id16"), ("u32_0_purpose_unknown", "u32"),
                  ("u32_1_purpose_unknown", "u32"), ("i32_purpose_unknown", "i32"),
                  ("ids0_purpose_unknown", array("id16")), ("id_purpose_unknown", "id16"),
                  ("ids1_purpose_unknown", array("id16")),
                  ("entries_purpose_unknown", array(PROFILE_STATE))]
REQUEST = [("inviter_battle_tag", "string"), ("string1_purpose_unknown", "string"),
           ("string2_purpose_unknown", "string"), ("u32_purpose_unknown", "u32"),
           ("u64_purpose_unknown", "u64"), ("inviter_account_id", "id16"),
           ("id1_purpose_unknown", "id16")]
SETTINGS_ENTRY = [("bool0_purpose_unknown", "bool"), ("bool1_purpose_unknown", "bool"),
                  ("bool2_purpose_unknown", "bool"), ("u64_0_purpose_unknown", "u64"),
                  ("u64_1_purpose_unknown", "u64")]
PROGRESS_ENTRY = [("bool_purpose_unknown", "bool"), ("i32_purpose_unknown", "i32"),
                  ("u64_0_purpose_unknown", "u64"), ("u64_1_purpose_unknown", "u64")]
HERO_RECORD = ([("status_purpose_unknown", "u8"), ("hero_level", "u32"),
                ("hero_guid", "u64")]
               # Slot 3 is the 0AE base skin wrapper, not a raw 0A5 color theme.
               + [(f"u64_{i}_purpose_unknown", "u64") if i != 3
                  else ("classic_skin_guid", "u64") for i in range(1, 12)]
               # CE8D20 resolves a base skin's theme through these context pairs.
               + [("skin_color_contexts", array([("base_skin_guid", "u64"), ("color_selector_guid", "u64")])),
                  ("entries_purpose_unknown", array(PROGRESS_ENTRY))])
UNLOCK_DIAGNOSTIC = [("unlock_name", "string"), ("unlock_guid", "u64")]
HERO_LEVEL_UPDATE = [("hero_level", "u32"), ("u32_purpose_unknown", "u32"),
                     ("hero_guid", "u64"), ("u64_0_purpose_unknown", "u64"),
                     ("u64_1_purpose_unknown", "u64"), ("unlock_guids", array("u64")),
                     ("entries_purpose_unknown", array([
                         ("u32_purpose_unknown", "u32"),
                         ("u64_0_purpose_unknown", "u64"),
                         ("u64_1_purpose_unknown", "u64"),
                         ("u64_2_purpose_unknown", "u64")]))]


# CRC -> (family name, minimum absolute message ID, maximum offset).
FAMILIES = {
    0x4E958DAF: ("ClientInLobbyConnect", 20500, 5),
    0xD7D457DD: ("ClientOutLobbyConnect", 21800, 8),
    0xDBE61F10: ("ClientInLobbyChat", 20400, 7),
    0x11757702: ("ClientOutLobbyChat", 21700, 6),
    0x912CEA67: ("ClientInLobbyPlayer", 20800, 5),
    0xB7C5277C: ("ClientOutLobbyPlayer", 22200, 10),
    0xC988E4B3: ("ClientInLobbyParty", 20700, 7),
    0x3BF03C3B: ("ClientOutLobbyParty", 22100, 9),
    0x585B3816: ("ClientInLobbyFriends", 27100, 17),
    0x027ADB37: ("ClientOutLobbyFriends", 27000, 8),
    0x8A89BC90: ("ClientInLobbyProfiles", 31800, 4),
    0xBD212AB1: ("ClientInLobbyPlayerProgression", 24300, 4),
    0xC345520E: ("ClientOutLobbyPlayerProgression", 24200, 2),
    0xE79948F2: ("ClientInLobbyFreeAssets", 30500, 0),
    0x70519A68: ("ClientInLobbyHeroProgression", 24900, 8),
    0x74C43F11: ("ClientInLobbyCustomGame", 23300, 12),
    0x0AF5E1B5: ("ClientOutLobbyCustomGame", 24000, 18),
    0xECB33337: ("ClientOutLobbyMatchmaking", 22000, 10),
}


# (CRC, offset) -> (observed function or explicit unknown purpose, body schema).
MESSAGES = {}


def register(crc, offset, function, schema):
    MESSAGES[crc, offset] = function, schema


register(0x4E958DAF, 0, "connect identity", [("account_id", "id16"), ("name", "string")])
register(0x4E958DAF, 1, "connect completion", [])
register(0x4E958DAF, 2, "disconnect control", [("disconnect", "bool")])
register(0x4E958DAF, 3, "CASC content keys", [("key_names", array("u64")), ("key_bytes", "bytes")])
register(0x4E958DAF, 4, "content pack lists", [(f"packs_{i}_purpose_unknown", array("u64")) for i in range(4)])
register(0xD7D457DD, 0, "connect login request", [("string_purpose_unknown", "string"),
         ("id_purpose_unknown", "id16"), ("i32_purpose_unknown", "i32"),
         ("client_fields_purpose_unknown", [("string0", "string"), ("string1", "string"),
             ("bytes", "bytes"), ("u32_0", "u32"), ("u32_1", "u32"),
             ("u32_2", "u32"), ("id16", "id16")])])
for offset in (1, 3):
    register(0xD7D457DD, offset, "purpose unknown", [])
register(0xD7D457DD, 2, "purpose unknown", [("flag", "bool")])
for offset in (4, 5, 7, 8):
    register(0xD7D457DD, offset, "purpose unknown", [("string", "string")])
register(0xD7D457DD, 6, "purpose unknown", [("u64", "u64"), ("string", "string")])

register(0x11757702, 0, "send chat", [("channel", CHANNEL), ("text", "string")])
register(0x11757702, 1, "request channel members", [("channel", CHANNEL)])
register(0x11757702, 2, "join built-in channel", [("channel_type", "u8")])
register(0x11757702, 3, "leave channel", [("channel", CHANNEL)])
register(0xDBE61F10, 0, "chat or system text", [("channel", CHANNEL), ("sender", MEMBER), ("text", "string")])
register(0xDBE61F10, 1, "channel member list", [("channel", CHANNEL), ("members", array(MEMBER))])
register(0xDBE61F10, 2, "joined channel", JOINED)
register(0xDBE61F10, 3, "initial channel snapshot", [("channels", array(JOINED))])
register(0xDBE61F10, 6, "left channel", [("channel", CHANNEL)])

# C7D180 forwards the string list to the native print queue (7E5C90).
register(0x912CEA67, 0, "native console output", [("strings", array("string"))])
register(0x912CEA67, 1, "own player state", [("account_id", "id16"), ("name", "string"),
         ("id0_purpose_unknown", "id16"), ("u64_purpose_unknown", "u64"),
         ("id1_purpose_unknown", "id16"), ("entries_purpose_unknown", array([
             ("u32", "u32"), ("u64_0", "u64"), ("u64_1", "u64")]))])
for crc, flags in ((0x912CEA67, 6), (0xB7C5277C, 2)):
    register(crc, 2 if crc == 0x912CEA67 else 0, "player settings", [
        ("float0_purpose_unknown", "f32"), ("float1_purpose_unknown", "f32"),
        ("float2_purpose_unknown", "f32"), ("flags_purpose_unknown", [(f"bit{i}", "bool") for i in range(flags)]),
        ("entries_purpose_unknown", array(SETTINGS_ENTRY))])
register(0x912CEA67, 3, "localized error enum", [("error_enum", "u8")])
register(0x912CEA67, 4, "purpose unknown", [("flag", "bool"), ("u64_0", "u64"), ("u64_1", "u64")])
register(0xC988E4B3, 0, "party member state", [("party_id", "id16"), ("members", array(PARTY_MEMBER))])
register(0xC988E4B3, 5, "party debug state (does not update membership)",
         [("party_id", "id16"), ("members", array(PARTY_MEMBER))])
register(0xC988E4B3, 1, "party member suggestion", [("suggesting_account_id", "id16"),
         ("suggesting_name", "string"), ("suggested_account_id", "id16"), ("suggested_name", "string")])
register(0xC988E4B3, 2, "incoming party invitation", [("party_id", "id16"),
         ("inviter_account_id", "id16"), ("inviter_battle_tag", "string")])
register(0xC988E4B3, 3, "clear party invitation", [("party_id", "id16")])
register(0x3BF03C3B, 1, "party invitation request", [("target_account_id", "id16"),
         ("request_to_join", "bool")])
for offset, action in ((2, "remove party member"), (3, "promote party leader")):
    register(0x3BF03C3B, offset, action, [("target_account_id", "id16")])
register(0x3BF03C3B, 4, "leave party", [])
for offset, action in ((5, "accept party invitation"), (6, "decline party invitation")):
    register(0x3BF03C3B, offset, action, [("party_id", "id16")])

register(0x585B3816, 0, "initial friends state", [("friends", array(FRIEND)),
         ("requests", array(REQUEST)), ("presence", array(PRESENCE)), ("blocked", array([("account_id", "id16")]))])
register(0x585B3816, 1, "friend added", FRIEND)
register(0x585B3816, 2, "friend removed", [("account_id", "id16")])
register(0x585B3816, 3, "incoming friend request", REQUEST)
register(0x585B3816, 4, "friend request removed", [("inviter_account_id", "id16")])
register(0x585B3816, 5, "friend metadata update", FRIEND)
register(0x585B3816, 6, "friend request completion with localized result",
         [("token", "u64"), ("resource_guid", "u64"), ("format_argument", "u64")])
for offset, function in ((7, "friend request response completion"), (8, "friend removal completion")):
    register(0x585B3816, offset, function, [("token", "u64"), ("status", "u32")])
register(0x585B3816, 9, "friend presence update", [("presence", array(PRESENCE))])
register(0x585B3816, 10, "rich presence localization query completion", [("status", "u32"), ("token", "u64"),
         ("protobuf_purpose_unknown", "blob")])
register(0x027ADB37, 0, "send friend request", [("token", "u64"), ("target_type", "u32"),
         ("target", "string"), ("message", "string")])
register(0x027ADB37, 1, "answer friend request", [("token", "u64"), ("inviter_account_id", "id16"),
         ("answer", "u32")])
register(0x027ADB37, 2, "remove friend", [("token", "u64"), ("target_account_id", "id16")])
register(0x027ADB37, 3, "rich presence localization query", [("token", "u64"),
         ("localization_key_part0", "u32"), ("localization_key_part1", "u32"),
         ("selector_purpose_unknown", "u32")])
register(0x027ADB37, 4, "send tell", [("token", "u64"), ("target_account_id", "id16"),
         ("target_game_account_id", "id16"), ("text", "string")])
register(0x027ADB37, 5, "set friend metadata (favorite bit0)", [("token", "u64"),
         ("target_account_id", "id16"), ("metadata_bits", "u64")])
# Native Block action hash42DAB826 at CE2095 constructs vtable160FC38;
# getterFC5630 selects27006. Its only field is the selected root account.
register(0x027ADB37, 6, "block player (unimplemented)", [("target_account_id", "id16")])
register(0x027ADB37, 7, "purpose unknown", [("account_id", "id16")])
# 24919's Social context action calls 0xC160A0. Its vtable getter
# 0xFC5650 selects 27008, and the sender copies the account's cached name.
# The observed integer is always 1; no category/enum meaning is recovered.
register(0x027ADB37, 8, "report player (unimplemented)",
         [("target_account_id", "id16"), ("i32_purpose_unknown", "i32"),
          ("cached_target_name", "string"), ("string1_purpose_unknown", "string")])
register(0x585B3816, 11, "friend operation completion with localized result", [("token", "u64"),
         ("resource_guid", "u64"), ("format_argument", "u64")])
register(0x585B3816, 12, "friend operation completion", [("token", "u64"), ("status", "u32")])
register(0x585B3816, 13, "received tell", [("sender_account_id", "id16"), ("text", "string")])
register(0x585B3816, 14, "sent tell echo", [("target_account_id", "id16"), ("text", "string")])
# C1A4B0 clears child presence entities and the root presence field; the
# original server trigger for this empty notification is still unknown.
register(0x585B3816, 15, "presence cache reset (trigger unknown)", [])
register(0x585B3816, 16, "localized friend notice", [("resource_guid", "u64"), ("account_id", "id16")])
# C6920F -> C1A860 selects the localized report-success/failure notice.
register(0x585B3816, 17, "report submission result (unimplemented)", [("report_received", "bool")])
register(0x8A89BC90, 0, "friend profile cache", [("profiles", array(FRIEND_PROFILE)),
         ("ids_purpose_unknown", array("id16"))])
register(0x8A89BC90, 4, "friend portrait update", [("account_id", "id16"), ("portrait_guid", "u64")])
register(0xBD212AB1, 0, "player progression state", [("bool_purpose_unknown", "bool"),
         ("u64_purpose_unknown", "u64"), ("array0_purpose_unknown", array(PROGRESS_ENTRY)),
         ("array1_purpose_unknown", array(PROGRESS_ENTRY))])
register(0xBD212AB1, 1, "player progression GUID cache append", [("progression_guid", "u64")])
register(0xBD212AB1, 2, "purpose unknown", [("values", array("u64"))])
# C2A290/C2A3B0 print these lists; they do not install progression state.
for offset, label in ((3, "default unlock diagnostics"), (4, "active unlock diagnostics")):
    register(0xBD212AB1, offset, label, [("unlocks", array(UNLOCK_DIAGNOSTIC))])
register(0xC345520E, 0, "request player progression", [])
register(0x70519A68, 0, "hero catalog and lobby display loadouts", [
    ("hero_level_limit", "i32"), ("heroes", array(HERO_RECORD)),
    ("entries_purpose_unknown", array([("hero_guid", "u64"),
                                       ("entries", array(PROGRESS_ENTRY))]))])
register(0x70519A68, 1, "hero unlock cache append", [("hero_guid", "u64"), ("unlock_guid", "u64")])
register(0x70519A68, 2, "hero skin equipment update", [("hero_guid", "u64"), ("skin_guid", "u64")])
register(0x70519A68, 3, "equipped unlock update", [("hero_guid", "u64"),
         ("slot_or_context_purpose_unknown", "u64"), ("equipped_unlock_guid", "u64")])
register(0x70519A68, 4, "hero level and unlock update", [("heroes", array(HERO_LEVEL_UPDATE))])
register(0x70519A68, 5, "hero experience table diagnostics", [("experience_deltas", array("u64"))])
for offset, label in ((6, "all hero unlock diagnostics"), (7, "active hero unlock diagnostics")):
    register(0x70519A68, offset, label, [("hero_guid", "u64"), ("unlocks", array(UNLOCK_DIAGNOSTIC))])
register(0x70519A68, 8, "hero unlock diagnostics by level", [("hero_guid", "u64"),
         ("levels", array(array(UNLOCK_DIAGNOSTIC)))])
register(0xE79948F2, 0, "free asset catalog", [("asset_guids", array("u64"))])
register(0x74C43F11, 0, "custom game catalogs", [("catalog0_purpose_unknown", array("u64")),
         ("catalog1_purpose_unknown", array("u64"))])
register(0x0AF5E1B5, 1, "private game menu request", [("u8_purpose_unknown", "u8"),
         ("string0_purpose_unknown", "string"), ("string1_purpose_unknown", "string")])
register(0xECB33337, 0, "Play/search request; no match allocation", None)


def describe_beta_payload(payload, *, wire_families=None, direction=None, raw_limit=64):
    """Decode supported schemas and label absent knowledge without speculation.

    Direction is optional, but when supplied a reversed In/Out family is
    explicitly flagged. Inspection limits are not described as malformed wire.
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes")
    if type(raw_limit) is not int or not 0 <= raw_limit <= 4096:
        raise ValueError("raw_limit must be between 0 and 4096")
    payload = bytes(payload)
    result = {"length": len(payload), "direction": direction, "wire_index": None,
              "message_offset": None, "function": "purpose unknown", "status": "unknown",
              "fields": {}, "raw_hex": payload[:raw_limit].hex(),
              "omitted_raw_bytes": max(0, len(payload) - raw_limit)}
    if len(payload) < 2:
        result.update(status="malformed", error="payload is shorter than its two-byte header")
        return result
    wire, offset = payload[:2]
    result.update(wire_index=wire, message_offset=offset)
    if wire == 0:
        result["family_name"] = "Base control"
        if offset == 0:
            result["function"] = "protocol family announcement"
            try:
                families = parse_announcement(payload)
                result.update(status="decoded", fields={"families": [f"{crc:08X}" for crc in families]})
            except ProtocolError as error:
                result.update(status="malformed", error=str(error))
        elif offset in (2, 3):
            result["function"] = "channel acceptance ACK" if offset == 2 else "keepalive"
            result["status"] = "decoded" if len(payload) == 2 else "malformed"
            if len(payload) != 2:
                result["error"] = "unexpected control body bytes"
        return result
    crc = (wire_families or {}).get(wire)
    if crc is None:
        return result
    result["family_crc_hex"] = f"{crc:08X}"
    family = FAMILIES.get(crc)
    if family is None:
        return result
    name, minimum, maximum = family
    result["family_name"] = name
    if offset <= maximum:
        result["message_id"] = minimum + offset
    if direction in ("c2s", "s2c"):
        expected = "ClientOut" if direction == "c2s" else "ClientIn"
        if not name.startswith(expected):
            result["direction_warning"] = "family belongs to the opposite direction"
    registered = MESSAGES.get((crc, offset))
    if registered is None:
        return result
    function, schema = registered
    result["function"] = function
    if schema is None:
        result.update(status="unparsed", unknown_fields="body schema/purpose unknown")
        return result
    reader = Reader(payload[2:])
    try:
        result["fields"] = reader.value(schema)
        reader.finish()
        result["status"] = "decoded"
    except InspectionLimit as error:
        result.update(status="inspection limit", error=str(error))
    except ProtocolError as error:
        result.update(status="malformed", error=str(error))
    return result


def format_beta_packet(description, *, connection=None, user=None, color=False):
    """Produce a compact line with decoded fields and optional light ANSI cues."""
    direction = {"c2s": "IN", "s2c": "OUT"}.get(description.get("direction"), "PACKET")
    direction = colorize(direction, {"IN": "in", "OUT": "out"}.get(direction, "dim"), color=color)
    identity = " [" + json.dumps(console_data(connection), ensure_ascii=True) + "]" if connection is not None else ""
    if user is not None:
        identity += " user=" + json.dumps(console_data(str(user)), ensure_ascii=True)
    family = description.get("family_name") or (
        "crc=" + description["family_crc_hex"] if description.get("family_crc_hex") else "purpose unknown")
    family = family.removeprefix("ClientInLobby").removeprefix("ClientOutLobby")
    message_id = description.get("message_id")
    identifier = (f"id={message_id}" if message_id is not None
                  else f"wire={description.get('wire_index')}/{description.get('message_offset')}")
    identifier = colorize(identifier, "id", color=color)
    function = colorize(description.get("function", "purpose unknown"), "function", color=color)
    status = description.get("status", "unknown")
    tone = "error" if status == "malformed" else "dim" if status == "decoded" else "warning"
    status = colorize(f"[{status}]", tone, color=color)
    details = console_data({key: description[key] for key in
        ("fields", "unknown_fields", "error", "direction_warning") if key in description})
    if details.get("fields") == {}:
        del details["fields"]
    prefix = (f"{direction}{identity} {family} {identifier} {function} {status} "
              f"bytes={description.get('length', 0)}")
    encoded = json.dumps(details, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) > 1400:
        # Captures retain the full descriptions; keep a complete console object.
        omitted = len(encoded)
        details = {key: value for key, value in details.items() if key != "fields"}
        details["fields"] = "decoded data exceeds console limit; see capture if enabled"
        details["omitted_decoded_characters"] = omitted
        encoded = json.dumps(details, ensure_ascii=True, separators=(",", ":"))
    if "error" in details or "direction_warning" in details:
        encoded = colorize(encoded, "error" if "error" in details else "warning", color=color)
    return prefix + (" " + encoded if details else "")


def format_beta_wire(direction, data, stage=None, *, connection=None, raw_limit=64, color=False):
    """Describe handshake chunks without inventing complete-record boundaries."""
    if stage in ("frame", "frame_stream"):
        return None  # Complete decrypted frames have their own semantic lines.
    functions = {"client_hello": "client greeting", "server_hello": "server greeting",
                 "client_nonce": "client ID/nonce record", "server_challenge": "challenge/server nonce",
                 "client_proof": "client MAC1 proof record",
                 "server_proof_and_blob": "server MAC2 and encrypted RSA state",
                 "passive": "purpose unknown (passive wire observation)"}
    label = functions.get(stage, "purpose unknown")
    arrow = {"c2s": "IN", "s2c": "OUT"}.get(direction, "PACKET")
    arrow = colorize(arrow, {"IN": "in", "OUT": "out"}.get(arrow, "dim"), color=color)
    identity = " [" + json.dumps(console_data(connection), ensure_ascii=True) + "]" if connection is not None else ""
    return (f"{arrow}{identity} JAM {colorize(label, 'function', color=color)} [wire chunk] "
            + json.dumps(console_data({"stage": stage, "length": len(data)}),
                         ensure_ascii=True, separators=(",", ":")))
