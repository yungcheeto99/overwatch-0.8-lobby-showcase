"""Build-24919 menu Party codecs, grounded in native descriptors and UI probes.

These messages update lobby membership and pending invitations only. They do
not allocate a match, transfer an instance ticket, or start gameplay.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from .portrait import DEFAULT_PORTRAIT
from .protocol import ProtocolError


IN_PARTY = 0xC988E4B3
OUT_PARTY = 0x3BF03C3B
PARTY_INVITATION_SECONDS = 25
_ACTIONS = {1: "invite", 2: "kick", 3: "promote", 4: "leave",
            5: "accept", 6: "decline"}


def _identity(value, label):
    if not isinstance(value, bytes) or len(value) != 16 or value == bytes(16):
        raise ValueError(f"{label} must contain a nonzero 16-byte identity")
    return value


def _text(value, label, maximum):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{label} must be nonempty text without NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > maximum:
        raise ValueError(f"{label} exceeds {maximum} UTF-8 bytes")
    return encoded + b"\0"


def _portrait(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise ValueError("party member portrait must be a u64")
    return struct.pack("<Q", value)


def player_party_record(account, party_id):
    """20801: own root, display name, own root, zero GUID, Party ID, empty array."""
    identity = _identity(account.account_id, "player account")
    party_id = _identity(party_id, "party")
    return (identity + _text(account.display_name, "player name", 64) + identity
            + bytes(8) + party_id + bytes(4))


@dataclass(frozen=True)
class PartyRosterEntry:
    account: object
    pending: bool = False
    timestamp_ms: int = 0


def party_state(party_id, accounts, leader_id):
    """20700 settled-only compatibility entry point."""
    return party_roster(party_id, (PartyRosterEntry(account) for account in accounts), leader_id)


def party_roster(party_id, entries, leader_id):
    """20700: ordered active members (5) and pending invitations (1).

    Names carry full BattleTags: the native avatar menu reuses this string
    for friend requests, while its renderer strips the discriminator.
    Member order comes from the caller. The first member ID is the root
    account. The final ID remains opaque; repeating that root is the local
    choice independently verified by the native two-avatar Party trial.
    """
    party_id = _identity(party_id, "party")
    leader_id = _identity(leader_id, "party leader")
    entries = tuple(entries)
    accounts = tuple(entry.account for entry in entries)
    identities = [_identity(account.account_id, "party member") for account in accounts]
    if not 1 <= len(identities) <= 6 or len(set(identities)) != len(identities):
        raise ValueError("party must contain up to six distinct players")
    if not any(identity == leader_id and not entry.pending for identity, entry in zip(identities, entries)):
        raise ValueError("party leader must be a member")
    members = []
    for entry, account, identity in zip(entries, accounts, identities):
        if (type(entry.pending) is not bool or type(entry.timestamp_ms) is not int
                or not 0 <= entry.timestamp_ms < 1 << 64):
            raise ValueError("invalid party roster status or timestamp")
        _text(account.display_name, "party member name", 64)
        members.append(_text(account.battle_tag, "party member BattleTag", 128)
                       + bytes((identity == leader_id, 1 if entry.pending else 5))
                       + _portrait(getattr(account, "portrait_guid", DEFAULT_PORTRAIT))
                       + struct.pack("<Q", entry.timestamp_ms if entry.pending else 0)
                       + identity + identity)
    return party_id + struct.pack("<I", len(members)) + b"".join(members)


def invitation_body(party_id, inviter):
    """20702: invited Party ID, inviter root account, inviter BattleTag.

    C2B7A0 stores the first identity as the invitation response target and
    renders the second identity/name as the inviter. Native Accept/Decline
    independently emitted 22105/22106 with this same Party ID.
    """
    return (_identity(party_id, "invited party")
            + _identity(inviter.account_id, "party inviter")
            + _text(inviter.battle_tag, "inviter BattleTag", 128))


@dataclass(frozen=True)
class PartyRequest:
    offset: int
    identity: bytes | None = None
    request_to_join: bool = False

    @property
    def action(self):
        return _ACTIONS[self.offset]


def parse_party_request(offset, body):
    """Decode proven 22101..22106 actions without accepting partial requests.

    Unknown offsets return None for the caller to log. Identity authorization
    and pending-invitation checks belong to the shared lobby controller.
    The bool-true invite mode is decoded but remains a separate research gate.
    """
    if not isinstance(offset, int) or isinstance(offset, bool) or offset not in _ACTIONS:
        return None
    if not isinstance(body, bytes):
        raise ProtocolError("beta party request body must be bytes")
    expected = 17 if offset == 1 else 0 if offset == 4 else 16
    if len(body) != expected:
        raise ProtocolError("invalid beta party request length")
    if offset == 1 and body[16] not in (0, 1):
        raise ProtocolError("invalid beta party invite mode")
    return PartyRequest(offset, body[:16] if offset != 4 else None,
                        bool(body[16]) if offset == 1 else False)
