"""Build 24919 friend, presence and tell codecs from native beta evidence.

The direct menu fixture remains one offline DummyFriend. Authenticated menu
peers add root account presence and a separate online game-account child.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
import unicodedata

from .protocol import ProtocolError
from .portrait import DEFAULT_PORTRAIT
from .games import DEFAULT_GAME_ACTIVITY, GameActivity, game_account_id


DUMMY_ACCOUNT = struct.pack("<QQ", 2, 0x0100000000000000)
AUTHENTICATED_DUMMY_ACCOUNT = struct.pack("<QQ", 0xFFFFFFFFFFFFFFFF, 0x0100000000000000)
ZERO_ID = bytes(16)
PRESENCE_PROGRAM = 0x424E  # Battle.net's "BN" presence namespace.
DEFAULT_FRIEND_NAME = "DummyFriend"
IN_FRIENDS = 0x585B3816
IN_FRIEND_PROFILES = 0x8A89BC90
OUT_FRIENDS = 0x027ADB37
TELL_NOT_FRIENDS = 0x0DE000000000030E
TELL_OFFLINE = 0x0DE000000000030F
TELL_INTERNAL_ERROR = 0x0DE0000000000310
FRIEND_REQUEST_INTERNAL_ERROR = 0x0DE0000000000363
FRIEND_REQUEST_SENT = 0x0DE0000000000365
FRIEND_REQUEST_SELF = 0x0DE000000000036A
FRIEND_REQUEST_ALREADY_FRIENDS = 0x0DE00000000017B6
FRIEND_FAVORITE = 1
PRESENCE_STATUSES = frozenset(("online", "away", "busy"))


def _integer(value, bits, label, *, positive=False):
    if (isinstance(value, bool) or not isinstance(value, int)
            or not int(positive) <= value < 1 << bits):
        raise ValueError(f"{label} must be a {'positive' if positive else 'nonnegative'} u{bits}")
    return value


def _text(value, label, limit, *, empty=False):
    if not isinstance(value, str) or "\0" in value or (not empty and not value):
        raise ValueError(f"{label} must be a {'possibly empty' if empty else 'nonempty'} string without NUL")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain valid UTF-8") from error
    if len(encoded) > limit:
        raise ValueError(f"{label} exceeds {limit} UTF-8 bytes")
    return encoded + b"\0"


def friend_record(relationship):
    """27101/27105: opaque u32=0, metadata u64 with favorite bit0, root ID.

    C164B0 changes only bit0 of the second metadata field. Local relations do
    not use its other bits or the first field. Storage timestamps are not wire
    metadata and must not be placed in either field.
    """
    if not isinstance(relationship.favorite, bool):
        raise ValueError("friend favorite must be a boolean")
    return (struct.pack("<IQ", 0, int(relationship.favorite))
            + _identity(relationship.account.account_id, "friend account"))


def incoming_request_record(request):
    """27103/27100 request record, keyed by the inviter's root account.

    Native C17230 displays the first string as a BattleTag; C174A0 and C161E0
    use the first ID for removing/answering the request. The other strings,
    scalars and final ID have no recovered menu consumer, so they retain empty
    or zero values. The message is persisted locally; its native
    string slot is intentionally not guessed. Login aliases are never sent.
    """
    return (_text(request.sender.battle_tag, "inviter BattleTag", 128)
            + b"\0\0" + bytes(12)
            + _identity(request.sender.account_id, "inviter account") + ZERO_ID)


def social_friends_state(snapshot, *, online=(), last_online=None, statuses=None, games=None):
    """27100: only the owner's stored friends and incoming requests.

    The legacy registered_friends_state remains available for direct fixtures.
    This authenticated form adds neither global peers nor DummyFriend.
    """
    relationships, requests = tuple(snapshot.friends), tuple(snapshot.incoming)
    identities = [relation.account.account_id for relation in relationships]
    if len(set(identities)) != len(identities) or snapshot.owner.account_id in identities:
        raise ValueError("friends must have distinct peer identities")
    inviter_ids = [request.sender.account_id for request in requests]
    if len(set(inviter_ids)) != len(inviter_ids):
        raise ValueError("incoming requests must have distinct inviters")
    if any(request.recipient.account_id != snapshot.owner.account_id for request in requests):
        raise ValueError("incoming friend request belongs to another account")
    active, seen, statuses, games = frozenset(online), last_online or {}, statuses or {}, games or {}
    fallback = max(0, int(time.time()) - 60)
    records = b"".join(friend_record(relation) for relation in relationships)
    pending = b"".join(incoming_request_record(request) for request in requests)
    presence = b"".join(account_presence(relation.account,
                                       online=relation.account.account_id in active,
                                       last_online=seen.get(relation.account.account_id, fallback),
                                       status=statuses.get(relation.account.account_id, "online"),
                                       game_activity=games.get(relation.account.account_id, DEFAULT_GAME_ACTIVITY))
                        for relation in relationships)
    return (struct.pack("<I", len(relationships)) + records
            + struct.pack("<I", len(requests)) + pending
            + struct.pack("<I", 2 * len(relationships)) + presence + bytes(4))


@dataclass(frozen=True)
class FriendAction:
    action: str
    token: int
    target: str | bytes
    target_type: int | None = None
    message: str = ""
    answer: int | None = None
    metadata: int | None = None


def parse_friend_request(offset, body):
    """Bounded supported beta27000/1/2/5; unknown offsets return None.

    Native target types are 1=BattleTag and 2=email; answer0 accepts and 1
    declines. Unsupported types/answers fail before controller mutation.
    """
    if offset not in (0, 1, 2, 5):
        return None
    if not isinstance(body, bytes) or len(body) < 8:
        raise ProtocolError("truncated beta friend action")
    token = struct.unpack_from("<Q", body)[0]
    if not token:
        raise ProtocolError("beta friend action requires a nonzero token")
    if offset == 0:
        if not 14 <= len(body) <= 12 + 129 + 1025:
            raise ProtocolError("invalid beta friend request length")
        target_type = struct.unpack_from("<I", body, 8)[0]
        if target_type not in (1, 2):
            raise ProtocolError("unsupported beta friend target type")
        parts = body[12:].split(b"\0")
        if len(parts) != 3 or parts[-1] or not 1 <= len(parts[0]) <= 128 or len(parts[1]) > 1024:
            raise ProtocolError("invalid beta friend request strings")
        try:
            target, message = (part.decode("utf-8") for part in parts[:2])
        except UnicodeDecodeError as error:
            raise ProtocolError("invalid beta friend request UTF-8") from error
        return FriendAction("request", token, target, target_type, message)
    expected = {1: 28, 2: 24, 5: 32}[offset]
    if len(body) != expected or body[8:24] == ZERO_ID:
        raise ProtocolError("invalid beta friend action body")
    target = body[8:24]
    if offset == 1:
        answer = struct.unpack_from("<I", body, 24)[0]
        if answer not in (0, 1):
            raise ProtocolError("unsupported beta friend request answer")
        return FriendAction("accept" if answer == 0 else "decline", token, target, answer=answer)
    if offset == 2:
        return FriendAction("remove", token, target)
    return FriendAction("favorite", token, target, metadata=struct.unpack_from("<Q", body, 24)[0])


def friend_operation_result(action, token, *, success=True, error_resource=None, argument=1):
    """Return (offset, body), preserving the client's pending-operation token.

    Requests use native27106 localized resources; responses/removal use27107/8
    status0 or1. Favorite uses generic27112 to clear its pending record;
    failures also receive an actor-only warning from the controller. The
    localized27111 resources recovered so far are specific to whispers.
    """
    _integer(token, 64, "friend operation token", positive=True)
    if not isinstance(success, bool):
        raise ValueError("friend operation success must be a boolean")
    if action == "request":
        resource = error_resource if error_resource is not None else (
            FRIEND_REQUEST_SENT if success else FRIEND_REQUEST_INTERNAL_ERROR)
        verified = {FRIEND_REQUEST_INTERNAL_ERROR, FRIEND_REQUEST_SENT,
                    FRIEND_REQUEST_SELF, FRIEND_REQUEST_ALREADY_FRIENDS}
        if resource not in verified:
            raise ValueError("friend request result resource is not verified")
        value = _integer(argument, 64, "friend result argument") if resource == FRIEND_REQUEST_INTERNAL_ERROR else 0
        return 6, struct.pack("<QQQ", token, resource, value)
    if action in ("respond", "accept", "decline", "remove"):
        if error_resource is not None:
            raise ValueError("friend response/removal uses numeric status")
        return (8 if action == "remove" else 7), struct.pack("<QI", token, int(not success))
    if action == "favorite":
        if error_resource is not None:
            raise ValueError("favorite update uses numeric status")
        return 12, struct.pack("<QI", token, int(not success))
    raise ValueError("unsupported beta friend operation")


def _varint(value):
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _blob(value):
    # Descriptor type 15: u32 byte length followed by the protobuf bytes.
    return struct.pack("<I", len(value)) + value


def _field(group, field, value, *, operation=0):
    # bnet.protocol.presence.FieldKey: program, group, field, unique id 0.
    key = b"\x08" + _varint(PRESENCE_PROGRAM) + b"\x10" + _varint(group)
    key += b"\x18" + _varint(field) + b"\x20\x00"
    # Beta's field tuple is key blob, Variant blob, operation u32 (0=set, 1=remove).
    return _blob(key) + _blob(value) + struct.pack("<I", operation)


def _name(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("dummy friend name must be a nonempty string without NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > 64:
        raise ValueError("dummy friend name exceeds 64 UTF-8 bytes")
    return encoded


def friend_presence(name=DEFAULT_FRIEND_NAME, *, last_online=None, account=DUMMY_ACCOUNT):
    """One beta presence record: fields array, account ID, parent ID.

    BN group 1 field 4 is BattleTag; field 6 is the last online timestamp in
    microseconds. Real ID name and online game accounts are omitted.
    """
    encoded = _name(name)
    if not isinstance(account, bytes) or len(account) != 16:
        raise ValueError("friend account must be 16 bytes")
    if last_online is None:
        last_online = max(0, int(time.time()) - 60)
    if isinstance(last_online, bool) or not isinstance(last_online, int) or last_online < 0:
        raise ValueError("dummy friend last_online must be a nonnegative Unix timestamp")
    # The beta's Variant string_value and int_value are protobuf fields 5 and 3.
    battle_tag = encoded + b"#0002"
    tag_value = b"\x2a" + _varint(len(battle_tag)) + battle_tag
    seen_value = b"\x18" + _varint(last_online * 1_000_000)
    fields = _field(1, 4, tag_value) + _field(1, 6, seen_value)
    return struct.pack("<I", 2) + fields + account + ZERO_ID


def friends_state(name=DEFAULT_FRIEND_NAME, *, last_online=None, account=DUMMY_ACCOUNT):
    """Body for Friends CRC 585B3816 offset 0 / message 27100.

    Four arrays: one friend; no incoming requests; one presence record; no
    blocked accounts. The two unneeded friend metadata fields stay zero.
    """
    presence = friend_presence(name, last_online=last_online, account=account)
    friend = bytes(12) + account  # u32, u64, id16; memory padding omitted.
    return struct.pack("<I", 1) + friend + bytes(4) + struct.pack("<I", 1) + presence + bytes(4)


def presence_update(name=DEFAULT_FRIEND_NAME, *, last_online=None):
    """Body for beta Friends offset 9 / 27109, if the Social UI needs refresh."""
    return struct.pack("<I", 1) + friend_presence(name, last_online=last_online)


def _identity(value, label):
    if not isinstance(value, bytes) or len(value) != 16:
        raise ValueError(f"{label} must contain exactly 16 bytes")
    return value


def friend_profile(name=DEFAULT_FRIEND_NAME, *, account=DUMMY_ACCOUNT,
                   portrait_guid=DEFAULT_PORTRAIT):
    """One 31800 peer profile, keyed by root account, with its chosen portrait.

    The native Social renderer reads the portrait from this separate profile
    cache. It is not a BN presence key. Descriptor wrappers serialize directly;
    the remaining scalar fields and nested arrays retain zero/empty values.
    """
    encoded = _name(name) + b"\0"
    identity = _identity(account, "friend profile account")
    portrait_guid = _integer(portrait_guid, 64, "friend portrait GUID")
    return (encoded + bytes(4) + struct.pack("<Q", portrait_guid) + identity
            + bytes(16)   # u32, u32, i32, empty id16 array
            + bytes(20)   # zero id16, empty id16 array
            + bytes(4))   # empty nested profile-state array


def friends_profile_state(accounts=(), *, include_dummy=False,
                          dummy_account=AUTHENTICATED_DUMMY_ACCOUNT):
    """31800 / profile-family offset0: profile array, then empty id16 array."""
    accounts = tuple(accounts)
    identities = [account.account_id for account in accounts]
    if len(set(identities)) != len(identities):
        raise ValueError("friend profiles must have distinct identities")
    profiles = [friend_profile(account.display_name, account=account.account_id,
                               portrait_guid=getattr(account, "portrait_guid", DEFAULT_PORTRAIT))
                for account in accounts]
    if include_dummy:
        _identity(dummy_account, "dummy friend profile account")
        if dummy_account in identities:
            raise ValueError("a registered friend profile collides with the DummyFriend identity")
        profiles.insert(0, friend_profile(account=dummy_account))
    return struct.pack("<I", len(profiles)) + b"".join(profiles) + bytes(4)


def friend_portrait_update(account, *, portrait_guid=DEFAULT_PORTRAIT):
    """31804 / profile-family offset4 updates an already-created root profile."""
    portrait_guid = _integer(portrait_guid, 64, "friend portrait GUID")
    return _identity(account, "friend profile account") + struct.pack("<Q", portrait_guid)


def _root_presence(account, last_online, *, remove_real_name=False):
    _name(account.display_name)
    identity = _identity(account.account_id, "friend account")
    tag = account.battle_tag.encode("utf-8")
    if not tag or b"\0" in tag or len(tag) > 128:
        raise ValueError("friend BattleTag must contain 1..128 UTF-8 bytes without NUL")
    if isinstance(last_online, bool) or not isinstance(last_online, int) or last_online < 0:
        raise ValueError("friend last_online must be a nonnegative Unix timestamp")
    fields = (_field(1, 4, b"\x2a" + _varint(len(tag)) + tag)
              + _field(1, 6, b"\x18" + _varint(last_online * 1_000_000)))
    real_name = getattr(account, "real_name", "")
    real_value = _text(real_name, "friend real name", 128, empty=True)[:-1]
    if any(unicodedata.category(char).startswith("C") for char in real_name):
        raise ValueError("friend real name must contain no control characters")
    if not isinstance(remove_real_name, bool):
        raise ValueError("remove real name must be a boolean")
    count = 2
    if real_value:
        fields += _field(1, 1, b"\x2a" + _varint(len(real_value)) + real_value)
        count += 1
    elif remove_real_name:
        # C190A0 skips Variant parsing for operation1 and erases this key.
        fields += _field(1, 1, b"", operation=1)
        count += 1
    return struct.pack("<I", count) + fields + identity + ZERO_ID


def game_presence(account, *, online, status="online", reset_status=False,
                  game_activity=DEFAULT_GAME_ACTIVITY):
    """Program-tagged child with BN online/availability, without rich captions."""
    if not isinstance(online, bool):
        raise ValueError("friend online must be a boolean")
    if not isinstance(status, str) or status not in PRESENCE_STATUSES:
        raise ValueError("friend status must be online, away, or busy")
    if not isinstance(reset_status, bool):
        raise ValueError("reset status must be a boolean")
    if not isinstance(game_activity, GameActivity):
        raise ValueError("friend game activity must be a GameActivity")
    identity = _identity(game_account_id(account, game_activity.game), "friend game account")
    parent = _identity(account.account_id, "friend account")
    fields = _field(2, 1, b"\x10" + bytes((online,)))
    count = 1
    if status != "online" or reset_status:
        # C15780 checks field10 (status3) before field2 (status2). Native
        # trials show orange for status3/away and red for status2/busy.
        # Both flags are explicit so transitions cannot retain a stale value.
        fields += _field(2, 2, b"\x10" + bytes((online and status == "busy",)))
        fields += _field(2, 10, b"\x10" + bytes((online and status == "away",)))
        count += 2
    return struct.pack("<I", count) + fields + identity + parent


def account_presence(account, *, online, last_online, remove_real_name=False,
                     status="online", reset_status=False,
                     game_activity=DEFAULT_GAME_ACTIVITY):
    """Two records in parent-before-child order, without a leading count."""
    return (_root_presence(account, last_online, remove_real_name=remove_real_name)
            + game_presence(account, online=online, status=status, reset_status=reset_status,
                            game_activity=game_activity))


def registered_friends_state(accounts, *, online=(), last_online=None,
                             include_dummy=False, dummy_last_online=None, statuses=None, games=None):
    """Initial27100 state for registered peers supplied by the trusted hub."""
    accounts = tuple(accounts)
    identities = [account.account_id for account in accounts]
    if len(set(identities)) != len(identities):
        raise ValueError("friend accounts must have distinct identities")
    active, seen, statuses, games = frozenset(online), last_online or {}, statuses or {}, games or {}
    fallback = max(0, int(time.time()) - 60)
    roster = b"".join(bytes(12) + _identity(account.account_id, "friend account")
                      for account in accounts)
    presence = b"".join(account_presence(account, online=account.account_id in active,
                                       last_online=seen.get(account.account_id, fallback),
                                       status=statuses.get(account.account_id, "online"),
                                       game_activity=games.get(account.account_id, DEFAULT_GAME_ACTIVITY))
                        for account in accounts)
    extra = int(include_dummy)
    if include_dummy:
        if AUTHENTICATED_DUMMY_ACCOUNT in identities:
            raise ValueError("a registered friend collides with the reserved DummyFriend identity")
        roster = bytes(12) + AUTHENTICATED_DUMMY_ACCOUNT + roster
        presence = friend_presence(account=AUTHENTICATED_DUMMY_ACCOUNT,
                                   last_online=dummy_last_online) + presence
    return (struct.pack("<I", len(accounts) + extra) + roster + bytes(4)
            + struct.pack("<I", len(accounts) * 2 + extra) + presence + bytes(4))


def parse_tell_request(body):
    """27004: token, target root ID, target game ID, terminated UTF-8 text."""
    if not isinstance(body, bytes) or len(body) < 42:
        raise ProtocolError("truncated beta tell request")
    token = struct.unpack_from("<Q", body)[0]
    encoded = body[40:]
    if not token or not encoded.endswith(b"\0") or b"\0" in encoded[:-1]:
        raise ProtocolError("invalid beta tell request")
    if not 1 <= len(encoded) - 1 <= 1024:
        raise ProtocolError("beta tell text must contain 1..1024 UTF-8 bytes")
    try:
        message = encoded[:-1].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("invalid beta tell UTF-8") from error
    return token, body[8:24], body[24:40], message


def tell_result(token, resource=None, argument=0):
    """27112 success or27111 native localized failure (including its token)."""
    if isinstance(token, bool) or not isinstance(token, int) or not 0 < token < 1 << 64:
        raise ValueError("tell token must be a positive u64")
    if resource is None:
        return 12, struct.pack("<QI", token, 0)
    if resource not in (TELL_NOT_FRIENDS, TELL_OFFLINE, TELL_INTERNAL_ERROR):
        raise ValueError("tell failure resource is not verified")
    if isinstance(argument, bool) or not isinstance(argument, int) or not 0 <= argument < 1 << 64:
        raise ValueError("tell failure argument must be a u64")
    return 11, struct.pack("<QQQ", token, resource, argument)
