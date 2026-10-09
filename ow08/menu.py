"""Build-24919 menu messages and authenticated shared lobby routes.

Schemas come from the beta's own JamMessageInfo tables. No match allocation,
instance handoff, gameplay endpoint, or retail payload is sent by this module.
"""

from __future__ import annotations

import asyncio
import struct

from .login import IN_CONNECT_BETA, OUT_CONNECT_BETA, beta_login_bodies
from .friends import (DUMMY_ACCOUNT, IN_FRIEND_PROFILES, friends_profile_state,
                      friends_state, parse_friend_request, parse_tell_request)
from .party import OUT_PARTY, _portrait, parse_party_request
from .portrait import DEFAULT_PORTRAIT
from .heroes import (IN_HERO_PROGRESSION, beta_hero_catalog, beta_hero_preload,
                     menu_heroes, normalize_menu_hero)
from .protocol import ProtocolError

IN_PLAYER = 0x912CEA67
OUT_PLAYER = 0xB7C5277C
IN_CHAT = 0xDBE61F10
OUT_CHAT = 0x11757702
IN_FRIENDS = 0x585B3816
OUT_FRIENDS = 0x027ADB37
IN_PARTY = 0xC988E4B3
IN_FREE_ASSETS = 0xE79948F2
IN_CUSTOM_GAME = 0x74C43F11
OUT_CUSTOM_GAME = 0x0AF5E1B5
OUT_MATCHMAKING = 0xECB33337

ACCOUNT = struct.pack("<QQ", 1, 0x0100000000000000)
ZERO_ID = bytes(16)
PARTY = struct.pack("<QQ", 2, 1)
# The beta's /join general command emits 21702 byte 9 (RVA 0xC778B3).
GENERAL = struct.pack("<i", 9) + ZERO_ID
# The beta's system channel selects the yellow system-text style (CDCC60).
SYSTEM = struct.pack("<i", 2) + ZERO_ID
# The beta's warning channel renders system text in red.
WARNING = struct.pack("<i", 1) + ZERO_ID
WELCOME = "Welcome to the Overwatch Closed Beta!"
DEFAULT_MENU = {
    "name": "Player",
    "hero": "random",
    "announcements": [],
    # Accepted for old experiment files; chat acknowledgments are always off.
    "chat_reply": False,
}


def text(value, label="text", maximum=1024):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{label} must be a nonempty string without NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > maximum:
        raise ValueError(f"{label} exceeds {maximum} UTF-8 bytes")
    return encoded + b"\0"


def validate_menu(settings):
    if not isinstance(settings, dict) or set(settings) - set(DEFAULT_MENU):
        raise ValueError("menu accepts name, hero, announcements, and chat_reply")
    result = {**DEFAULT_MENU, **settings}
    text(result["name"], "menu name", 64)
    result["hero"] = normalize_menu_hero(result["hero"])
    lines = result["announcements"]
    if not isinstance(lines, list) or len(lines) > 16:
        raise ValueError("menu announcements must be an array of at most 16 strings")
    for line in lines:
        text(line, "announcement")
    if not isinstance(result["chat_reply"], bool):
        raise ValueError("menu chat_reply must be true or false")
    result["chat_reply"] = False
    return result


class Reader:
    """Bounded decoding: malformed requests never become partial actions."""
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, size):
        end = self.position + size
        if end > len(self.data):
            raise ProtocolError("truncated beta menu request")
        value = self.data[self.position:end]
        self.position = end
        return value

    def string(self):
        end = self.data.find(b"\0", self.position)
        if end < 0 or end - self.position > 1024:
            raise ProtocolError("invalid beta menu string")
        try:
            value = self.data[self.position:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("invalid beta menu UTF-8") from error
        self.position = end + 1
        return value

    def finish(self):
        if self.position != len(self.data):
            raise ProtocolError("trailing beta menu request bytes")


def player_record(name, account=ACCOUNT, party=PARTY):
    # 20801's ordered descriptor values; remaining ID/GUID semantics are unknown.
    return account + text(name, "name", 64) + account + bytes(8) + party + bytes(4)


def party_record(name, account=ACCOUNT, party=PARTY, *, portrait_guid=DEFAULT_PORTRAIT):
    # 20700: party ID and one local member; each non-bool field ends a bool run.
    # The beta counts status values 5..7 as active members (RVA 0xCD9E50).
    # The first u64 is memory offset 0x20, resolved by PartyVM (DA5C94).
    member = (text(name, "name", 64) + b"\x01\x05"
              + _portrait(portrait_guid) + bytes(8) + account + account)
    return party + struct.pack("<I", 1) + member


def chat_message(channel, name, account, message):
    return channel + text(name, "sender", 64) + account + text(message)


def system_message(channel, message):
    # Empty member name selects the beta's system-text receiver path.
    return channel + b"\0" + ZERO_ID + text(message)


class MenuLobby:
    def __init__(self, session, settings):
        self.session = session
        self.settings = validate_menu(settings)
        self.logged_in = False
        self.channels = set()
        self.announced = False
        self.account = ACCOUNT
        self.portrait_guid = DEFAULT_PORTRAIT
        self.party = PARTY
        self.actor = None
        self.hub = getattr(session, "hub", None)
        experiment = getattr(session, "exp", None)
        self.extended = getattr(experiment, "settings", {}).get("extended", False)

    async def attach_account(self, lease):
        self.account = lease.account.account_id
        self.portrait_guid = getattr(lease.account, "portrait_guid", DEFAULT_PORTRAIT)
        self.party = struct.pack("<QQ", lease.account.id, 1)
        self.settings["name"] = lease.account.display_name
        if self.hub is not None:
            self.actor = await self.hub.register(lease, self.send,
                                               on_send_error=lambda error: self.session.writer.close(),
                                               hero_selection=self.settings["hero"])
            self.party, _, _ = await self.hub.party_view(self.actor)

    async def send(self, family, offset, body=b""):
        if family == IN_PARTY and offset == 0:
            self.party = body[:16]
        await self.session.send_family(family, offset, body)

    async def initialize(self):
        bodies = beta_login_bodies(name=self.settings["name"], known_keys=True, account_id=self.account)
        bodies[4] = beta_hero_preload(self.settings["hero"], extended=self.extended)
        for offset in (0, 3, 4):
            await self.send(IN_CONNECT_BETA, offset, bodies.get(offset, b""))
        # The native menu chooses from the beta's hero catalog. Install it
        # before connect completion creates the scene; the preload loads the
        # same hero and classic-skin packages through the content manager.
        if self.settings["hero"] != "none":
            catalog = (self.hub.hero_catalog(self.actor.lease.account, self.settings["hero"])
                       if self.actor else beta_hero_catalog(self.settings["hero"], extended=self.extended))
            await self.send(IN_HERO_PROGRESSION, 0, catalog)
        await self.send(IN_CONNECT_BETA, 1)
        self.logged_in = True
        if self.actor:
            self.party, player, party = await self.hub.party_view(self.actor)
        else:
            player = player_record(self.settings["name"], self.account, self.party)
            party = party_record(self.settings["name"], self.account, self.party,
                                 portrait_guid=self.portrait_guid)
        await self.send(IN_PLAYER, 1, player)
        await self.send(IN_PLAYER, 2, struct.pack("<fff", 1, 1, 1) + bytes(5))
        await self.send(IN_PARTY, 0, party)
        if self.actor:
            await self.hub.initialize_friends(self.actor, self.send)
        else:
            await self.send(IN_FRIENDS, 0, friends_state())
            await self.send(IN_FRIEND_PROFILES, 0,
                            friends_profile_state(include_dummy=True, dummy_account=DUMMY_ACCOUNT))
        await self.send(IN_FREE_ASSETS, 0, bytes(4))
        await self.send(IN_CUSTOM_GAME, 0, bytes(8))
        self.channels.add(GENERAL)
        # 20403 is the initial channel snapshot, without join/roster output.
        await self.send(IN_CHAT, 3, struct.pack("<I", 1) + b"\x00" + GENERAL)
        task = asyncio.create_task(self.after_menu())
        self.session.tasks.add(task)
        task.add_done_callback(self.session.task_done)
        self.session.capture.event("menu_login", name=self.settings["name"],
                                   hero=self.settings["hero"],
                                   extended=self.extended,
                                   hero_count=len(menu_heroes(self.settings["hero"], extended=self.extended)))

    async def after_menu(self):
        await asyncio.sleep(3)
        if self.actor:
            await self.hub.party_refresh(self.actor)
        else:
            await self.send(IN_PLAYER, 1, player_record(self.settings["name"], self.account, self.party))
            await self.send(IN_PARTY, 0, party_record(self.settings["name"], self.account, self.party,
                                                    portrait_guid=self.portrait_guid))
        await self.welcome()

    async def welcome(self):
        if not self.announced:
            self.announced = True
            await self.send(IN_CHAT, 0, system_message(SYSTEM, WELCOME))
            if self.actor is not None:
                await self.hub.mark_ready(self.actor)
            for line in self.settings["announcements"]:
                await self.send(IN_CHAT, 0, system_message(SYSTEM, line))

    async def join(self, channel):
        # Three consecutive bool fields share the same byte in the beta.
        if channel != GENERAL:
            return
        if self.actor is not None:
            await self.hub.join_general(self.actor)
        self.channels.add(channel)
        await self.send(IN_CHAT, 2, b"\x00" + channel)

    async def members(self, channel):
        if self.actor is not None:
            await self.hub.who(self.actor, channel)
        else:
            await self.send(IN_CHAT, 1, channel + struct.pack("<I", 1)
                            + text(self.settings["name"], "name", 64) + self.account)

    async def handle(self, payload):
        family = self.session.families.get(payload[0])
        offset, body = payload[1], payload[2:]
        if family == OUT_CONNECT_BETA and offset == 0 and not self.logged_in:
            await self.initialize()
            return
        if not self.logged_in:
            return
        # Only menu actions count; protocol keepalives and progression replies
        # arrive on other families. Hub entry points also cover console actors.
        if self.actor is not None and family in (OUT_CHAT, OUT_PARTY, OUT_FRIENDS,
                                                OUT_PLAYER, OUT_CUSTOM_GAME, OUT_MATCHMAKING):
            await self.hub.record_activity(self.actor)
        if family == OUT_CHAT:
            await self.chat(offset, body)
        elif family == OUT_PARTY:
            await self.party_request(offset, body)
        elif family == OUT_FRIENDS:
            await self.friend_request(offset, body)
        elif family == OUT_PLAYER:
            self.session.capture.event("menu_request", family="player", offset=offset, body_hex=body.hex())
        elif family in (OUT_CUSTOM_GAME, OUT_MATCHMAKING):
            self.session.capture.event("menu_request", family=f"{family:08x}", offset=offset, body_hex=body.hex())
            # These buttons may display the client's search/loading UI. Give
            # useful feedback without allocating a match or sending a handoff.
            if self.announced and (family, offset) in ((OUT_CUSTOM_GAME, 1), (OUT_MATCHMAKING, 0)):
                await self.send(IN_CHAT, 0, system_message(WARNING,
                    "Matchmaking is not supported by this server emulator."))

    async def friend_request(self, offset, body):
        if offset == 4 and self.actor is not None:
            token, target, game_target, message = parse_tell_request(body)
            await self.hub.tell(self.actor, token, target, game_target, message)
            self.session.capture.event("menu_tell", target_account_id=target.hex(),
                                       target_game_account_id=game_target.hex(), text=message)
            return
        request = parse_friend_request(offset, body)
        self.session.capture.event("menu_request", family="friends", offset=offset,
                                   body_hex=body.hex(), action=request.action if request else "unknown")
        if request is not None and self.actor is not None:
            accepted = await self.hub.social_request(self.actor, request)
            self.session.capture.event("menu_social_result", action=request.action, accepted=accepted)

    async def party_request(self, offset, body):
        request = parse_party_request(offset, body)
        self.session.capture.event("menu_request", family="party", offset=offset,
                                   body_hex=body.hex(), action=request.action if request else "unknown")
        if request is None or self.actor is None:
            return
        if request.action == "invite":
            await self.hub.party_invite(self.actor, request.identity, request.request_to_join)
        elif request.action == "kick":
            await self.hub.party_kick(self.actor, request.identity)
        elif request.action == "promote":
            await self.hub.party_promote(self.actor, request.identity)
        elif request.action == "leave":
            await self.hub.party_leave(self.actor)
        else:
            await self.hub.party_respond(self.actor, request.identity, accept=request.action == "accept")

    async def chat(self, offset, body):
        reader = Reader(body)
        if offset == 2:
            kind = reader.take(1)[0]
            reader.finish()
            if kind == 9:
                await self.join(GENERAL)
            elif kind == 4 and self.actor is not None:
                groups = [channel for channel in self.actor.channels if channel[:4] == struct.pack("<i", 4)]
                for channel in groups:
                    await self.send(IN_CHAT, 2, b"\x00" + channel)
            else:
                self.session.capture.event("menu_request", family="chat", offset=offset, body_hex=body.hex())
        elif offset in (0, 1, 3):
            channel = reader.take(20)  # i32 type followed by id16; no memory padding.
            message = reader.string() if offset == 0 else None
            reader.finish()
            if offset == 3:
                if channel != GENERAL:
                    return
                if self.actor is not None:
                    await self.hub.leave_general(self.actor)
                self.channels.discard(channel)
                await self.send(IN_CHAT, 6, channel)
                return
            channels = self.actor.channels if self.actor is not None else self.channels
            if channel not in channels:
                self.session.capture.event("chat_rejected", reason="channel membership required", channel_hex=channel.hex())
                return
            if offset == 1:
                await self.members(channel)
            elif message:
                if self.actor is not None:
                    if channel == GENERAL:
                        await self.hub.general(self.actor, message)
                    else:
                        await self.hub.group(self.actor, message)
                else:
                    await self.send(IN_CHAT, 0, chat_message(channel, self.settings["name"], self.account, message))
                self.session.capture.event("menu_chat", channel_hex=channel.hex(), text=message)
        else:
            self.session.capture.event("menu_request", family="chat", offset=offset, body_hex=body.hex())
