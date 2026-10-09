"""Administrative dot commands over the shared account and lobby services.

Input is never a shell command. Passwords are never repeated in responses.
The input service uses one reusable daemon reader per stream, rather than an
executor worker which could block server shutdown while waiting for stdin.
"""
from __future__ import annotations

import asyncio
import io
import inspect
import ipaddress
import json
import secrets
import shlex
import threading
import sys

from .accounts import AccountError, AccountNotFound
from .friends import PRESENCE_STATUSES
from .games import GAMES, resolve_game
from .heroes import DEFAULT_HERO_LEVEL, HEROES, HERO_LEVEL_LIMIT, normalize_menu_hero
from .portrait import PORTRAITS, resolve_portrait


MAX_COMMAND_BYTES = 8192
MAX_TELL_TOKEN = (1 << 64) - 1
MAX_SOCIAL_DISPLAY_ROWS = 50
MAX_SOCIAL_OUTPUT_BYTES = 12000
USERS_PER_PAGE = 20
MAX_USERS_OUTPUT_BYTES = 14000
MESSAGE_TYPES = frozenset(("general", "error", "announcement"))
FRIEND_ACTIONS = {
    ".friendadd": "add", ".friendrequest": "request", ".friendaccept": "accept",
    ".frienddecline": "decline", ".friendcancel": "cancel", ".friendremove": "remove",
    ".favorite": "favorite", ".favoriteuser": "favorite",
}
HELP = "\n".join((
    ".help",
    ".serverip (alias: .ip; current server IP, LAN gateway port or public tunnel identifier)",
    ".accountcreate <user> <pass>",
    ".accountdelete <user> (offline accounts only)",
    ".accountportrait [<account> <portrait name|GUID|number>] (no arguments: list all portraits)",
    ".accountrealname <account> <name|--clear> (saved Real ID/IRL label)",
    ".status <account> <online|away|busy> (online real or synthetic players; resets on reconnect)",
    ".game <account> <game> (no arguments: list games; None: Battle.net only; synthetic players; resets on reconnect)",
    ".users <page> (all accounts, 20 per page; default: 1 when no arguments)",
    ".login <user> (possess an idle synthetic player)",
    ".logoff <user> (synthetic players only)",
    ".msg <user> <general|error|announcement> <message>",
    ".msgall <general|error|announcement> <message>",
    ".partyinvite <from> <to>",
    ".partyaccept <user>",
    ".partydecline <user>",
    ".partyleave <user>",
    ".partykick <leader> <user>",
    ".partyleader <leader> <user>",
    ".group <user> <message>",
    ".tell <from> <to> <message>",
    ".friendadd <user> <friend> (explicit admin mutual friendship)",
    ".friendrequest <from> <to>",
    ".friendaccept <user> <from>",
    ".frienddecline <user> <from>",
    ".friendcancel <user> <to>",
    ".friendremove <user> <friend>",
    ".favorite <user> <friend> <on|off> (alias: .favoriteuser; default: on; arguments are case-insensitive)",
    ".friends <user>",
    "Native login: use <user>@email.com (or the fallback alias printed by .accountcreate), with its password.",
    "Party, group and tell actions require a current synthetic player created with .login; targets may be real players.",
    "Party invitations expire after 25 seconds and require explicit .partyaccept or .partydecline.",
    "Friend commands are administrative: offline, real and synthetic accounts are supported.",
    "Friend requests need explicit acceptance; .friendadd establishes mutual friendship directly.",
    "Friend targets accept local account names, native login aliases or local BattleTags; names are case-insensitive.",
    "Native favorite stars appear beside Real ID labels set with .accountrealname; plain BattleTag rows omit the star.",
    "Portrait names are case-insensitive; portrait changes are saved and refresh online party and friend views.",
    "Real names are optional, support spaces, and refresh friends; --clear removes the saved label.",
    "Status changes refresh native friend views; use .logoff to disconnect a synthetic player.",
    "Quote arguments containing spaces. Messages retain their internal spaces.",
))


def _lexer(line):
    lexer = shlex.shlex(io.StringIO(line), posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    # Preserve Windows-style paths and literal password backslashes. Quotes
    # still delimit arguments; use the other quote style for a literal quote.
    lexer.escape = ""
    return lexer


def _message(remainder):
    remainder = remainder.lstrip()
    if remainder.startswith(("'", '"')):
        lexer = _lexer(remainder)
        lexer.whitespace = ""
        message = lexer.get_token()
    else:
        message = remainder
    if not message or "\0" in message:
        raise ValueError("message must be nonempty and contain no NUL")
    if len(message.encode("utf-8")) > 1024:
        raise ValueError("message exceeds 1024 UTF-8 bytes")
    return message


def parse_command(line):
    """Return command/arguments, preserving message text after its prefix."""
    if not isinstance(line, str):
        raise ValueError("console input must be text")
    line = line.rstrip("\r\n")
    if len(line.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise ValueError("console command exceeds the input limit")
    if "\0" in line or "\r" in line or "\n" in line:
        raise ValueError("console command must be one line without NUL")
    lexer = _lexer(line)
    command = lexer.get_token()
    if not command:
        return None, []
    if not command.startswith("."):
        raise ValueError("console commands start with a dot; use .help")
    command = command.lower()
    if command == ".accountrealname":
        target = lexer.get_token()
        if target is None or target == "":
            raise ValueError("usage: .accountrealname <account> <name|--clear>")
        return command, [target, _message(line[lexer.instream.tell():])]
    if command in (".msg", ".msgall", ".group", ".tell"):
        required = 2 if command in (".msg", ".tell") else 1
        arguments = [lexer.get_token() for _ in range(required)]
        if any(argument is None or argument == "" for argument in arguments):
            raise ValueError("usage: " + next(row for row in HELP.splitlines() if row.startswith(command + " ")))
        message = _message(line[lexer.instream.tell():])
        if command in (".msg", ".msgall") and arguments[-1] not in MESSAGE_TYPES:
            raise ValueError("message type must be general, error, or announcement")
        return command, arguments + [message]
    return command, list(lexer)


def _name(value):
    return json.dumps(value, ensure_ascii=True)


def _server_address(value):
    """Display only a joining endpoint, never a descriptor or private URL fields."""
    if value is None:
        return None
    if (not isinstance(value, str) or len(value) > 512
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        raise ValueError("invalid server address")
    if value.startswith(("https://", "wss://")):
        from virtual import normalize_endpoint
        return normalize_endpoint(value)
    host, separator, port = value.partition(":")
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("invalid server address")
    if separator:
        if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("invalid server port")
        return f"{address}:{int(port)}"
    return str(address)


def _social_listing(account, snapshot):
    """A bounded relationship view; request message contents are not printed."""
    lines = [f"Social account {_name(account.username)}; BattleTag {_name(account.battle_tag)}."]
    used = len(lines[0].encode("utf-8")) + 1
    shown = 0
    sections = (
        ("Friends", snapshot.friends,
         lambda item: "  " + _name(item.account.username) + (" [favorite]" if item.favorite else "")),
        ("Incoming requests", snapshot.incoming,
         lambda item: "  from " + _name(item.sender.username)),
        ("Outgoing requests", snapshot.outgoing,
         lambda item: "  to " + _name(item.recipient.username)),
    )
    for label, items, render in sections:
        title = f"{label}: {len(items)}."
        lines.append(title)
        used += len(title.encode("utf-8")) + 1
        omitted = 0
        for item in items:
            row = render(item)
            size = len(row.encode("utf-8")) + 1
            # Reserve room for remaining section headings and omission counts.
            if shown == MAX_SOCIAL_DISPLAY_ROWS or used + size > MAX_SOCIAL_OUTPUT_BYTES - 512:
                omitted += 1
                continue
            lines.append(row)
            used += size
            shown += 1
        if omitted:
            notice = f"  {omitted} entries omitted (console display limit)."
            lines.append(notice)
            used += len(notice.encode("utf-8")) + 1
    return "\n".join(lines)


class Console:
    def __init__(self, store, admissions, hub, *, owner=None, extended=False, server_address=None):
        if admissions.store is not store:
            raise ValueError("console and admission manager must share one account store")
        if server_address is not None and (not callable(server_address)
                or inspect.iscoroutinefunction(server_address)
                or inspect.iscoroutinefunction(getattr(server_address, "__call__", None))):
            raise ValueError("the server address provider must be a synchronous callable")
        self.store, self.admissions, self.hub = store, admissions, hub
        self.owner = owner or "console-" + secrets.token_hex(16)
        self.extended = bool(extended)
        self.server_address = server_address
        self._synthetic = {}
        self._tell_token = 0
        self._lock = asyncio.Lock()
        self._closed = False

    async def execute(self, line):
        """Execute one command and return a safe response; cancellation propagates."""
        try:
            command, arguments = parse_command(line)
        except (ValueError, UnicodeError):
            # A malformed password/quote must not appear in an error response.
            return "Invalid command or arguments. Use .help; messages are limited to 1024 UTF-8 bytes."
        if command is None:
            return ""
        async with self._lock:
            if self._closed:
                return "Console is closed."
            try:
                return await self._execute(command, arguments)
            except AccountError as error:
                return "Error: " + str(error)[:512] + "."
            except (ValueError, UnicodeError):
                return "Invalid arguments. Use .help; message types are general, error, and announcement."
            except Exception:
                return "Command failed. Account ownership was preserved; check server diagnostics."

    @staticmethod
    def _arity(arguments, expected, command):
        if len(arguments) != expected:
            raise ValueError("invalid argument count for " + command)

    async def _synthetic_actor(self, user):
        """Resolve a live synthetic lease; never act as real or pending users."""
        account = self.store.get(user)
        lease = self.admissions.lease_for(account.username)
        if lease is None or lease.kind != "synthetic" or not self.admissions.is_current(lease):
            raise AccountError("this action requires a current synthetic player; use .login")
        actor = await self.hub.find(account.account_id)
        if (actor is None or actor.lease != lease or not actor.synthetic
                or not actor.active or not self.admissions.is_current(lease)):
            raise AccountError("this action requires a current synthetic player; use .login")
        return actor

    def _user_lease(self, account):
        try:
            lease = self.admissions.lease_for(account.username)
        except AccountNotFound:
            return None  # Deleted after this account-list snapshot was read.
        return lease if (lease is not None and lease.account == account
                         and self.admissions.is_current(lease)) else None

    async def _user_status(self, account):
        for _ in range(2):
            lease = self._user_lease(account)
            if lease is None:
                return "offline"
            if lease.kind == "pending":
                return "pending"
            actor = await self.hub.find(account.account_id)
            if not self.admissions.is_current(lease):
                continue  # Ownership changed while waiting for the hub lock.
            online = (actor is not None and actor.lease == lease and actor.active and actor.ready)
            detail = (f" ({actor.status})" if online else " (connecting)")
            if online and actor.game != "overwatch":
                detail += " | game=" + _name(GAMES[actor.game].name)
            return lease.kind + detail
        lease = self._user_lease(account)
        return ("offline" if lease is None else "pending" if lease.kind == "pending"
                else lease.kind + " (connecting)")

    async def _users(self, arguments):
        if (len(arguments) > 1 or arguments and (not arguments[0].isascii()
                or not arguments[0].isdecimal() or len(arguments[0]) > 19)):
            return "Invalid page arguments. Use .users <page> with a positive integer; no arguments: page 1."
        page = int(arguments[0]) if arguments else 1
        accounts = self.store.list()
        pages = max(1, (len(accounts) + USERS_PER_PAGE - 1) // USERS_PER_PAGE)
        if not 1 <= page <= pages:
            return f"Users: {len(accounts)} accounts; page must be 1..{pages}. Use .users <page>; no arguments: page 1."
        selected = accounts[(page - 1) * USERS_PER_PAGE:page * USERS_PER_PAGE]
        lines = [f"Users: {len(accounts)} accounts; page {page}/{pages}."]
        for account in selected:
            status = await self._user_status(account)
            lines.append(f"id={account.id} | name={_name(account.username)} | login={_name(account.login_name)}"
                         f" | BattleTag={_name(account.battle_tag)} | status={status}")
        if not accounts:
            lines.append("No accounts exist. Use .accountcreate <user> <pass>.")
        if page < pages:
            lines.append(f"Next page: .users {page + 1}")
        if page > 1:
            lines.append(f"Previous page: .users {page - 1}")
        result = "\n".join(lines)
        # Registered fields are bounded at creation. Keep that guarantee at the
        # command boundary too, without printing arbitrary Account/Lease reprs.
        if len(result.encode("utf-8")) > MAX_USERS_OUTPUT_BYTES:
            raise ValueError("account-list display exceeds the result limit")
        return result

    async def _execute(self, command, arguments):
        if command in (".serverip", ".ip"):
            if arguments:
                return "Usage: .serverip (alias: .ip); no arguments."
            if self.server_address is None:
                return "Server address is unavailable in this console."
            try:
                address = self.server_address()
                if inspect.iscoroutine(address):
                    address.close()
                address = _server_address(address)
            except Exception:
                return "Server address is unavailable; check the server or public tunnel connection."
            if address is None:
                return "Server address is unavailable; the gateway has not assigned an address."
            return "Server address: " + address
        if command == ".help":
            self._arity(arguments, 0, command)
            feature = (f".herolevel <account> <hero|all> <{DEFAULT_HERO_LEVEL}..{HERO_LEVEL_LIMIT}> "
                       "(saved levels; refreshes online hero catalogs)" if self.extended
                       else "Hero level commands are disabled; enable extended mode at server startup to use .herolevel.")
            return HELP + "\n" + feature
        if command == ".herolevel":
            if not self.extended:
                return "Hero level commands require extended mode; enable it at the server startup prompt."
            if len(arguments) != 3:
                return f"Usage: .herolevel <account> <hero|all> <{DEFAULT_HERO_LEVEL}..{HERO_LEVEL_LIMIT}>."
            user, selection, value = arguments
            if (not value.isascii() or not value.isdecimal() or len(value) > 2
                    or not DEFAULT_HERO_LEVEL <= int(value) <= HERO_LEVEL_LIMIT):
                return f"Invalid hero level. Choose {DEFAULT_HERO_LEVEL}..{HERO_LEVEL_LIMIT}."
            if selection.casefold() == "all":
                keys = tuple(hero.key for hero in HEROES)
                label = "all heroes"
            else:
                try:
                    key = normalize_menu_hero(selection)
                except ValueError:
                    return "Invalid hero. Choose a beta hero name or all."
                if key in ("random", "none"):
                    return "Invalid hero. Choose a beta hero name or all."
                keys = (key,)
                label = next(hero.name for hero in HEROES if hero.key == key)
            account = self.store.social.resolve(user)
            account = self.store.set_hero_levels(account, keys, int(value))
            await self.hub.refresh_hero_levels(account)
            return ("Hero level for " + _name(account.username) + " (" + label + ") set to "
                    + str(int(value)) + "; saved and online hero catalog refreshed.")
        if command == ".users":
            return await self._users(arguments)
        if command == ".accountcreate":
            self._arity(arguments, 2, command)
            # Hashing runs outside the socket loop. On cancellation, finish this
            # finite operation before the caller can close its SQLite store.
            work = asyncio.create_task(asyncio.to_thread(self.store.create, *arguments))
            try:
                account = await asyncio.shield(work)
            except asyncio.CancelledError:
                try:
                    await work
                except Exception:
                    pass
                raise
            await self.hub.refresh_friends()
            return ("Created account " + _name(account.username) + ". BattleTag: "
                    + _name(account.battle_tag) + ". Native login: "
                    + account.login_name + " (use the account password).")
        if command == ".accountdelete":
            self._arity(arguments, 1, command)
            account = await self.hub.delete_account(self.admissions.delete, arguments[0])
            return "Deleted offline account " + _name(account.username) + "."
        if command == ".accountportrait":
            if not arguments:
                lines = [f"Portraits: {len(PORTRAITS)} available."]
                lines.extend(f"{index} | name={json.dumps(portrait.name, ensure_ascii=False)} | GUID=0x{portrait.guid:016X}"
                             for index, portrait in enumerate(PORTRAITS, 1))
                lines.append("Set: .accountportrait <account> <portrait name|GUID|number>. Quote names containing spaces.")
                return "\n".join(lines)
            if len(arguments) < 2:
                return "Usage: .accountportrait <account> <portrait name|GUID|number>; .accountportrait lists all portraits."
            selection = " ".join(arguments[1:])
            try:
                portrait = resolve_portrait(selection)
            except ValueError:
                return "Invalid portrait. Use .accountportrait to list available names, GUIDs and numbers."
            account = self.store.social.resolve(arguments[0])
            account = await self.hub.set_portrait(self.store.set_portrait, account, portrait.guid)
            return ("Portrait for " + _name(account.username) + " set to "
                    + json.dumps(portrait.name, ensure_ascii=False)
                    + f" (0x{portrait.guid:016X}); saved and online views refreshed.")
        if command == ".accountrealname":
            self._arity(arguments, 2, command)
            account = self.store.social.resolve(arguments[0])
            name = "" if arguments[1].strip().casefold() == "--clear" else arguments[1]
            account = await self.hub.set_real_name(self.store.set_real_name, account, name)
            label = " cleared" if not account.real_name else " set to " + _name(account.real_name)
            return ("Real name for " + _name(account.username) + label
                    + "; saved and online friend views refreshed.")
        if command == ".status":
            self._arity(arguments, 2, command)
            status = arguments[1].casefold()
            if status not in PRESENCE_STATUSES:
                return "Invalid status. Use .status <account> <online|away|busy>; .logoff disconnects synthetic players."
            account = self.store.social.resolve(arguments[0])
            actor = await self.hub.find(account.account_id)
            if actor is None:
                raise AccountError("status changes require an online player")
            await self.hub.set_status(actor, status)
            return ("Status for " + _name(account.username) + " set to " + status
                    + "; online friend views refreshed (resets on reconnect).")
        if command == ".game":
            if not arguments:
                return "\n".join(["Battle.net games supported by the beta Friends tab:"]
                    + [game.slug + " | " + game.name + (" (no game)" if game.slug == "none" else "")
                       for game in GAMES.values()]
                    + ["Set: .game <account> <game>; online synthetic players only.",
                       "Invite/Join for other games does nothing. Game resets on reconnect."])
            self._arity(arguments, 2, command)
            try:
                selected = resolve_game(arguments[1])
            except ValueError:
                return "Invalid game. Use .game to list supported Battle.net games."
            account = self.store.social.resolve(arguments[0])
            actor = await self.hub.find(account.account_id)
            if actor is None:
                raise AccountError("game changes require an online synthetic player")
            await self.hub.set_game(actor, selected.slug)
            return ("Game for " + _name(account.username) + " set to " + selected.name
                    + (" (no game)" if selected.slug == "none" else "")
                    + "; online friend views refreshed (resets on reconnect).")
        if command == ".login":
            self._arity(arguments, 1, command)
            lease = self.admissions.possess(arguments[0], self.owner)
            try:
                actor = await self.hub.register(lease)
            except BaseException:
                # Registration may have reached the hub before cancellation.
                try:
                    actor = await self.hub.find(lease.account.account_id)
                    if actor is not None and actor.lease == lease:
                        await self.hub.release(actor)
                finally:
                    self.admissions.release(lease)
                raise
            self._synthetic[lease.account.id] = actor
            return "Synthetic player " + _name(lease.account.username) + " is idle in the menu."
        if command == ".logoff":
            self._arity(arguments, 1, command)
            account = self.store.get(arguments[0])
            lease = self.admissions.lease_for(arguments[0])
            if lease is None:
                return "Account " + _name(account.username) + " is offline."
            if lease.kind != "synthetic":
                return "Error: .logoff only removes synthetic players; this account has a real or pending login."
            actor = await self.hub.find(account.account_id)
            if actor is not None and actor.lease == lease:
                await self.hub.release(actor)
            self.admissions.release(lease)
            self._synthetic.pop(account.id, None)
            return "Logged off synthetic player " + _name(account.username) + "."
        if command == ".msg":
            self._arity(arguments, 3, command)
            user, kind, message = arguments
            account = self.store.get(user)
            actor = await self.hub.find(account.account_id)
            if actor is None:
                return "Account " + _name(account.username) + " is offline (0 recipients)."
            accepted = await self.hub.notify(actor, kind, message)
            return ("Accepted " + kind + " for " + _name(account.username)
                    + " (1 recipient; queued until welcome if needed)." if accepted
                    else "Message was not delivered (0 recipients).")
        if command == ".msgall":
            self._arity(arguments, 2, command)
            count = await self.hub.notify_all(*arguments)
            return f"Accepted {arguments[0]} for {count} online players (queued until welcome if needed)."
        if command == ".friends":
            self._arity(arguments, 1, command)
            account = self.store.social.resolve(arguments[0])
            return _social_listing(account, self.store.social.snapshot(account))
        if command in FRIEND_ACTIONS:
            value = None
            if FRIEND_ACTIONS[command] == "favorite":
                if len(arguments) not in (2, 3):
                    raise ValueError("invalid favorite argument count")
                option = arguments[2].casefold() if len(arguments) == 3 else "on"
                if option not in ("on", "off"):
                    raise ValueError("favorite must be on or off")
                value = option == "on"
            else:
                self._arity(arguments, 2, command)
            # These are explicit administrator actions, including for offline
            # and native accounts. Party/chat impersonation remains synthetic.
            owner = self.store.social.resolve(arguments[0])
            target = self.store.social.resolve(arguments[1])
            result = await self.hub.social_admin(FRIEND_ACTIONS[command], owner, target, value=value)
            names = _name(owner.username) + " and " + _name(target.username)
            if command == ".friendadd":
                return "Friendship established between " + names + "." if result else names + " are already friends."
            if command == ".friendrequest":
                return ("Friend request from " + _name(owner.username) + " to " + _name(target.username)
                        + " is pending; acceptance is manual.")
            if command in (".friendaccept", ".frienddecline"):
                action = "accepted" if command == ".friendaccept" else "declined"
                return ("Friend request from " + _name(target.username) + " " + action + " by "
                        + _name(owner.username) + "." if result else "No pending friend request was " + action + ".")
            if command == ".friendcancel":
                return "Outgoing friend request canceled." if result else "No outgoing friend request was canceled."
            if command == ".friendremove":
                return "Friendship removed between " + names + "." if result else "Accounts are not friends."
            return ("Favorite preference " + ("on" if value else "off") + " for " + _name(owner.username)
                    + " toward " + _name(target.username) + "." if result else "Favorite preference was not changed.")
        if command in (".partyinvite", ".partykick", ".partyleader"):
            self._arity(arguments, 2, command)
            actor = await self._synthetic_actor(arguments[0])
            target = self.store.get(arguments[1])
            if command == ".partyinvite":
                accepted = await self.hub.party_invite(actor, target.account_id, request_to_join=False)
                return ("Party invitation sent (expires after 25 seconds)." if accepted
                        else "Party invitation was not sent.")
            if command == ".partykick":
                accepted = await self.hub.party_kick(actor, target.account_id)
                return "Party member removed." if accepted else "Party member was not removed."
            accepted = await self.hub.party_promote(actor, target.account_id)
            return "Party leader changed." if accepted else "Party leader was not changed."
        if command in (".partyaccept", ".partydecline", ".partyleave"):
            self._arity(arguments, 1, command)
            actor = await self._synthetic_actor(arguments[0])
            if command == ".partyleave":
                accepted = await self.hub.party_leave(actor)
                return "Synthetic player left the party." if accepted else "Party was not left."
            accept = command == ".partyaccept"
            accepted = await self.hub.party_respond(actor, party_id=None, accept=accept)
            action = "accepted" if accept else "declined"
            return (f"Party invitation {action}." if accepted
                    else f"No valid party invitation was {action}.")
        if command == ".group":
            self._arity(arguments, 2, command)
            actor = await self._synthetic_actor(arguments[0])
            count = await self.hub.group(actor, arguments[1])
            return f"Group message delivered to {count} party members."
        if command == ".tell":
            self._arity(arguments, 3, command)
            actor = await self._synthetic_actor(arguments[0])
            target = self.store.get(arguments[1])
            if self._tell_token == MAX_TELL_TOKEN:
                return "Error: console tell token limit reached; no message was sent."
            self._tell_token += 1
            target_actor = await self.hub.find(target.account_id)
            accepted = await self.hub.tell(actor, self._tell_token, target.account_id,
                                           target_actor.game_account_id if target_actor is not None
                                           else target.game_account_id, arguments[2])
            return "Private tell delivered." if accepted else "Private tell was not delivered."
        return "Unknown command. Use .help."

    async def close(self):
        """Remove only actors this console possesses; leave native clients alone."""
        async with self._lock:
            self._closed = True
            actors, self._synthetic = tuple(self._synthetic.values()), {}
            for actor in actors:
                try:
                    await self.hub.release(actor)
                finally:
                    self.admissions.release(actor.lease)


_readers = {}
_readers_lock = threading.Lock()


class _InputReader:
    def __init__(self, stream):
        self.stream = stream
        self.condition = threading.Condition()
        self.handler = None
        self.thread = None
        self.eof = False

    def attach(self, loop, callback):
        token = object()
        with self.condition:
            if self.handler is not None:
                raise RuntimeError("console input already has an active reader")
            self.handler = (token, loop, callback)
            if self.eof:
                loop.call_soon(callback, ("eof", None))
            elif self.thread is None:
                self.thread = threading.Thread(target=self.run, name="ow08-console-input", daemon=True)
                self.thread.start()
            self.condition.notify_all()
        return token

    def detach(self, token):
        with self.condition:
            if self.handler is not None and self.handler[0] is token:
                self.handler = None
            self.condition.notify_all()

    def deliver(self, event):
        with self.condition:
            handler = self.handler
        if handler is not None:
            token, loop, callback = handler
            try:
                loop.call_soon_threadsafe(callback, event)
            except RuntimeError:
                self.detach(token)  # No calls into a closed event loop.

    def run(self):
        try:
            while True:
                with self.condition:
                    while self.handler is None:
                        self.condition.wait()
                try:
                    line = self.stream.readline(MAX_COMMAND_BYTES + 1)
                    if not isinstance(line, str):
                        raise TypeError("console input must be text")
                    if not line:
                        self.eof = True
                        self.deliver(("eof", None))
                        return
                    if len(line) > MAX_COMMAND_BYTES:
                        while line and not line.endswith("\n"):
                            line = self.stream.readline(MAX_COMMAND_BYTES + 1)
                        self.deliver(("error", "Console input exceeded the command limit; command was not executed."))
                    else:
                        self.deliver(("line", line))
                except Exception:
                    self.eof = True
                    self.deliver(("error", "Console input failed; interactive commands are unavailable."))
                    self.deliver(("eof", None))
                    return
        finally:
            with _readers_lock:
                if _readers.get(id(self.stream)) is self:
                    _readers.pop(id(self.stream))


async def read_console(console, *, stream=None, logger=print):
    """Run stdin commands until EOF/cancellation without blocking server teardown.

    A reader blocked inside the operating system is reused on a later run for
    that stream. It is daemonized and detached, with no retained event-loop
    callback, when this task stops. No executor shutdown or thread join waits
    for user input. close() remains the server owner's cleanup responsibility.
    """
    stream = sys.stdin if stream is None else stream
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue(maxsize=64)
    active = True

    def deliver(event):
        if not active:
            return
        if queue.full():
            logger("Console input queue is full; command was not executed.")
            if event[0] == "eof":
                queue.get_nowait()
            else:
                return
        queue.put_nowait(event)

    with _readers_lock:
        reader = _readers.get(id(stream))
        if reader is None:
            reader = _InputReader(stream)
            _readers[id(stream)] = reader
    token = reader.attach(loop, deliver)
    try:
        while True:
            event, value = await queue.get()
            if event == "eof":
                return
            result = await console.execute(value) if event == "line" else value
            if result:
                logger(result)
    finally:
        active = False
        reader.detach(token)
