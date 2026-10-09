"""Shared beta-menu actors and native General, tell and friend presence routes.

Account admission owns credentials and exclusive leases. This hub validates
those leases and owns lobby membership; its teardown never releases an account
lease. The menu and first yellow welcome remain the wire session's
responsibility, before calling ``mark_ready``.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
import inspect
import math
import struct
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Callable

from .accounts import AccountError, AccountInUse, InvalidAdmission
from .friends import (AUTHENTICATED_DUMMY_ACCOUNT, IN_FRIENDS, IN_FRIEND_PROFILES,
                      FRIEND_REQUEST_ALREADY_FRIENDS, FRIEND_REQUEST_INTERNAL_ERROR,
                      FRIEND_REQUEST_SELF, PRESENCE_STATUSES,
                      TELL_INTERNAL_ERROR, TELL_OFFLINE, TELL_NOT_FRIENDS, account_presence,
                      friend_portrait_update, friends_profile_state, friend_record, incoming_request_record,
                      social_friends_state, friend_operation_result, game_presence, tell_result)
from .games import DEFAULT_GAME_ACTIVITY, GameActivity, game_account_id
from .party_lobby import Parties
from .portrait import DEFAULT_PORTRAIT
from .heroes import IN_HERO_PROGRESSION, beta_hero_catalog, normalize_menu_hero
from .protocol import ProtocolError

if TYPE_CHECKING:
    from .accounts import Lease


IN_CHAT = 0xDBE61F10
IDLE_AWAY_SECONDS = 15 * 60
ZERO_ID = bytes(16)
GENERAL = struct.pack("<i", 9) + ZERO_ID
NOTICE_CHANNELS = {
    "general": GENERAL,
    "error": struct.pack("<i", 1) + ZERO_ID,
    "announcement": struct.pack("<i", 2) + ZERO_ID,
}


def _text(value, label="message", maximum=1024):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{label} must be a nonempty string without NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > maximum:
        raise ValueError(f"{label} exceeds {maximum} UTF-8 bytes")
    return encoded + b"\0"


@dataclass(frozen=True)
class Delivery:
    """A native beta packet, also retained by a synthetic actor's bounded log."""

    family: int
    offset: int
    body: bytes
    kind: str
    text: str = ""
    sender_id: bytes = ZERO_ID
    sender_name: str = ""
    channel: bytes | None = None
    view_revision: int | None = None
    invitation_nonce: bytes | None = None
    sender_actor: Actor | None = field(default=None, repr=False, compare=False)


@dataclass(eq=False)
class Actor:
    lease: Lease
    send: Callable | None = field(repr=False)
    on_send_error: Callable | None = field(default=None, repr=False)
    _channels: set = field(default_factory=lambda: {GENERAL}, repr=False)
    _pending: deque = field(default_factory=deque, repr=False)
    _messages: deque = field(default_factory=deque, repr=False)
    _delivery_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _friends_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _friend_cache: dict = field(default_factory=dict, repr=False)
    _friend_metadata: dict = field(default_factory=dict, repr=False)
    _friend_portraits: dict = field(default_factory=dict, repr=False)
    _friend_real_names: dict = field(default_factory=dict, repr=False)
    _friend_statuses: dict = field(default_factory=dict, repr=False)
    _friend_games: dict = field(default_factory=dict, repr=False)
    _request_cache: dict = field(default_factory=dict, repr=False)
    _friends_initialized: bool = False
    _party_id: bytes | None = None
    _party_revision: int = 0
    _shown_group: bytes | None = None
    _ready: bool = False
    _active: bool = True
    _presence_status: str = "online"
    _last_activity: float = field(default=0, repr=False)
    _auto_away: bool = field(default=False, repr=False)
    _activity_changed: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _idle_task: asyncio.Task | None = field(default=None, repr=False)
    _game_activity: GameActivity = DEFAULT_GAME_ACTIVITY
    _hero_selection: str = "random"

    @property
    def account_id(self):
        return self.lease.account.account_id

    @property
    def name(self):
        return self.lease.account.display_name

    @property
    def synthetic(self):
        return self.lease.kind == "synthetic"

    @property
    def channels(self):
        return frozenset(self._channels)

    @property
    def ready(self):
        return self._ready

    @property
    def active(self):
        return self._active

    @property
    def status(self):
        return self._presence_status

    @property
    def game(self):
        return self._game_activity.game

    @property
    def game_account_id(self):
        return game_account_id(self.lease.account, self.game)

    @property
    def messages(self):
        return tuple(self._messages)


class LobbyHub:
    def __init__(self, is_current: Callable, *, send_timeout=5,
                 max_pending=64, max_synthetic_messages=128, accounts=None, social=None,
                 extended=False, hero_levels=None, idle_seconds=IDLE_AWAY_SECONDS,
                 clock=time.monotonic):
        if not callable(is_current):
            raise ValueError("the lobby requires an account lease validator")
        if accounts is not None and not callable(accounts):
            raise ValueError("accounts must be a callable returning registered accounts")
        if not isinstance(extended, bool) or hero_levels is not None and not callable(hero_levels):
            raise ValueError("extended mode requires a boolean and an optional hero level reader")
        if isinstance(send_timeout, bool) or not isinstance(send_timeout, (int, float)) or not 0 < send_timeout <= 60:
            raise ValueError("send_timeout must be positive and at most 60 seconds")
        if (isinstance(idle_seconds, bool) or not isinstance(idle_seconds, (int, float))
                or not math.isfinite(idle_seconds) or idle_seconds <= 0 or not callable(clock)):
            raise ValueError("idle_seconds must be finite and positive, with a callable clock")
        for label, value in (("max_pending", max_pending),
                             ("max_synthetic_messages", max_synthetic_messages)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1024:
                raise ValueError(f"{label} must be an integer from 1 to 1024")
        self.is_current = is_current
        self.send_timeout = send_timeout
        self.idle_seconds, self.clock = idle_seconds, clock
        self.max_pending = max_pending
        self.max_synthetic_messages = max_synthetic_messages
        self.accounts = accounts
        self.social = social
        self.extended, self.hero_levels = extended, hero_levels
        self._last_online = {}
        self._last_games = {}
        self._dummy_last_online = max(0, int(time.time()) - 60)
        self._actors = {}
        self._lock = asyncio.Lock()
        self._social_publication_lock = asyncio.Lock()
        self._parties = Parties(self, Delivery)
        self._party_flush_task = None

    _chat_text = staticmethod(_text)

    def hero_catalog(self, account, selection="random"):
        """Read saved levels only when this server enables extended features."""
        levels = self.hero_levels(account) if self.extended and self.hero_levels else None
        return beta_hero_catalog(selection, extended=self.extended, levels=levels)

    async def refresh_hero_levels(self, account):
        """Publish the account's catalog through its current lobby actor."""
        if not self.extended:
            raise AccountError("hero level changes require extended mode enabled at server startup")
        actor = await self.find(account.account_id)
        if actor is None or actor._hero_selection == "none":
            return False
        return await self._deliver(actor, Delivery(
            IN_HERO_PROGRESSION, 0, self.hero_catalog(account, actor._hero_selection), "hero_catalog"))

    async def social_admin(self, action, owner, target, value=None):
        """Explicit administrative relationships; native actions check leases separately."""
        async with self._social_publication_lock:
            return await self._social_admin_locked(action, owner, target, value)

    async def _social_admin_locked(self, action, owner, target, value=None):
        if self.social is None:
            raise ValueError("social relationships require the shared account store")
        if action == "add":
            result = self.social.establish(owner, target)
        elif action == "request":
            result = self.social.request(owner, target, value or "")
        elif action in ("accept", "decline"):
            request = self.social.incoming_request(owner, target)
            result = getattr(self.social, action)(owner, request.id)
        elif action == "cancel":
            request = next((item for item in self.social.snapshot(owner).outgoing
                            if item.recipient.id == target.id), None)
            if request is None:
                from .social_store import RequestNotFound
                raise RequestNotFound("no outgoing friend request for that account")
            result = self.social.cancel(owner, request.id)
        elif action == "remove":
            result = self.social.remove(owner, target)
        elif action == "favorite":
            result = self.social.favorite(owner, target, value)
        else:
            raise ValueError("unknown social operation")
        async with self._lock:
            actor = self._actors.get(owner.account_id)
            if actor is not None and actor.ready and self.is_current(actor.lease):
                self._record_activity_locked(actor)
        await self._refresh_friends_locked()
        return result

    async def delete_account(self, delete_callback, user):
        """Serialize trusted synchronous deletion and its cascading social deltas."""
        if not callable(delete_callback) or inspect.iscoroutinefunction(delete_callback):
            raise ValueError("account deletion requires a synchronous callback")
        async with self._social_publication_lock:
            result = delete_callback(user)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise ValueError("account deletion requires a synchronous callback")
            await self._refresh_friends_locked()
            return result

    async def set_portrait(self, update_callback, user, portrait_guid):
        """Save an administrative portrait change and publish its current views."""
        if not callable(update_callback) or inspect.iscoroutinefunction(update_callback):
            raise ValueError("portrait changes require a synchronous callback")
        async with self._social_publication_lock:
            account = update_callback(user, portrait_guid)
            if inspect.isawaitable(account):
                if inspect.iscoroutine(account):
                    account.close()
                raise ValueError("portrait changes require a synchronous callback")
            await self._parties.refresh_portrait(account.account_id)
            await self._refresh_friends_locked()
            return account

    async def set_real_name(self, update_callback, user, real_name):
        """Serialize a saved Real ID label and its incremental friend presence."""
        if not callable(update_callback) or inspect.iscoroutinefunction(update_callback):
            raise ValueError("real name changes require a synchronous callback")
        async with self._social_publication_lock:
            account = update_callback(user, real_name)
            if inspect.isawaitable(account):
                if inspect.iscoroutine(account):
                    account.close()
                raise ValueError("real name changes require a synchronous callback")
            await self._refresh_friends_locked()
            return account

    async def set_status(self, actor, status):
        """Change an admitted online actor's transient native friend status."""
        if not isinstance(status, str) or status not in PRESENCE_STATUSES:
            raise ValueError("status must be online, away, or busy")
        async with self._social_publication_lock:
            async with self._lock:
                self._check_locked(actor)
                if not actor.ready:
                    raise AccountError("status changes require an online player")
                actor._presence_status = status
                actor._auto_away = False
                self._record_activity_locked(actor)
            await self._refresh_friends_locked()
            return status

    def _record_activity_locked(self, actor):
        actor._last_activity = self.clock()
        actor._activity_changed.set()
        # Explicit Away and Busy are independent of automatic idleness.
        changed = actor._auto_away and actor.status == "away"
        if changed:
            actor._presence_status = "online"
        actor._auto_away = False
        return changed

    async def record_activity(self, actor):
        """Record a player action, restoring only automatically selected Away."""
        async with self._social_publication_lock:
            async with self._lock:
                self._check_locked(actor)
                changed = self._record_activity_locked(actor)
            if changed:
                await self._refresh_friends_locked()
            return changed

    def _start_idle_locked(self, actor):
        self._record_activity_locked(actor)
        actor._idle_task = asyncio.create_task(self._watch_idle(actor))

    async def _watch_idle(self, actor):
        while True:
            async with self._lock:
                if (not actor.active or not actor.ready
                        or self._actors.get(actor.account_id) is not actor
                        or not self.is_current(actor.lease)):
                    return
                actor._activity_changed.clear()
                online = actor.status == "online"
                remaining = self.idle_seconds - (self.clock() - actor._last_activity)
            if not online:
                await actor._activity_changed.wait()
            else:
                try:
                    await asyncio.wait_for(actor._activity_changed.wait(), max(0.001, remaining))
                except TimeoutError:
                    await self._expire_idle(actor)

    async def _expire_idle(self, actor):
        """Recheck status, activity and admission after waiting for publication."""
        async with self._social_publication_lock:
            async with self._lock:
                if (not actor.active or not actor.ready
                        or self._actors.get(actor.account_id) is not actor
                        or not self.is_current(actor.lease)
                        or actor.status != "online"
                        or self.clock() - actor._last_activity <= self.idle_seconds):
                    return False
                actor._presence_status = "away"
                actor._auto_away = True
            await self._refresh_friends_locked()
            return True

    async def set_game(self, actor, game):
        """Advertise a synthetic player's game without changing its login lease."""
        selected = GameActivity(game)
        async with self._social_publication_lock:
            async with self._parties.events:
                async with self._lock:
                    self._check_locked(actor)
                    if not actor.synthetic or not actor.ready:
                        raise AccountError("game changes require an online synthetic player")
                    self._record_activity_locked(actor)
                    if actor._game_activity != selected and selected.game != "overwatch":
                        self._parties._cancel_actor(actor)
                        if len(self._parties._party(actor).members) > 1:
                            self._parties._detach(actor)
                    actor._game_activity = selected
                await self._parties._publish()
            await self._refresh_friends_locked()
            return selected

    async def social_request(self, actor, request):
        """Authorize one beta Social operation against the current session owner."""
        await self.record_activity(actor)
        async with self._social_publication_lock:
            success, resource, error_text = await self._social_request_locked(actor, request)
        offset, body = friend_operation_result(request.action, request.token,
                                               success=success, error_resource=resource)
        await self._deliver(actor, Delivery(IN_FRIENDS, offset, body, "social_result"))
        if not success and request.action == "favorite":
            await self.notify(actor, "error", "Unable to update favorite: " + error_text)
        return success

    async def _social_request_locked(self, actor, request):
        # A native operation may have waited behind another publication. Its
        # original actor must still own the lease when the mutation begins.
        async with self._lock:
            self._check_locked(actor)
        owner = actor.lease.account
        success, resource = True, None
        error_text = None
        try:
            if self.social is None:
                raise AccountError("social relationships require the shared account store")
            if request.action == "request":
                kind = {2: "email", 1: "battletag"}.get(request.target_type)
                if kind is None:
                    raise AccountError("unsupported friend target type")
                target = self.social.resolve(request.target, kind=kind)
                if target.id == owner.id:
                    resource = FRIEND_REQUEST_SELF
                self.social.request(owner, target, request.message)
            elif request.action in ("accept", "decline"):
                pending = self.social.incoming_request(owner, request.target)
                if request.action == "accept":
                    self.social.accept(owner, pending.id)
                else:
                    self.social.decline(owner, pending.id)
            elif request.action == "remove":
                self.social.remove(owner, request.target)
            elif request.action == "favorite":
                if request.metadata & ~1:
                    raise AccountError("unsupported friend metadata bits")
                self.social.favorite(owner, request.target, bool(request.metadata & 1))
            else:
                raise AccountError("unsupported social operation")
        except AccountError as error:
            success = False
            error_text = str(error)
            # These localized resources are confirmed by the beta's own
            # Add Friend completion handler, never taken from later builds.
            if request.action == "request":
                from .social_store import AlreadyFriends
                resource = (FRIEND_REQUEST_ALREADY_FRIENDS if isinstance(error, AlreadyFriends)
                            else resource or FRIEND_REQUEST_INTERNAL_ERROR)
        if success:
            await self._refresh_friends_locked()
        return success, resource, error_text

    def _check_locked(self, actor):
        if (not actor._active or self._actors.get(actor.account_id) is not actor
                or not self.is_current(actor.lease)):
            raise InvalidAdmission("the actor no longer owns an admitted account lease")

    def _remove_locked(self, actor):
        if self._actors.get(actor.account_id) is not actor:
            return False
        self._parties.remove_locked(actor)
        del self._actors[actor.account_id]
        self._last_online[actor.account_id] = max(0, int(time.time()))
        self._last_games[actor.account_id] = actor._game_activity
        actor._active = False
        actor._activity_changed.set()
        actor._channels.clear()
        actor._pending.clear()
        return True

    async def register(self, lease, send=None, *, on_send_error=None, hero_selection="random"):
        """Register an existing real/synthetic lease; pending leases are rejected."""
        if lease.kind not in ("real", "synthetic"):
            raise InvalidAdmission("a pending admission cannot enter the menu lobby")
        if not isinstance(lease.account.account_id, bytes) or len(lease.account.account_id) != 16:
            raise ValueError("an account identity must contain exactly 16 bytes")
        _text(lease.account.display_name, "account display name", 64)
        if lease.kind == "real" and not callable(send):
            raise ValueError("a real actor requires an asynchronous packet sender")
        if lease.kind == "synthetic" and send is not None:
            raise ValueError("a synthetic actor has no packet transport")
        if on_send_error is not None and not callable(on_send_error):
            raise ValueError("on_send_error must be callable")
        actor = Actor(lease, send, on_send_error,
                      _messages=deque(maxlen=self.max_synthetic_messages),
                      _ready=lease.kind == "synthetic",
                      _hero_selection=normalize_menu_hero(hero_selection))
        async with self._lock:
            if not self.is_current(lease):
                raise InvalidAdmission("the account lease is no longer current")
            previous = self._actors.get(actor.account_id)
            if previous is not None:
                if self.is_current(previous.lease):
                    raise AccountInUse("the account already has a lobby actor")
                self._remove_locked(previous)
            self._actors[actor.account_id] = actor
            self._parties.register_locked(actor)
            if actor.ready:
                self._start_idle_locked(actor)
        await self._parties.flush()
        if actor.ready:
            await self.refresh_friends()
        return actor

    async def release(self, actor):
        """Remove this exact actor, without changing its account admission lease."""
        async with self._lock:
            removed = self._remove_locked(actor)
        await self._parties.flush()
        # A transport failure may already have removed this actor. Refreshing
        # here also publishes that failure when the session closes its lease.
        await self.refresh_friends()
        return removed

    async def actors(self):
        async with self._lock:
            return tuple(actor for actor in self._actors.values()
                         if actor._active and self.is_current(actor.lease))

    async def find(self, account_id):
        async with self._lock:
            actor = self._actors.get(account_id)
            return actor if actor is not None and self.is_current(actor.lease) else None

    async def join_general(self, actor):
        """Membership only: the caller sends the native join/snapshot response."""
        await self.record_activity(actor)
        async with self._lock:
            self._check_locked(actor)
            joined = GENERAL not in actor._channels
            actor._channels.add(GENERAL)
            return joined

    async def leave_general(self, actor):
        await self.record_activity(actor)
        async with self._lock:
            self._check_locked(actor)
            joined = GENERAL in actor._channels
            actor._channels.discard(GENERAL)
            # Do not deliver deferred channel traffic after its owner leaves.
            actor._pending = deque(delivery for delivery in actor._pending
                                   if delivery.channel != GENERAL)
            return joined

    async def mark_ready(self, actor):
        """Call only after the exact welcome packet has been sent successfully.

        The per-actor delivery lock makes queued messages precede any concurrent
        new delivery. No wire callback runs while the membership lock is held.
        """
        async with actor._delivery_lock:
            async with self._lock:
                self._check_locked(actor)
                if actor._ready:
                    return 0
                actor._ready = True
                self._start_idle_locked(actor)
                pending = tuple(actor._pending)
                actor._pending.clear()
            count = 0
            for delivery in pending:
                if not await self._emit(actor, delivery):
                    if not actor.active:
                        break
                    continue
                count += 1
        await self.refresh_friends()
        return count

    def _registered_accounts(self):
        return tuple(self.accounts()) if self.accounts is not None else ()

    def _profile_account(self, actor):
        """Read mutable profile data without replacing the actor's identity lease."""
        return next((account for account in self._registered_accounts()
                     if account.account_id == actor.account_id), actor.lease.account)

    async def _friends_snapshot(self, actor):
        async with self._lock:
            self._check_locked(actor)
        snapshot = (self.social.snapshot(actor.lease.account) if self.social is not None else
                    SimpleNamespace(owner=actor.lease.account, friends=(), incoming=(), outgoing=()))
        peers = tuple(relation.account for relation in snapshot.friends)
        async with self._lock:
            self._check_locked(actor)
            statuses = {member.account_id: member.status for member in self._actors.values()
                        if member._ready and member._active and self.is_current(member.lease)}
            games = dict(self._last_games)
            games.update({member.account_id: member._game_activity for member in self._actors.values()
                          if member.account_id in statuses})
            online = frozenset(statuses)
            fallback = max(0, int(time.time()) - 60)
            for account in peers:
                self._last_online.setdefault(account.account_id, fallback)
            seen = dict(self._last_online)
        records = {account.account_id: account_presence(
            account, online=account.account_id in online,
            last_online=seen[account.account_id],
            status=statuses.get(account.account_id, "online"),
            game_activity=games.get(account.account_id, DEFAULT_GAME_ACTIVITY)) for account in peers}
        return snapshot, peers, online, seen, records, statuses, games

    @staticmethod
    def _remember_friends(actor, snapshot, records, statuses, games):
        actor._friend_cache = records
        actor._friend_metadata = {relation.account.account_id: friend_record(relation)
                                  for relation in snapshot.friends}
        actor._friend_portraits = {relation.account.account_id:
                                  getattr(relation.account, "portrait_guid", DEFAULT_PORTRAIT)
                                  for relation in snapshot.friends}
        actor._friend_real_names = {relation.account.account_id:
                                   getattr(relation.account, "real_name", "")
                                   for relation in snapshot.friends}
        actor._friend_statuses = {relation.account.account_id:
                                 statuses.get(relation.account.account_id, "online")
                                 for relation in snapshot.friends}
        actor._friend_games = {relation.account.account_id:
                              games.get(relation.account.account_id, DEFAULT_GAME_ACTIVITY)
                              for relation in snapshot.friends}
        actor._request_cache = {request.sender.account_id: incoming_request_record(request)
                                for request in snapshot.incoming}
        actor._friends_initialized = True

    async def friends_body(self, actor):
        """Initial27100 body containing only this account's stored relationships.

        Send this body in the menu initialization sequence before mark_ready.
        Later refreshes use beta incremental messages and preserve pending tells.
        """
        if self.accounts is None:
            raise ValueError("registered friend presence requires an accounts provider")
        async with self._social_publication_lock:
            async with actor._friends_lock:
                snapshot, _, online, seen, records, statuses, games = await self._friends_snapshot(actor)
                body = social_friends_state(snapshot, online=online, last_online=seen, statuses=statuses, games=games)
                self._remember_friends(actor, snapshot, records, statuses, games)
                return body

    async def friends_profiles_body(self, actor):
        async with self._social_publication_lock:
            async with actor._friends_lock:
                _, peers, _, _, _, _, _ = await self._friends_snapshot(actor)
                return friends_profile_state(peers)

    async def initialize_friends(self, actor, send):
        """Send both initial social baselines before committing their shared cache."""
        if not callable(send):
            raise ValueError("initial social state requires an asynchronous packet sender")
        if self.accounts is None:
            raise ValueError("registered friend presence requires an accounts provider")
        async with self._social_publication_lock:
            async with actor._friends_lock:
                snapshot, peers, online, seen, records, statuses, games = await self._friends_snapshot(actor)
                body = social_friends_state(snapshot, online=online, last_online=seen, statuses=statuses, games=games)
                profiles = friends_profile_state(peers)
                async with actor._delivery_lock:
                    async with self._lock:
                        self._check_locked(actor)
                    await asyncio.wait_for(send(IN_FRIENDS, 0, body), self.send_timeout)
                    async with self._lock:
                        self._check_locked(actor)
                    await asyncio.wait_for(send(IN_FRIEND_PROFILES, 0, profiles), self.send_timeout)
                    async with self._lock:
                        self._check_locked(actor)
                    self._remember_friends(actor, snapshot, records, statuses, games)
                return 2

    async def _refresh_actor_friends(self, actor):
        async with actor._friends_lock:
            try:
                snapshot, peers, online, seen, records, statuses, games = await self._friends_snapshot(actor)
            except InvalidAdmission:
                return 0
            deliveries = []
            if not actor._friends_initialized:
                body = social_friends_state(snapshot, online=online, last_online=seen, statuses=statuses, games=games)
                deliveries.append(Delivery(IN_FRIENDS, 0, body, "friends"))
                deliveries.append(Delivery(IN_FRIEND_PROFILES, 0,
                    friends_profile_state(peers), "friend_profiles"))
            else:
                previous = actor._friend_cache
                # The native manager requires a roster root before its presence
                # child can be attached. Removal takes only the root identity.
                for identity in previous.keys() - records.keys():
                    deliveries.append(Delivery(IN_FRIENDS, 2, identity, "friend_removed"))
                requests = {request.sender.account_id: incoming_request_record(request)
                            for request in snapshot.incoming}
                for identity in actor._request_cache.keys() - requests.keys():
                    deliveries.append(Delivery(IN_FRIENDS, 4, identity, "friend_request_removed"))
                for relation in snapshot.friends:
                    identity = relation.account.account_id
                    metadata = friend_record(relation)
                    if identity not in previous:
                        deliveries.append(Delivery(IN_FRIENDS, 1, metadata,
                                                   "friend_added"))
                    elif actor._friend_metadata.get(identity) != metadata:
                        deliveries.append(Delivery(IN_FRIENDS, 5, metadata, "friend_metadata"))
                for identity, record in requests.items():
                    if actor._request_cache.get(identity) != record:
                        deliveries.append(Delivery(IN_FRIENDS, 3, record, "friend_request"))
                changed = []
                changed_count = 0
                for account in peers:
                    identity = account.account_id
                    record = records[identity]
                    if previous.get(identity) == record:
                        continue
                    remove_name = bool(actor._friend_real_names.get(identity)
                                       and not getattr(account, "real_name", ""))
                    status = statuses.get(identity, "online")
                    reset_status = (actor._friend_statuses.get(identity, "online") != "online"
                                    and status == "online")
                    game = games.get(identity, DEFAULT_GAME_ACTIVITY)
                    old_game = actor._friend_games.get(identity, DEFAULT_GAME_ACTIVITY)
                    switched = identity in previous and old_game.game != game.game
                    if switched:
                        # C15800 prefers an online Overwatch child. Retire the
                        # old child first so it cannot mask the selected game.
                        changed.append(game_presence(account, online=False, reset_status=True,
                                                     game_activity=old_game))
                        changed_count += 1
                    if remove_name or reset_status or switched:
                        # Omission leaves native cache keys intact. Clearing a
                        # previously shown Real ID label needs operation1.
                        record = account_presence(account, online=identity in online,
                            last_online=seen[identity], remove_real_name=remove_name,
                            status=status, reset_status=reset_status or switched,
                            game_activity=game)
                    changed.append(record)
                    changed_count += 2
                if changed:
                    deliveries.append(Delivery(IN_FRIENDS, 9,
                        struct.pack("<I", changed_count) + b"".join(changed), "presence"))
                if previous.keys() != records.keys():
                    deliveries.append(Delivery(IN_FRIEND_PROFILES, 0,
                        friends_profile_state(peers), "friend_profiles"))
                else:
                    for account in peers:
                        portrait_guid = getattr(account, "portrait_guid", DEFAULT_PORTRAIT)
                        if actor._friend_portraits.get(account.account_id) != portrait_guid:
                            deliveries.append(Delivery(IN_FRIEND_PROFILES, 4,
                                friend_portrait_update(account.account_id, portrait_guid=portrait_guid),
                                "friend_portrait"))
            sent = 0
            for delivery in deliveries:
                if not await self._deliver(actor, delivery):
                    return sent
                sent += 1
            self._remember_friends(actor, snapshot, records, statuses, games)
            return sent

    async def refresh_friends(self):
        """Publish explicit social changes and friends' real/synthetic presence.

        Call after changing the registry. Actor readiness and normal release also
        call this automatically. Each actor gets a serialized incremental view.
        """
        async with self._social_publication_lock:
            return await self._refresh_friends_locked()

    async def _refresh_friends_locked(self):
        """Caller owns publication across mutation, snapshot, sends and cache commit."""
        if self.accounts is None:
            return 0
        recipients = tuple(actor for actor in await self.actors() if actor.ready)
        counts = await asyncio.gather(*(self._refresh_actor_friends(actor)
                                      for actor in recipients))
        return sum(counts)

    async def tell(self, actor, token, target_account_id, target_game_id, message):
        """27004 targets two recipient IDs; sender identity comes from its lease."""
        encoded = _text(message)
        # Validate the request before refreshing or sending any partial action.
        tell_result(token)
        for identity in (target_account_id, target_game_id):
            if not isinstance(identity, bytes) or len(identity) != 16:
                raise ValueError("a tell target identity must contain exactly 16 bytes")
        await self.record_activity(actor)
        await self.refresh_friends()
        registered = {account.account_id: account for account in self._registered_accounts()}
        async with self._lock:
            self._check_locked(actor)
            target = self._actors.get(target_account_id)
            account = registered.get(target_account_id)
            if self.accounts is None and target is not None:
                account = target.lease.account
            expected_games = ()
            if account is not None:
                if target is not None:
                    expected_games = (target.game_account_id,)
                else:
                    last_game = self._last_games.get(target_account_id, DEFAULT_GAME_ACTIVITY)
                    expected_games = (account.game_account_id, game_account_id(account, last_game.game))
            if target_account_id == AUTHENTICATED_DUMMY_ACCOUNT:
                failure = TELL_OFFLINE
            elif (account is None or target_account_id == actor.account_id
                  or target_game_id not in expected_games):
                failure = TELL_INTERNAL_ERROR
            elif not self._tell_friends(actor, account):
                failure = TELL_NOT_FRIENDS
            elif (target is None or not target._ready or not target._active
                  or not self.is_current(target.lease)):
                failure = TELL_OFFLINE
            else:
                failure = None
        if failure is None:
            received = Delivery(IN_FRIENDS, 13, actor.account_id + encoded,
                                "tell_received", message, actor.account_id, actor.name,
                                sender_actor=actor)
            if not await self._deliver(target, received):
                async with self._lock:
                    try:
                        self._check_locked(actor)
                    except InvalidAdmission:
                        return False
                    failure = (TELL_OFFLINE if self._tell_friends(actor, account)
                               else TELL_NOT_FRIENDS)
        # The native send action already appends its outgoing tell locally.
        # 27114 renders another sent line, so ordinary requests only complete
        # the pending operation after delivering 27113 to the recipient.
        offset, body = tell_result(token, failure, 1 if failure == TELL_INTERNAL_ERROR else 0)
        await self._deliver(actor, Delivery(IN_FRIENDS, offset, body, "tell_result"))
        return failure is None

    def _tell_friends(self, actor, target_account):
        if self.social is None:
            return True
        try:
            return self.social.are_friends(actor.lease.account, target_account)
        except AccountError:
            return False

    def _current_tell_locked(self, actor, delivery):
        source = delivery.sender_actor
        if source is None:
            return False
        try:
            self._check_locked(actor)
            self._check_locked(source)
        except InvalidAdmission:
            return False
        return self._tell_friends(source, actor.lease.account)

    async def general(self, actor, message):
        """Broadcast trusted sender identity only to current General members."""
        encoded = _text(message)
        await self.record_activity(actor)
        async with self._lock:
            self._check_locked(actor)
            if GENERAL not in actor._channels:
                raise ProtocolError("the sender is not a member of General")
            recipients = tuple(member for member in self._actors.values()
                               if GENERAL in member._channels and self.is_current(member.lease))
            # The native chat cache retains this full tag for context-menu
            # friend requests; C7B700 strips its suffix for the visible name.
            delivery = Delivery(IN_CHAT, 0, GENERAL
                                + _text(actor.lease.account.battle_tag, "sender BattleTag", 128)
                                + actor.account_id + encoded, "chat", message,
                                actor.account_id, actor.name, GENERAL)
        # Send to the sender as well: the beta suppresses its own authenticated
        # ID and already displays a local echo. Never spoof that identity.
        results = await asyncio.gather(*(self._deliver(member, delivery) for member in recipients))
        return sum(results)

    async def party_view(self, actor):
        return await self._parties.view(actor)

    async def party_refresh(self, actor):
        return await self._parties.refresh(actor)

    async def party_invite(self, actor, target_root, request_to_join=False):
        await self.record_activity(actor)
        return await self._parties.invite(actor, target_root, request_to_join)

    async def party_respond(self, actor, party_id=None, accept=True):
        await self.record_activity(actor)
        return await self._parties.respond(actor, party_id, accept=accept)

    async def party_leave(self, actor):
        await self.record_activity(actor)
        return await self._parties.leave(actor)

    async def party_kick(self, actor, target_root):
        await self.record_activity(actor)
        return await self._parties.member_action(actor, target_root)

    async def party_promote(self, actor, target_root):
        await self.record_activity(actor)
        return await self._parties.member_action(actor, target_root, promote=True)

    async def group(self, actor, message):
        _text(message)
        await self.record_activity(actor)
        return await self._parties.group(actor, message)

    async def who(self, actor, channel=GENERAL):
        await self.record_activity(actor)
        if channel != GENERAL:
            return await self._parties.members(actor, channel)
        async with self._lock:
            self._check_locked(actor)
            if GENERAL not in actor._channels:
                raise ProtocolError("the requester is not a member of General")
            members = tuple(member for member in self._actors.values()
                            if GENERAL in member._channels and self.is_current(member.lease))
            body = GENERAL + struct.pack("<I", len(members))
            body += b"".join(_text(member.lease.account.battle_tag, "member BattleTag", 128)
                             + member.account_id for member in members)
        return await self._deliver(actor, Delivery(IN_CHAT, 1, body, "members", channel=GENERAL))

    async def notify(self, actor, kind, message):
        delivery = self._notice(kind, message)
        async with self._lock:
            self._check_locked(actor)
        return await self._deliver(actor, delivery)

    async def notify_all(self, kind, message):
        delivery = self._notice(kind, message)
        recipients = await self.actors()
        results = await asyncio.gather(*(self._deliver(actor, delivery) for actor in recipients))
        return sum(results)

    @staticmethod
    def _notice(kind, message):
        if kind not in NOTICE_CHANNELS:
            raise ValueError("message type must be general, error, or announcement")
        encoded = _text(message)
        channel = NOTICE_CHANNELS[kind]
        return Delivery(IN_CHAT, 0, channel + b"\0" + ZERO_ID + encoded,
                        kind, message, channel=channel)

    async def _failed(self, actor, error):
        async with self._lock:
            removed = self._remove_locked(actor)
        if removed and (self._party_flush_task is None or self._party_flush_task.done()):
            # A failure can happen inside party publication. Flush on another
            # task so that cleanup never recursively acquires its event lock.
            self._party_flush_task = asyncio.create_task(self._parties.flush())
        if removed and actor.on_send_error is not None:
            try:
                result = actor.on_send_error(error)
                if inspect.isawaitable(result):
                    await asyncio.wait_for(result, self.send_timeout)
            except Exception:
                # Failure callbacks are cleanup, not a reason to interrupt
                # delivery to the rest of the hub.
                pass

    async def _emit(self, actor, delivery):
        async with self._lock:
            if (not actor._active or self._actors.get(actor.account_id) is not actor
                    or not self.is_current(actor.lease)):
                return False
            if delivery.kind in ("chat", "members") and delivery.channel not in actor._channels:
                return False
            if delivery.view_revision is not None and delivery.view_revision != actor._party_revision:
                return False
            if not self._current_invitation_locked(actor, delivery):
                return False
            if delivery.kind == "tell_received" and not self._current_tell_locked(actor, delivery):
                return False
        if actor.synthetic:
            actor._messages.append(delivery)
            self._emitted_party_channel(actor, delivery)
            return True

        async def send():
            if delivery.kind == "tell_received":
                # wait_for schedules this coroutine separately. Recheck there
                # too, before invoking the transport, without a lock held
                # across the asynchronous sender callback.
                async with self._lock:
                    if not self._current_tell_locked(actor, delivery):
                        return False
            await actor.send(delivery.family, delivery.offset, delivery.body)
            return True

        try:
            if not await asyncio.wait_for(send(), self.send_timeout):
                return False
            self._emitted_party_channel(actor, delivery)
            return True
        except Exception as error:
            await self._failed(actor, error)
            return False

    @staticmethod
    def _emitted_party_channel(actor, delivery):
        # Queuing a pre-welcome join does not mean the client has seen it.
        if delivery.kind == "party_view" and delivery.family == IN_CHAT:
            if delivery.offset == 2:
                actor._shown_group = delivery.body[1:]
            elif delivery.offset == 6 and actor._shown_group == delivery.body:
                actor._shown_group = None

    def _current_invitation_locked(self, actor, delivery):
        if delivery.invitation_nonce is None:
            return True
        invitation = self._parties.invitations.get(actor)
        return (invitation is not None and invitation.nonce == delivery.invitation_nonce
                and self._parties._valid(invitation))

    async def _deliver(self, actor, delivery):
        async with actor._delivery_lock:
            async with self._lock:
                if (not actor._active or self._actors.get(actor.account_id) is not actor
                        or not self.is_current(actor.lease)):
                    return False
                if delivery.kind in ("chat", "members") and delivery.channel not in actor._channels:
                    return False
                if delivery.view_revision is not None and delivery.view_revision != actor._party_revision:
                    return False
                if not self._current_invitation_locked(actor, delivery):
                    return False
                if not actor._ready and not (delivery.kind == "party_view" and delivery.family != IN_CHAT):
                    if delivery.kind in ("party_view", "hero_catalog"):
                        actor._pending = deque(item for item in actor._pending
                            if (item.kind, item.family, item.offset) !=
                               (delivery.kind, delivery.family, delivery.offset))
                    if len(actor._pending) < self.max_pending:
                        actor._pending.append(delivery)
                        return True
                    overflow = True
                else:
                    overflow = False
            if overflow:
                await self._failed(actor, ProtocolError("the pre-welcome lobby message queue is full"))
                return False
            return await self._emit(actor, delivery)
