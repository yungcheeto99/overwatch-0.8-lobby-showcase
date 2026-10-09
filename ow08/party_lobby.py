"""Shared, consent-based menu parties; no match allocation or handoff."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import secrets
import struct
import time

from .party import (IN_PARTY, PARTY_INVITATION_SECONDS, invitation_body,
                    party_state, player_party_record)

IN_PLAYER = 0x912CEA67
IN_CHAT = 0xDBE61F10


@dataclass(eq=False)
class Party:
    identity: bytes
    members: list
    leader: object

    @property
    def channel(self):
        return struct.pack('<i', 4) + self.identity


@dataclass(eq=False)
class Invitation:
    inviter: object
    recipient: object
    party: Party
    deadline: float
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    timer: asyncio.Task | None = None


class Parties:
    """Mutations use the hub lock; publications serialize on ``events``.

    Actor object identity binds invitations to one admission generation. A
    reconnect cannot accept another connection's old invitation. Wire callbacks
    never execute under the membership lock.
    """
    def __init__(self, hub, delivery, *, clock=time.monotonic,
                 invitation_seconds=PARTY_INVITATION_SECONDS):
        self.hub, self.delivery = hub, delivery
        self.clock, self.invitation_seconds = clock, invitation_seconds
        self.events = asyncio.Lock()
        self.parties = {}
        self.invitations = {}
        self.dirty = set()
        self.clears = []

    def register_locked(self, actor):
        identity = secrets.token_bytes(16)
        while identity == bytes(16) or identity in self.parties:
            identity = secrets.token_bytes(16)
        party = Party(identity, [actor], actor)
        self.parties[identity] = party
        actor._party_id = identity

    def _party(self, actor):
        return self.parties[actor._party_id]

    def _change(self, party):
        for actor in party.members:
            # Remove every former group channel before granting this one.
            actor._channels = {channel for channel in actor._channels
                               if channel[:4] != struct.pack('<i', 4)}
            if len(party.members) > 1:
                actor._channels.add(party.channel)
            actor._party_revision += 1
            self.dirty.add(actor)

    def _cancel(self, invitation):
        if self.invitations.get(invitation.recipient) is not invitation:
            return
        del self.invitations[invitation.recipient]
        if invitation.timer and invitation.timer is not asyncio.current_task():
            invitation.timer.cancel()
        self.clears.append((invitation.recipient, invitation.party.identity))

    def _cancel_actor(self, actor):
        for invitation in tuple(self.invitations.values()):
            if invitation.inviter is actor or invitation.recipient is actor:
                self._cancel(invitation)

    def remove_locked(self, actor):
        self._cancel_actor(actor)
        party = self.parties.get(actor._party_id)
        if party is None or actor not in party.members:
            return
        party.members.remove(actor)
        actor._party_id = None
        actor._party_revision += 1
        self.dirty.discard(actor)
        if party.members:
            if party.leader is actor:
                party.leader = party.members[0]
            self._change(party)
        else:
            del self.parties[party.identity]

    def _detach(self, actor):
        self.remove_locked(actor)
        self.register_locked(actor)
        self._change(self._party(actor))

    def _valid(self, invitation):
        return (invitation.deadline > self.clock()
                and self.invitations.get(invitation.recipient) is invitation
                and self.parties.get(invitation.party.identity) is invitation.party
                and invitation.party.leader is invitation.inviter
                and invitation.inviter._active and invitation.recipient._active
                and invitation.inviter.game == "overwatch" and invitation.recipient.game == "overwatch"
                and self.hub.is_current(invitation.inviter.lease)
                and self.hub.is_current(invitation.recipient.lease))

    async def view(self, actor):
        async with self.hub._lock:
            self.hub._check_locked(actor)
            party = self._party(actor)
            accounts = [self.hub._profile_account(member) for member in party.members]
            return (party.identity, player_party_record(actor.lease.account, party.identity),
                    party_state(party.identity, accounts, party.leader.account_id))

    async def refresh(self, actor):
        """Serialize a menu refresh with membership changes, never replay solo."""
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                self.dirty.add(actor)
            await self._publish()

    async def refresh_portrait(self, account_id):
        """Publish the current portrait while preserving party membership and leases."""
        async with self.events:
            async with self.hub._lock:
                actor = self.hub._actors.get(account_id)
                if actor is None or not actor._active or not self.hub.is_current(actor.lease):
                    return
                self._change(self._party(actor))
            await self._publish()

    async def _publish(self):
        # A failed transport can dirty another member's view during publication.
        while True:
            async with self.hub._lock:
                clears, self.clears = self.clears, []
                actors, self.dirty = tuple(self.dirty), set()
                views = []
                for actor in actors:
                    if not actor._active or not self.hub.is_current(actor.lease):
                        continue
                    party = self._party(actor)
                    group = party.channel if len(party.members) > 1 else None
                    accounts = [self.hub._profile_account(member) for member in party.members]
                    views.append((actor, actor._party_revision, group,
                        player_party_record(actor.lease.account, party.identity),
                        party_state(party.identity, accounts, party.leader.account_id)))
            if not clears and not views:
                return
            for actor, identity in clears:
                await self.hub._deliver(actor, self.delivery(IN_PARTY, 3, identity, 'invitation_clear'))
            for actor, revision, group, player, state in views:
                old = actor._shown_group
                if old is not None and old != group:
                    await self.hub._deliver(actor, self.delivery(IN_CHAT, 6, old, 'party_view',
                                                                 view_revision=revision))
                for family, body in ((IN_PLAYER, player), (IN_PARTY, state)):
                    await self.hub._deliver(actor, self.delivery(family, 1 if family == IN_PLAYER else 0,
                        body, 'party_view', view_revision=revision))
                if group is not None and actor._shown_group != group:
                    await self.hub._deliver(actor, self.delivery(IN_CHAT, 2, b'\0' + group,
                        'party_view', view_revision=revision))

    async def flush(self):
        async with self.events:
            await self._publish()

    async def _expire(self, invitation):
        try:
            await asyncio.sleep(max(0, invitation.deadline - self.clock()))
            async with self.events:
                async with self.hub._lock:
                    self._cancel(invitation)
                await self._publish()
        except asyncio.CancelledError:
            pass

    async def invite(self, actor, target_id, request_to_join=False):
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                target = self.hub._actors.get(target_id)
                if actor.game != "overwatch" or target is not None and target.game != "overwatch":
                    # Other games are Social presence only. Native Invite/Join
                    # must not create a party request or even a notice.
                    return False
                if (target is None or target is actor or not target.ready
                        or not self.hub.is_current(target.lease)):
                    error = 'That player is not available for a party invitation.'
                elif self._party(target) is self._party(actor):
                    error = 'That player is already in your party.'
                elif request_to_join:
                    leader = self._party(target).leader
                    error = None
                elif self._party(actor).leader is not actor:
                    error = 'Only the party leader can invite players.'
                elif len(self._party(actor).members) >= 6:
                    error = 'The party is full.'
                else:
                    party = self._party(actor)
                    old = self.invitations.get(target)
                    if old:
                        self._cancel(old)
                    invitation = Invitation(actor, target, party, self.clock() + self.invitation_seconds)
                    self.invitations[target] = invitation
                    invitation.timer = asyncio.create_task(self._expire(invitation))
                    error = None
            await self._publish()
            if error:
                await self.hub.notify(actor, 'error', error)
                return False
            if request_to_join:
                # A request conveys interest, not the other leader's consent.
                await self.hub.notify(leader, 'announcement',
                    actor.name + ' requested to join your party. Invite them from Social.')
                return True
            async with self.hub._lock:
                if not self._valid(invitation):
                    return False
            sent = await self.hub._deliver(target, self.delivery(IN_PARTY, 2,
                invitation_body(party.identity, actor.lease.account), 'party_invitation',
                invitation_nonce=invitation.nonce))
            if not sent:
                async with self.hub._lock:
                    self._cancel(invitation)
                await self._publish()
            return sent

    async def respond(self, actor, identity=None, *, accept=True):
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                invitation = self.invitations.get(actor)
                valid = (invitation is not None and (identity is None or identity == invitation.party.identity)
                         and self._valid(invitation))
                if not valid:
                    # A wrong-ID response must not clear a newer invitation.
                    if invitation and (identity is None or identity == invitation.party.identity):
                        self._cancel(invitation)
                    success = False
                elif not accept:
                    self._cancel(invitation)
                    success = True
                elif len(invitation.party.members) >= 6:
                    self._cancel(invitation)
                    success = False
                else:
                    party = invitation.party
                    self._detach(actor)
                    solo = self._party(actor)
                    del self.parties[solo.identity]
                    party.members.append(actor)
                    actor._party_id = party.identity
                    self._change(party)
                    success = True
            await self._publish()
            return success

    async def leave(self, actor):
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                if len(self._party(actor).members) == 1:
                    return False
                self._detach(actor)
            await self._publish()
            return True

    async def member_action(self, actor, target_id, *, promote=False):
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                party = self._party(actor)
                target = self.hub._actors.get(target_id)
                if (party.leader is not actor or target is None or target is actor
                        or target not in party.members or not self.hub.is_current(target.lease)):
                    return False
                if promote:
                    self._cancel_actor(actor)
                    party.leader = target
                    self._change(party)
                else:
                    self._detach(target)
            await self._publish()
            return True

    async def group(self, actor, message):
        encoded = self.hub._chat_text(message)
        async with self.events:
            async with self.hub._lock:
                self.hub._check_locked(actor)
                party = self._party(actor)
                if len(party.members) < 2 or party.channel not in actor._channels:
                    return 0
                recipients = tuple(party.members)
                delivery = self.delivery(IN_CHAT, 0, party.channel
                    + self.hub._chat_text(actor.lease.account.battle_tag, 'sender BattleTag', 128)
                    + actor.account_id + encoded,
                    'chat', message, actor.account_id, actor.name, party.channel)
            counts = await asyncio.gather(*(self.hub._deliver(member, delivery) for member in recipients))
            await self._publish()
            return sum(counts)

    async def members(self, actor, channel):
        async with self.hub._lock:
            self.hub._check_locked(actor)
            party = self._party(actor)
            if channel != party.channel or channel not in actor._channels:
                return False
            body = channel + struct.pack('<I', len(party.members))
            body += b''.join(self.hub._chat_text(member.lease.account.battle_tag, 'member BattleTag', 128)
                             + member.account_id
                             for member in party.members)
        return await self.hub._deliver(actor, self.delivery(IN_CHAT, 1, body, 'members', channel=channel))
