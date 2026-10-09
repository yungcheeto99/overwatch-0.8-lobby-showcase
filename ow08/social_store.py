"""Explicit local social relationships in the existing account database.

Friendships are symmetric; favorites belong to one owner. Requests require
recipient consent and survive restarts. Account deletion cascades through both
tables. No registered-account roster is implicitly converted into friends.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import math
import struct
import time
import unicodedata

from .accounts import Account, AccountError, AccountNotFound, ACCOUNT_TAG, _SQLITE_MAX_ID


class SocialError(AccountError):
    pass


class AlreadyFriends(SocialError):
    pass


class RequestPending(SocialError):
    def __init__(self, request):
        self.request = request
        super().__init__("an incoming friend request already exists")


class RequestNotFound(SocialError):
    pass


class NotAuthorized(SocialError):
    pass


@dataclass(frozen=True)
class FriendRelationship:
    account: Account
    favorite: bool
    created_at: int
    favorite_updated_at: int | None = None


@dataclass(frozen=True)
class FriendRequest:
    id: int
    sender: Account
    recipient: Account
    message: str
    created_at: int


@dataclass(frozen=True)
class SocialSnapshot:
    owner: Account
    friends: tuple[FriendRelationship, ...]
    incoming: tuple[FriendRequest, ...]
    outgoing: tuple[FriendRequest, ...]


class SocialStore:
    """Share AccountStore's SQLite connection and RLock, never its own file.

    Every mutation takes an immediate SQLite transaction, so duplicate or
    crossed requests cannot race even across separate AccountStore instances.
    Callers authorize the current account/lease before using this local API.
    """
    def __init__(self, accounts, *, clock=time.time):
        if not callable(clock):
            raise ValueError("social clock must be callable")
        self.accounts = accounts
        self._db, self._lock = accounts._db, accounts._lock
        self._clock = clock

    def _create_schema(self):
        # AccountStore invokes this inside its own schema migration transaction.
        self._db.execute("""CREATE TABLE IF NOT EXISTS social_friends (
            account_a INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            account_b INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL CHECK(created_at>=0),
            favorite_a INTEGER NOT NULL DEFAULT 0 CHECK(favorite_a IN (0,1)),
            favorite_b INTEGER NOT NULL DEFAULT 0 CHECK(favorite_b IN (0,1)),
            favorite_updated_a INTEGER CHECK(favorite_updated_a>=0),
            favorite_updated_b INTEGER CHECK(favorite_updated_b>=0),
            PRIMARY KEY(account_a,account_b), CHECK(account_a<account_b)
        )""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS social_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            recipient_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            account_a INTEGER NOT NULL, account_b INTEGER NOT NULL,
            message TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at>=0),
            UNIQUE(account_a,account_b), CHECK(account_a<account_b),
            CHECK((sender_id=account_a AND recipient_id=account_b)
               OR (sender_id=account_b AND recipient_id=account_a))
        )""")

    @contextmanager
    def _transaction(self, *, write=False):
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield

    def _now(self):
        value = self._clock()
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not 0 <= value <= _SQLITE_MAX_ID):
            raise SocialError("social timestamp must be a nonnegative Unix time")
        return int(value)

    def _account(self, account_id):
        if type(account_id) is not int or not 0 < account_id <= _SQLITE_MAX_ID:
            raise AccountNotFound("account does not exist")
        row = self._db.execute("SELECT id,username,login_alias,portrait_guid,real_name FROM accounts WHERE id=?",
                               (account_id,)).fetchone()
        if row is None:
            raise AccountNotFound("account does not exist")
        return self.accounts._account(row)

    def _owner(self, owner):
        if not isinstance(owner, Account):
            raise AccountNotFound("the account identity is no longer current")
        current = self._account(owner.id)
        if current != owner:
            raise AccountNotFound("the account identity is no longer current")
        return current

    def _resolve(self, target, kind=None):
        if kind not in (None, "email", "battletag"):
            raise SocialError("unknown social target type")
        if kind is not None and not isinstance(target, str):
            raise SocialError("typed social targets must be text")
        if isinstance(target, Account):
            return self._owner(target)
        if isinstance(target, bytes):
            if len(target) != 16:
                raise AccountNotFound("account does not exist")
            account_id, tag = struct.unpack("<QQ", target)
            if tag != ACCOUNT_TAG:
                raise AccountNotFound("account does not exist")
            return self._account(account_id)
        if not isinstance(target, str):
            raise AccountNotFound("account does not exist")
        supplied = target.strip()
        if (any(unicodedata.category(char).startswith("C") for char in supplied)
                or len(supplied.encode("utf-8")) > 128):
            raise AccountNotFound("account does not exist")
        try:
            row = self.accounts._login_row_locked(target, "id,username,login_alias,portrait_guid,real_name")
        except AccountError:
            row = None
        literal = self.accounts._account(row) if row is not None else None
        if kind == "email":
            if supplied.count("@") != 1 or literal is None:
                raise AccountNotFound("account does not exist")
            return literal
        # A BattleTag requires the canonical discriminator and its own name.
        name, separator, discriminator = supplied.rpartition("#")
        tagged = None
        if (separator and discriminator.isascii() and discriminator.isdecimal()
                and 1 <= len(discriminator) <= 19):
            try:
                account = self._account(int(discriminator))
            except AccountNotFound:
                account = None
            if (account is not None and discriminator == f"{account.id:04d}"
                    and unicodedata.normalize("NFKC", name).casefold()
                    == unicodedata.normalize("NFKC", account.username).casefold()):
                tagged = account
        if kind == "battletag":
            if tagged is None:
                raise AccountNotFound("account does not exist")
            return tagged
        if literal is not None and tagged is not None and literal.id != tagged.id:
            raise SocialError("ambiguous account target; use its printed login alias")
        account = literal or tagged
        if account is None:
            raise AccountNotFound("account does not exist")
        return account

    def resolve(self, target, *, kind=None) -> Account:
        """Resolve one registered local name, login alias, BattleTag or root ID."""
        with self._transaction():
            return self._resolve(target, kind)

    def _pair(self, owner, target):
        owner, target = self._owner(owner), self._resolve(target)
        if owner.id == target.id:
            raise SocialError("an account cannot be its own friend")
        return owner, target, min(owner.id, target.id), max(owner.id, target.id)

    def _friend(self, owner, row):
        a, b, created, favorite_a, favorite_b, updated_a, updated_b = row
        return FriendRelationship(self._account(b if owner.id == a else a),
                                  bool(favorite_a if owner.id == a else favorite_b),
                                  created, updated_a if owner.id == a else updated_b)

    def _friend_row(self, a, b):
        return self._db.execute("SELECT account_a,account_b,created_at,favorite_a,favorite_b,"
                                "favorite_updated_a,favorite_updated_b FROM social_friends "
                                "WHERE account_a=? AND account_b=?", (a, b)).fetchone()

    def _request(self, row):
        return FriendRequest(row[0], self._account(row[1]), self._account(row[2]), row[3], row[4])

    @staticmethod
    def _request_id(value):
        if type(value) is not int or not 0 < value <= _SQLITE_MAX_ID:
            raise RequestNotFound("friend request does not exist")
        return value

    def _request_row(self, request_id):
        return self._db.execute("SELECT id,sender_id,recipient_id,message,created_at "
                                "FROM social_requests WHERE id=?", (self._request_id(request_id),)).fetchone()

    def snapshot(self, owner) -> SocialSnapshot:
        with self._transaction():
            owner = self._owner(owner)
            rows = self._db.execute("SELECT account_a,account_b,created_at,favorite_a,favorite_b,"
                "favorite_updated_a,favorite_updated_b FROM social_friends "
                "WHERE account_a=? OR account_b=? ORDER BY account_a,account_b", (owner.id, owner.id)).fetchall()
            friends = tuple(sorted((self._friend(owner, row) for row in rows), key=lambda item: item.account.id))
            requests = tuple(self._request(row) for row in self._db.execute(
                "SELECT id,sender_id,recipient_id,message,created_at FROM social_requests "
                "WHERE sender_id=? OR recipient_id=? ORDER BY id", (owner.id, owner.id)).fetchall())
            return SocialSnapshot(owner, friends,
                tuple(item for item in requests if item.recipient.id == owner.id),
                tuple(item for item in requests if item.sender.id == owner.id))

    def request(self, owner, target, message="") -> FriendRequest:
        if (not isinstance(message, str) or any(unicodedata.category(char).startswith("C") for char in message)
                or len(message.encode("utf-8")) > 1024):
            raise SocialError("friend request message must contain at most 1024 UTF-8 bytes without controls")
        with self._transaction(write=True):
            owner, target, a, b = self._pair(owner, target)
            if self._friend_row(a, b) is not None:
                raise AlreadyFriends("accounts are already friends")
            row = self._db.execute("SELECT id,sender_id,recipient_id,message,created_at "
                "FROM social_requests WHERE account_a=? AND account_b=?", (a, b)).fetchone()
            if row is not None:
                request = self._request(row)
                if request.sender.id != owner.id:
                    raise RequestPending(request)
                return request
            cursor = self._db.execute("INSERT INTO social_requests(sender_id,recipient_id,account_a,account_b,"
                "message,created_at) VALUES(?,?,?,?,?,?)", (owner.id, target.id, a, b, message, self._now()))
            return self._request(self._request_row(cursor.lastrowid))

    def incoming_request(self, owner, sender_or_id) -> FriendRequest:
        with self._transaction():
            owner = self._owner(owner)
            if type(sender_or_id) is int:
                row = self._request_row(sender_or_id)
            else:
                sender = self._resolve(sender_or_id)
                row = self._db.execute("SELECT id,sender_id,recipient_id,message,created_at "
                    "FROM social_requests WHERE sender_id=? AND recipient_id=?", (sender.id, owner.id)).fetchone()
            if row is None:
                raise RequestNotFound("friend request does not exist")
            if row[2] != owner.id:
                raise NotAuthorized("only the recipient may access this friend request")
            return self._request(row)

    def _establish(self, a, b):
        existed = self._friend_row(a, b) is not None
        if not existed:
            self._db.execute("INSERT INTO social_friends(account_a,account_b,created_at) VALUES(?,?,?)",
                             (a, b, self._now()))
        self._db.execute("DELETE FROM social_requests WHERE account_a=? AND account_b=?", (a, b))
        return not existed

    def establish(self, owner, target) -> bool:
        """Explicit administrative friendship; normal clients use consent."""
        with self._transaction(write=True):
            _, _, a, b = self._pair(owner, target)
            return self._establish(a, b)

    def are_friends(self, owner, target) -> bool:
        with self._transaction():
            _, _, a, b = self._pair(owner, target)
            return self._friend_row(a, b) is not None

    def accept(self, owner, request_id) -> FriendRelationship:
        with self._transaction(write=True):
            owner = self._owner(owner)
            row = self._request_row(request_id)
            if row is None:
                raise RequestNotFound("friend request does not exist")
            if row[2] != owner.id:
                raise NotAuthorized("only the recipient may accept this friend request")
            a, b = min(row[1], row[2]), max(row[1], row[2])
            self._establish(a, b)
            return self._friend(owner, self._friend_row(a, b))

    def _dismiss(self, owner, request_id, *, cancel):
        with self._transaction(write=True):
            owner = self._owner(owner)
            row = self._request_row(request_id)
            if row is None:
                return False
            if row[1 if cancel else 2] != owner.id:
                raise NotAuthorized("only the sender may cancel this friend request" if cancel
                                    else "only the recipient may decline this friend request")
            self._db.execute("DELETE FROM social_requests WHERE id=?", (row[0],))
            return True

    def decline(self, owner, request_id) -> bool:
        return self._dismiss(owner, request_id, cancel=False)

    def cancel(self, owner, request_id) -> bool:
        return self._dismiss(owner, request_id, cancel=True)

    def remove(self, owner, target) -> bool:
        with self._transaction(write=True):
            _, _, a, b = self._pair(owner, target)
            return bool(self._db.execute("DELETE FROM social_friends WHERE account_a=? AND account_b=?",
                                         (a, b)).rowcount)

    def favorite(self, owner, target, value) -> bool:
        if not isinstance(value, bool):
            raise SocialError("favorite must be a boolean")
        with self._transaction(write=True):
            owner, _, a, b = self._pair(owner, target)
            row = self._friend_row(a, b)
            if row is None:
                raise SocialError("accounts are not friends")
            if self._friend(owner, row).favorite == value:
                return False
            suffix = "a" if owner.id == a else "b"
            self._db.execute(f"UPDATE social_friends SET favorite_{suffix}=?,favorite_updated_{suffix}=? "
                             "WHERE account_a=? AND account_b=?", (int(value), self._now(), a, b))
            return True
