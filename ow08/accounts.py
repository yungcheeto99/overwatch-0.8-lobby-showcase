"""Local research accounts and transient, exclusive login ownership.

This module has no sockets or beta protocol assumptions. Bootstrap and lobby
adapters must share one AdmissionManager, and must release the lease they own.
Account/password data persists; challenges, tickets, referrals and leases do not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import threading
import time
from types import MappingProxyType
from typing import Callable, Iterable, Mapping
import unicodedata

from .portrait import DEFAULT_PORTRAIT, PORTRAITS
from .heroes import DEFAULT_HERO_LEVEL, HEROES, HERO_LEVEL_LIMIT


PASSWORD_ITERATIONS = 600_000
ACCOUNT_TAG = 0x0100000000000000
GAME_ACCOUNT_TAG = 0x020000010050726F
_LOGIN_ALIAS = re.compile(r"account-([1-9][0-9]*)@local\.invalid", re.IGNORECASE | re.ASCII)
_ID_ALIAS_NAMESPACE = re.compile(r"account-[1-9][0-9]*(?:-[1-9][0-9]*)?@local\.invalid",
                                 re.IGNORECASE | re.ASCII)
_EMAIL_LOCAL = r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*"
_USERNAME_ALIAS = re.compile(_EMAIL_LOCAL + r"@email\.com", re.IGNORECASE | re.ASCII)
_ALIAS_LOCAL = re.compile(_EMAIL_LOCAL, re.ASCII)
_SQLITE_MAX_ID = (1 << 63) - 1
_HERO_KEYS = frozenset(hero.key for hero in HEROES)


class AccountError(ValueError):
    """An account operation could not be completed."""


class AccountExists(AccountError):
    pass


class AccountNotFound(AccountError):
    pass


class InvalidCredentials(AccountError):
    pass


class AccountInUse(AccountError):
    pass


class InvalidAdmission(AccountError):
    pass


def normalize_username(value: str) -> tuple[str, str]:
    """Preserve a display name, with NFKC/casefold uniqueness for lookups."""
    if not isinstance(value, str):
        raise AccountError("username must be text")
    display = unicodedata.normalize("NFC", value.strip())
    if (not display or any(unicodedata.category(char).startswith("C") for char in display)
            or len(display.encode("utf-8")) > 64
            ):
        raise AccountError("username must contain 1..64 UTF-8 bytes without control characters")
    return unicodedata.normalize("NFKC", display).casefold(), display


def normalize_real_name(value: str) -> str:
    """Optional native Real ID display label, independent of login identity."""
    if not isinstance(value, str):
        raise AccountError("real name must be text")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise AccountError("real name must contain at most 128 UTF-8 bytes without control characters")
    display = unicodedata.normalize("NFC", value.strip())
    if len(display.encode("utf-8")) > 128:
        raise AccountError("real name must contain at most 128 UTF-8 bytes without control characters")
    return display


def _password(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 128 or "\0" in value:
        raise AccountError("password must contain 1..128 characters without NUL")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise AccountError("password must contain valid Unicode characters") from None


def _derive(password: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


@dataclass(frozen=True)
class Account:
    id: int
    username: str
    game_id: int
    _native_login: str | None = field(default=None, repr=False, compare=False)
    portrait_guid: int = field(default=DEFAULT_PORTRAIT, compare=False)
    real_name: str = field(default="", compare=False)

    @property
    def display_name(self) -> str:
        return self.username

    @property
    def login_name(self) -> str:
        """Native email-shaped alias; display identity and password stay unchanged.

        Stored aliases survive database reopening. Ordinary ASCII local names
        use ``<username>@email.com``; spaces, Unicode, ``@`` and saved-name
        collisions use a reserved account-ID alias. The domain is only a local
        login suffix: no mail service or external account is consulted.
        """
        if self._native_login is not None:
            return self._native_login
        return (self.username + "@email.com" if _ALIAS_LOCAL.fullmatch(self.username)
                else f"account-{self.id}@local.invalid")

    @property
    def account_id(self) -> bytes:
        return struct.pack("<QQ", self.id, ACCOUNT_TAG)

    @property
    def game_account_id(self) -> bytes:
        return struct.pack("<QQ", self.game_id, GAME_ACCOUNT_TAG)

    @property
    def battle_tag(self) -> str:
        return f"{self.username}#{self.id:04d}"


class AccountStore:
    """One SQLite connection shared safely by bootstrap and lobby threads.

    Use AdmissionManager.delete() when the store has an online manager; the
    lower-level store alone cannot know whether an account is online.
    """
    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(f"""CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    normalized TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    login_alias TEXT,
                    portrait_guid INTEGER NOT NULL DEFAULT {DEFAULT_PORTRAIT},
                    real_name TEXT NOT NULL DEFAULT ''
                )""")
                columns = {row[1] for row in self._db.execute("PRAGMA table_info(accounts)")}
                if "login_alias" not in columns:
                    self._db.execute("ALTER TABLE accounts ADD COLUMN login_alias TEXT")
                if "portrait_guid" not in columns:
                    self._db.execute("ALTER TABLE accounts ADD COLUMN portrait_guid "
                                     f"INTEGER NOT NULL DEFAULT {DEFAULT_PORTRAIT}")
                if "real_name" not in columns:
                    self._db.execute("ALTER TABLE accounts ADD COLUMN real_name TEXT NOT NULL DEFAULT ''")
                self._db.execute(f"""CREATE TABLE IF NOT EXISTS account_hero_levels (
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    hero_key TEXT NOT NULL,
                    level INTEGER NOT NULL CHECK(level BETWEEN {DEFAULT_HERO_LEVEL} AND {HERO_LEVEL_LIMIT}),
                    PRIMARY KEY(account_id,hero_key)
                )""")
                self._db.execute("CREATE UNIQUE INDEX IF NOT EXISTS accounts_login_alias "
                                 "ON accounts(login_alias COLLATE NOCASE)")
                for row in self._db.execute(
                        "SELECT id,username FROM accounts WHERE login_alias IS NULL ORDER BY id").fetchall():
                    alias = self._allocate_alias(*row)
                    self._db.execute("UPDATE accounts SET login_alias=? WHERE id=?", (alias, row[0]))
                from .social_store import SocialStore
                self.social = SocialStore(self)
                self.social._create_schema()
        except BaseException:
            self._db.close()
            raise

    def _allocate_alias(self, account_id: int, username: str) -> str:
        """Choose a free alias without shadowing any saved literal username.

        Migration checks every existing name before assigning aliases. If a
        pre-reservation database already occupied the ordinary ID fallback,
        append the smallest positive suffix in the same reserved namespace.
        """
        preferred = username + "@email.com" if _ALIAS_LOCAL.fullmatch(username) else None
        fallback = f"account-{account_id}@local.invalid"
        candidates = [preferred, fallback] if preferred is not None else [fallback]
        suffix = 0
        while True:
            candidate = candidates.pop(0) if candidates else f"account-{account_id}-{suffix}@local.invalid"
            if self._db.execute(
                    "SELECT 1 FROM accounts WHERE (normalized=? AND id<>?) "
                    "OR login_alias=? COLLATE NOCASE LIMIT 1",
                    (candidate.casefold(), account_id, candidate)).fetchone() is None:
                return candidate
            if not candidates:
                suffix += 1

    @staticmethod
    def _account(row) -> Account:
        return Account(row[0], row[1], row[0] + 0x10000000, row[2], row[3], row[4])

    def create(self, user: str, password: str) -> Account:
        normalized, display = normalize_username(user)
        if _ID_ALIAS_NAMESPACE.fullmatch(normalized) or _USERNAME_ALIAS.fullmatch(normalized):
            raise AccountError("@email.com and account-<id>@local.invalid aliases are reserved for native login")
        encoded = _password(password)
        salt = secrets.token_bytes(16)
        digest = _derive(encoded, salt, PASSWORD_ITERATIONS)
        with self._lock, self._db:
            try:
                cursor = self._db.execute(
                    "INSERT INTO accounts(normalized,username,salt,password_hash,iterations) VALUES(?,?,?,?,?)",
                    (normalized, display, salt, digest, PASSWORD_ITERATIONS))
            except sqlite3.IntegrityError:
                raise AccountExists("account already exists") from None
            alias = self._allocate_alias(cursor.lastrowid, display)
            self._db.execute("UPDATE accounts SET login_alias=? WHERE id=?", (alias, cursor.lastrowid))
            return self._account((cursor.lastrowid, display, alias, DEFAULT_PORTRAIT, ""))

    def get(self, user: str) -> Account:
        normalized, _ = normalize_username(user)
        with self._lock:
            row = self._db.execute("SELECT id,username,login_alias,portrait_guid,real_name FROM accounts WHERE normalized=?",
                                   (normalized,)).fetchone()
            if row is None:
                raise AccountNotFound("account does not exist")
            return self._account(row)

    def authenticate(self, user: str, password: str) -> Account:
        try:
            encoded = _password(password)
            with self._lock:
                row = self._login_row_locked(user, "id,username,salt,password_hash,iterations,login_alias,portrait_guid,real_name")
        except AccountError:
            raise InvalidCredentials("invalid account or password") from None
        # An unknown username does the same password work and has the same error.
        salt, digest, iterations = (row[2:5] if row is not None
                                    else (bytes(16), bytes(32), PASSWORD_ITERATIONS))
        candidate = _derive(encoded, salt, iterations)
        if row is None or not hmac.compare_digest(candidate, digest):
            raise InvalidCredentials("invalid account or password")
        return self._account((row[0], row[1], row[5], row[6], row[7]))

    def set_portrait(self, user: str | Account, guid: int) -> Account:
        """Persist a verified beta portrait without changing account identity."""
        if type(guid) is not int or not any(portrait.guid == guid for portrait in PORTRAITS):
            raise AccountError("portrait must be one of the listed beta portrait GUIDs")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if isinstance(user, Account):
                row = (self._db.execute(
                    "SELECT id,username,login_alias,portrait_guid,real_name FROM accounts WHERE id=?",
                    (user.id,)).fetchone() if type(user.id) is int and 0 < user.id <= _SQLITE_MAX_ID
                    else None)
                account = self._account(row) if row is not None else None
                if account is None or account != user:
                    raise AccountNotFound("the account identity is no longer current")
            else:
                account = self.get(user)
            self._db.execute("UPDATE accounts SET portrait_guid=? WHERE id=?", (guid, account.id))
            return self._account((account.id, account.username, account.login_name, guid, account.real_name))

    def set_real_name(self, user: str | Account, value: str) -> Account:
        """Save or clear a Real ID label without replacing account ownership."""
        display = normalize_real_name(value)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if isinstance(user, Account):
                row = (self._db.execute(
                    "SELECT id,username,login_alias,portrait_guid,real_name FROM accounts WHERE id=?",
                    (user.id,)).fetchone() if type(user.id) is int and 0 < user.id <= _SQLITE_MAX_ID
                    else None)
                account = self._account(row) if row is not None else None
                if account is None or account != user:
                    raise AccountNotFound("the account identity is no longer current")
            else:
                account = self.get(user)
            self._db.execute("UPDATE accounts SET real_name=? WHERE id=?", (display, account.id))
            return self._account((account.id, account.username, account.login_name,
                                  account.portrait_guid, display))

    def _login_row_locked(self, user: str, columns: str):
        """Shared password-independent resolution; caller owns the store lock."""
        if not isinstance(user, str):
            raise AccountError("username must be text")
        supplied = user.strip()
        # A 64-byte username may have a 74-byte email-shaped login alias.
        if _USERNAME_ALIAS.fullmatch(supplied) and len(supplied.split("@", 1)[0]) <= 64:
            normalized = supplied.casefold()
        else:
            normalized, _ = normalize_username(user)
        # Saved literal usernames win; no alias can retarget them.
        row = self._db.execute(f"SELECT {columns} FROM accounts WHERE normalized=?",
                               (normalized,)).fetchone()
        if row is None and (_USERNAME_ALIAS.fullmatch(supplied)
                            or _ID_ALIAS_NAMESPACE.fullmatch(supplied)):
            row = self._db.execute(f"SELECT {columns} FROM accounts WHERE login_alias=? COLLATE NOCASE",
                                   (supplied,)).fetchone()
        alias = _LOGIN_ALIAS.fullmatch(supplied)
        if row is None and alias:
            alias_id = int(alias[1])
            row = (self._db.execute(f"SELECT {columns} FROM accounts WHERE id=?",
                                   (alias_id,)).fetchone() if alias_id <= _SQLITE_MAX_ID else None)
        return row

    def hero_levels(self, user: str | Account) -> dict[str, int]:
        """Read saved hero overrides; every absent hero starts at level 1.

        Account identities and account selectors use the same resolution as
        administrative social commands. The returned map is a detached copy.
        """
        with self._lock, self._db:
            self._db.execute("BEGIN")
            account = self.social._resolve(user)
            return dict(self._db.execute(
                "SELECT hero_key,level FROM account_hero_levels WHERE account_id=?",
                (account.id,)))

    def set_hero_levels(self, user: str | Account, hero_keys: Iterable[str], level: int) -> Account:
        """Atomically persist levels for named beta heroes and return their owner.

        Saving level 1 clears an override. Progression is enabled by the server
        runtime's extended mode; storage validates values independently of it.
        """
        if type(level) is not int or not DEFAULT_HERO_LEVEL <= level <= HERO_LEVEL_LIMIT:
            raise AccountError(f"hero level must be {DEFAULT_HERO_LEVEL}..{HERO_LEVEL_LIMIT}")
        if isinstance(hero_keys, (str, bytes)):
            raise AccountError("hero selection must contain beta hero keys")
        try:
            keys = tuple(hero_keys)
        except TypeError:
            raise AccountError("hero selection must contain beta hero keys") from None
        if not keys or any(not isinstance(key, str) or key not in _HERO_KEYS for key in keys):
            raise AccountError("hero selection must contain beta hero keys")
        keys = tuple(dict.fromkeys(keys))
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            account = self.social._resolve(user)
            if level == DEFAULT_HERO_LEVEL:
                self._db.executemany(
                    "DELETE FROM account_hero_levels WHERE account_id=? AND hero_key=?",
                    ((account.id, key) for key in keys))
            else:
                self._db.executemany(
                    "INSERT INTO account_hero_levels(account_id,hero_key,level) VALUES(?,?,?) "
                    "ON CONFLICT(account_id,hero_key) DO UPDATE SET level=excluded.level",
                    ((account.id, key, level) for key in keys))
            return account

    def delete(self, user: str) -> Account:
        normalized, _ = normalize_username(user)
        with self._lock, self._db:
            account = self.get(user)
            self._db.execute("DELETE FROM accounts WHERE normalized=?", (normalized,))
            return account

    def list(self) -> tuple[Account, ...]:
        with self._lock:
            return tuple(self._account(row) for row in self._db.execute(
                "SELECT id,username,login_alias,portrait_guid,real_name FROM accounts ORDER BY id"))

    def close(self):
        with self._lock:
            self._db.close()


@dataclass(frozen=True)
class Lease:
    account: Account
    owner: str
    kind: str
    generation: str


@dataclass(frozen=True)
class Admission:
    cid: int
    lease: Lease
    challenge: str = field(repr=False)
    key_slots: Mapping[str, bytes] = field(repr=False)


@dataclass
class _Challenge:
    owner: str
    expires: float
    attempt: int = 0


@dataclass
class _Pending:
    lease: Lease
    challenge: str
    expires: float
    verified: bool = False
    cid: int | None = None


@dataclass
class _Ticket:
    challenge: str
    generation: str
    expires: float


class AdmissionManager:
    """Atomic account ownership, from a web challenge to a real/synthetic actor.

    Each RPC session supplies a unique owner. issue_ticket reserves its account;
    verify_ticket consumes the token. A successful JAM proof must be checked by
    the adapter before claim_referral transfers ownership to its lobby session.
    abort_owner only cancels pending auth, never transferred or synthetic actors.
    """
    def __init__(self, store: AccountStore, *, clock: Callable[[], float] = time.monotonic,
                 challenge_ttl: float = 600, ticket_ttl: float = 120, admission_ttl: float = 120):
        if any(not isinstance(ttl, (int, float)) or not 0 < ttl <= 3600
               for ttl in (challenge_ttl, ticket_ttl, admission_ttl)):
            raise AccountError("authentication lifetimes must be within 1 hour")
        self.store, self._clock = store, clock
        self.challenge_ttl, self.ticket_ttl, self.admission_ttl = challenge_ttl, ticket_ttl, admission_ttl
        self._lock = threading.RLock()
        self._challenges: dict[str, _Challenge] = {}
        self._tickets: dict[str, _Ticket] = {}
        self._leases: dict[int, Lease] = {}
        self._pending: dict[str, _Pending] = {}
        self._referrals: dict[int, Admission] = {}

    @staticmethod
    def _owner(owner: str):
        if not isinstance(owner, str) or not owner:
            raise AccountError("owner must be a nonempty session identifier")

    def _forget_pending(self, generation: str):
        pending = self._pending.pop(generation, None)
        if pending is not None:
            if self._leases.get(pending.lease.account.id) == pending.lease:
                self._leases.pop(pending.lease.account.id)
            if pending.cid is not None:
                self._referrals.pop(pending.cid, None)
        for token, ticket in tuple(self._tickets.items()):
            if ticket.generation == generation:
                self._tickets.pop(token)

    def _prune(self):
        now = self._clock()
        for generation, pending in tuple(self._pending.items()):
            if pending.expires <= now:
                self._forget_pending(generation)
        for nonce, challenge in tuple(self._challenges.items()):
            if challenge.expires <= now:
                self._challenges.pop(nonce)
                for generation, pending in tuple(self._pending.items()):
                    if pending.challenge == nonce:
                        self._forget_pending(generation)

    def begin_challenge(self, owner: str) -> str:
        self._owner(owner)
        with self._lock:
            self.abort_owner(owner)
            nonce = secrets.token_urlsafe(32)
            self._challenges[nonce] = _Challenge(owner, self._clock() + self.challenge_ttl)
            return nonce

    def challenge_valid(self, nonce: str) -> bool:
        with self._lock:
            self._prune()
            return isinstance(nonce, str) and nonce in self._challenges

    def issue_ticket(self, nonce: str, user: str, password: str) -> str:
        with self._lock:
            self._prune()
            challenge = self._challenges.get(nonce) if isinstance(nonce, str) else None
            if challenge is None:
                raise InvalidAdmission("login challenge expired or invalid")
            challenge.attempt += 1
            attempt = challenge.attempt
            # A repeated form submit supersedes its old reservation/token.
            for generation, pending in tuple(self._pending.items()):
                if pending.challenge == nonce:
                    self._forget_pending(generation)
        account = self.store.authenticate(user, password)
        with self._lock:
            self._prune()
            if self._challenges.get(nonce) is not challenge or challenge.attempt != attempt:
                raise InvalidAdmission("login challenge expired or invalid")
            # Deletion/recreation during password work must not admit stale IDs.
            try:
                current = self.store.get(account.username)
            except AccountNotFound:
                raise InvalidCredentials("invalid account or password") from None
            if current != account:
                raise InvalidCredentials("invalid account or password")
            if account.id in self._leases:
                raise AccountInUse("account is already in use")
            lease = Lease(account, challenge.owner, "pending", secrets.token_hex(16))
            expires = min(challenge.expires, self._clock() + self.ticket_ttl)
            self._leases[account.id] = lease
            self._pending[lease.generation] = _Pending(lease, nonce, expires)
            token = "US-" + secrets.token_hex(32)
            self._tickets[token] = _Ticket(nonce, lease.generation, expires)
            return token

    def verify_ticket(self, nonce: str, token: str, owner: str) -> Lease:
        self._owner(owner)
        with self._lock:
            self._prune()
            challenge = self._challenges.get(nonce) if isinstance(nonce, str) else None
            ticket = self._tickets.get(token) if isinstance(token, str) else None
            if (challenge is None or challenge.owner != owner or ticket is None
                    or ticket.challenge != nonce):
                raise InvalidAdmission("login ticket expired or invalid")
            pending = self._pending.get(ticket.generation)
            if pending is None or self._leases.get(pending.lease.account.id) != pending.lease:
                raise InvalidAdmission("login ticket expired or invalid")
            self._tickets.pop(token)
            self._challenges.pop(nonce)
            pending.verified = True
            pending.expires = self._clock() + self.admission_ttl
            return pending.lease

    def issue_referral(self, lease: Lease) -> Admission:
        with self._lock:
            self._prune()
            pending = self._pending.get(lease.generation)
            if (pending is None or not pending.verified or pending.lease != lease
                    or self._leases.get(lease.account.id) != lease):
                raise InvalidAdmission("account has no verified admission")
            if pending.cid is not None:
                return self._referrals[pending.cid]
            cid = secrets.randbelow(0xFFFFFFFF) + 1
            while cid in self._referrals:
                cid = secrets.randbelow(0xFFFFFFFF) + 1
            keys = MappingProxyType({f"k{index}": secrets.token_bytes(64) for index in range(4)})
            admission = Admission(cid, lease, pending.challenge, keys)
            pending.cid = cid
            self._referrals[cid] = admission
            return admission

    def pending_referral(self, cid: int) -> Admission:
        with self._lock:
            self._prune()
            admission = self._referrals.get(cid) if type(cid) is int else None
            if admission is None:
                raise InvalidAdmission("lobby referral expired or invalid")
            return admission

    def claim_referral(self, cid: int, admission: Admission, lobby_owner: str) -> Lease:
        self._owner(lobby_owner)
        with self._lock:
            self._prune()
            if (type(cid) is not int or not isinstance(admission, Admission)
                    or self._referrals.get(cid) is not admission
                    or self._leases.get(admission.lease.account.id) != admission.lease):
                raise InvalidAdmission("lobby referral expired or already used")
            self._forget_pending(admission.lease.generation)
            lease = Lease(admission.lease.account, lobby_owner, "real", secrets.token_hex(16))
            self._leases[lease.account.id] = lease
            return lease

    def possess(self, user: str, owner: str) -> Lease:
        self._owner(owner)
        with self._lock:
            self._prune()
            account = self.store.get(user)
            if account.id in self._leases:
                raise AccountInUse("account is already in use")
            lease = Lease(account, owner, "synthetic", secrets.token_hex(16))
            self._leases[account.id] = lease
            return lease

    def is_current(self, lease: Lease) -> bool:
        with self._lock:
            self._prune()
            return isinstance(lease, Lease) and self._leases.get(lease.account.id) == lease

    def release(self, lease: Lease) -> bool:
        with self._lock:
            if not self.is_current(lease):
                return False
            if lease.kind == "pending":
                self._forget_pending(lease.generation)
            else:
                self._leases.pop(lease.account.id)
            return True

    def abort_owner(self, owner: str):
        self._owner(owner)
        with self._lock:
            self._prune()
            for nonce, challenge in tuple(self._challenges.items()):
                if challenge.owner == owner:
                    self._challenges.pop(nonce)
            for generation, pending in tuple(self._pending.items()):
                if pending.lease.owner == owner:
                    self._forget_pending(generation)

    def lease_for(self, user: str) -> Lease | None:
        with self._lock:
            self._prune()
            return self._leases.get(self.store.get(user).id)

    def delete(self, user: str) -> Account:
        with self._lock:
            self._prune()
            account = self.store.get(user)
            if account.id in self._leases:
                raise AccountInUse("account is already in use")
            return self.store.delete(user)
