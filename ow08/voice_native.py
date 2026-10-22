"""Owned beta client's metadata-only voice roster and held push-to-talk input.

Only an idle inline participant cache is borrowed while the original SDK is in
its failed state. No code, SDK state, allocation, audio or game file is changed.
The authenticated launch control supplies membership; native input supplies PTT.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from .client import LaunchResult, _Windows, stop_client, validate_owned_client

_CAPACITY, _STRIDE = 16, 0x60
_EMPTY = {"kind": 0, "speaking": False}


def _identity(value: object) -> bytes:
    if not isinstance(value, str) or len(value) != 32:
        raise ValueError("Voice identity must contain sixteen bytes")
    result = bytes.fromhex(value)
    if len(result) != 16 or not any(result):
        raise ValueError("Voice identity must be nonzero")
    return result


def _snapshot(value: object):
    if not isinstance(value, dict):
        return None
    account = _identity(value.get("account_id"))
    channels = value.get("channels")
    if not isinstance(channels, list) or len(channels) > 2:
        raise ValueError("Invalid voice channel snapshot")
    parsed, kinds = [], set()
    for channel in channels:
        if not isinstance(channel, dict) or type(channel.get("kind")) is not int:
            raise ValueError("Invalid voice channel")
        kind, identity = channel["kind"], _identity(channel.get("identity"))
        if kind not in (4, 5) or kind in kinds:
            raise ValueError("Invalid voice channel kind")
        kinds.add(kind)
        members = channel.get("members")
        if not isinstance(members, list) or len(members) > _CAPACITY:
            raise ValueError("Voice participant inline capacity exceeded")
        peers, seen = [], set()
        for member in members:
            if not isinstance(member, dict) or type(member.get("speaking")) is not bool:
                raise ValueError("Invalid voice participant")
            peer = _identity(member.get("account_id"))
            if peer in seen:
                raise ValueError("Duplicate voice participant")
            seen.add(peer)
            peers.append((peer, member["speaking"]))
        if peers and account not in seen:
            raise ValueError("Voice snapshot omits authenticated self")
        marker = base64.b64encode(hashlib.md5(identity).digest())
        parsed.append((kind, b"sip:confctl-g-" + marker + b"@", peers))
    return account, parsed


@dataclass
class _Borrowed:
    service: int
    handle: int
    uri: bytes
    original: bytes
    published: bytes
    count: int
    guard: tuple


class NativeVoiceMetadata:
    """Bounded bridge attached exclusively to this launcher's supported child."""

    def __init__(self, result: LaunchResult, game: Path):
        validate_owned_client(result, game)
        self.result, self.api = result, _Windows()
        # Suspend/resume rights permit a short data transaction while publishing:
        # the client's channel array cannot move between its guards and writes.
        self.handle = self.api.kernel.OpenProcess(0xC38, False, result.process.pid)
        self.api._check(self.handle, "OpenProcess owned voice metadata")
        try:
            self.base, self.size = self.api.module(self.handle, Path(game).resolve())
            self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            for name in ("NtSuspendProcess", "NtResumeProcess"):
                function = getattr(self.ntdll, name)
                function.argtypes, function.restype = [ctypes.c_void_p], ctypes.c_long
        except BaseException:
            self.api.close(self.handle)
            raise
        self.borrowed: dict[int, _Borrowed] = {}
        self.last_error: str | None = None
        self._last_render = None
        self._suspended = False

    @contextmanager
    def _transaction(self):
        if self.ntdll.NtSuspendProcess(self.handle) < 0:
            raise OSError("Cannot safely suspend owned voice metadata child")
        self._suspended = True
        try:
            yield
        finally:
            self._suspended = False
            if self.ntdll.NtResumeProcess(self.handle) < 0:
                stop_client(self.result.process)
                raise OSError("Cannot resume owned voice metadata child")

    def _read(self, address: int, length: int) -> bytes:
        if not 0x10000 <= address < 0x7FFFFFFFFFFF or not 0 < length <= 65536:
            raise ValueError("Invalid bounded native voice read")
        value = self.api.read(self.handle, address, length)
        if value is None:
            raise OSError("Native voice state is unavailable")
        return value

    def _pointer(self, address: int) -> int:
        value = struct.unpack("<Q", self._read(address, 8))[0]
        if not 0x10000 <= value < 0x7FFFFFFFFFFF:
            raise ValueError("Native voice pointer is unavailable")
        return value

    def _integer(self, address: int) -> int:
        return struct.unpack("<i", self._read(address, 4))[0]

    def _write_data(self, address: int, value: bytes):
        # These destinations are validated inline heap storage, never code.
        if (not self._suspended or self.base <= address < self.base + self.size
                or not 0 < len(value) <= _CAPACITY * _STRIDE):
            raise ValueError("Invalid native voice data destination")
        buffer, written = ctypes.create_string_buffer(value, len(value)), ctypes.c_size_t()
        self.api._check(self.api.kernel.WriteProcessMemory(self.handle, address, buffer, len(value), ctypes.byref(written)),
                        "WriteProcessMemory voice metadata")
        if written.value != len(value) or self._read(address, len(value)) != value:
            raise OSError("Native voice metadata readback differs")

    def _native(self):
        self._guards = {}
        context = self._pointer(self.base + 0x1833E18)
        service = self._pointer(context + 0x188)
        if self._integer(service + 0xB0) != -2:
            return context, service, None, []
        controller = self._pointer(context + 0x180)
        active = self._integer(controller + 0x58)
        count = self._integer(service + 0x288)
        capacity = self._integer(service + 0x28C)
        if not 0 <= count <= _CAPACITY or not count <= capacity <= _CAPACITY:
            raise ValueError("Native voice channel array is outside bounds")
        table = self._pointer(service + 0x280) if count else 0
        rows = []
        for index in range(count):
            row = table + index * 0x6C0
            header = self._read(row, 0xA0)
            pointer, participants, slots = struct.unpack_from("<Qii", header, 0x90)
            uri = header[8:0x48].split(b"\0", 1)[0]
            if b"\0" not in header[8:0x48]:
                continue
            if pointer != row + 0xA0 or slots != _CAPACITY or not 0 <= participants <= _CAPACITY:
                continue
            if not uri.startswith(b"sip:confctl-g-") or b"@" not in uri:
                continue
            rows.append((row, struct.unpack_from("<i", header)[0], uri, participants))
            self._guards[row] = (context, service, table, header[:0x98])
        return context, service, active, rows

    def _held(self, context: int) -> bool:
        engine = self._pointer(context + 0xB0)
        count = self._integer(engine + 0x788)
        capacity = self._integer(engine + 0x78C)
        if not 1 <= count <= _CAPACITY or not count <= capacity <= 64:
            return False
        vector = self._pointer(engine + 0x780)
        native_input = self._pointer(vector)
        slot = self._integer(native_input + 0x40)
        if not 0 <= slot <= 3:
            return False
        return bool(self._read(native_input + slot * 0xC3 + 0x377, 1)[0]
                    or self._read(native_input + slot * 0xC3 + 0x1F1, 1)[0])

    def _selected(self, context: int, active: int | None, rows) -> int:
        if active is None or not any(handle == active for _, handle, _, _ in rows):
            return 0
        choice = self._integer(self._pointer(context + 0x180) + 0x14)
        return 4 if choice == 0 else 5 if choice == 1 else 0

    def _restore(self, service: int, rows, keep: set[int] | None = None):
        current = {row: (handle, uri, count) for row, handle, uri, count in rows}
        for row, borrowed in list(self.borrowed.items()):
            if keep is not None and row in keep:
                continue
            self.borrowed.pop(row, None)
            if (borrowed.service == service and current.get(row) == (borrowed.handle, borrowed.uri, borrowed.count)
                    and self._guards.get(row) == borrowed.guard
                    and self._read(row + 0xA0, _CAPACITY * _STRIDE) == borrowed.published):
                self._write_data(row + 0x98, bytes(4))
                self._write_data(row + 0xA0, borrowed.original)

    def _publish(self, parsed, service, active, rows):
        if parsed is None:
            self._restore(service, rows)
            return
        account, channels = parsed
        matched = {row: members for row, handle, uri, _ in rows
                   for _, prefix, members in channels if handle == active and uri.startswith(prefix)}
        self._restore(service, rows, set(matched))
        for row, handle, uri, count in rows:
            if row not in matched:
                continue
            members, old = matched[row], self.borrowed.get(row)
            current = self._read(row + 0xA0, _CAPACITY * _STRIDE)
            if old is None:
                if count:
                    continue
                old = _Borrowed(service, handle, uri, current, current, 0, self._guards[row])
                self.borrowed[row] = old
            if (old.service, old.handle, old.uri, old.count, old.published) != (service, handle, uri, count, current):
                self.borrowed.pop(row, None)
                continue
            if old.guard != self._guards[row]:
                self.borrowed.pop(row, None)
                continue
            published = bytearray(_CAPACITY * _STRIDE)
            for index, (peer, speaking) in enumerate(members):
                offset = index * _STRIDE
                published[offset + 0x40:offset + 0x50] = peer
                published[offset + 0x5C] = peer == account
                published[offset + 0x5D] = speaking
            value = bytes(published)
            if value != old.published or len(members) != old.count:
                self._write_data(row + 0x98, bytes(4))
                self._write_data(row + 0xA0, value)
                self._write_data(row + 0x98, struct.pack("<i", len(members)))
                old.published, old.count = value, len(members)

    def update(self, snapshot: object):
        if not self.handle or self.result.process.poll() is not None:
            return dict(_EMPTY)
        try:
            parsed = _snapshot(snapshot)
            context, service, active, rows = self._native()
            render_key = (parsed, service, active, tuple(self._guards.items()))
            retry = parsed is not None and any(handle == active and not count and row not in self.borrowed for row, handle, uri, count in rows
                       for _, prefix, _ in parsed[1] if uri.startswith(prefix))
            if render_key != self._last_render or retry:
                if (parsed is not None and rows) or self.borrowed:
                    with self._transaction():
                        context, service, active, rows = self._native()
                        self._publish(parsed, service, active, rows)
                self._last_render = render_key
            selected = self._selected(context, active, rows)
            self.last_error = None
            return {"kind": selected, "speaking": bool(selected and self._held(context))}
        except (OSError, ValueError, struct.error) as error:
            self.last_error = str(error)
            try:
                if self.borrowed:
                    with self._transaction():
                        _, service, _, rows = self._native()
                        self._restore(service, rows)
            except (OSError, ValueError, struct.error):
                self.borrowed.clear()
            return dict(_EMPTY)

    def close(self):
        if self.handle:
            try:
                self.update(None)
            finally:
                self.api.close(self.handle)
                self.handle = None
