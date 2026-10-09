"""Per-launch loopback relays that preserve TLS bytes and launcher identity.

The launcher owns its child and its patch event. A relay registers its backend
source address before connect, so the shared bootstrap can identify that launch
without accepting a PID or guessing from whichever launcher connected last.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import secrets
import socket
import threading
from typing import Callable


CHUNK_SIZE = 65536


@dataclass(frozen=True)
class Registration:
    address: tuple[str, int]
    launcher_id: str
    generation: str


class LaunchRegistry:
    """Small synchronized bridge from backend TCP peer to launch identity."""
    def __init__(self):
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, int], Registration] = {}

    def register(self, address: tuple[str, int], launcher_id: str) -> Registration:
        if address[0] != "127.0.0.1" or not 0 < address[1] < 65536 or not launcher_id:
            raise ValueError("launch registration requires a loopback socket and launch identity")
        registration = Registration(address, launcher_id, secrets.token_hex(16))
        with self._lock:
            if address in self._entries:
                raise ValueError("backend socket is already registered")
            self._entries[address] = registration
        return registration

    def resolve(self, peer: tuple[str, int]) -> str | None:
        with self._lock:
            registration = self._entries.get(peer)
            return registration.launcher_id if registration is not None else None

    def unregister(self, registration: Registration) -> bool:
        with self._lock:
            if self._entries.get(registration.address) != registration:
                return False
            self._entries.pop(registration.address)
            return True


class LaunchRelay:
    """One ephemeral frontend for one launch, with bounded forwarding buffers."""
    def __init__(self, registry: LaunchRegistry, launcher_id: str,
                 bootstrap_endpoint: tuple[str, int], patched: asyncio.Event, *,
                 patch_timeout: float = 15, connect_timeout: float = 10,
                 event: Callable[..., None] = lambda *args, **kwargs: None):
        if (bootstrap_endpoint[0] != "127.0.0.1"
                or not 0 < bootstrap_endpoint[1] < 65536 or not launcher_id):
            raise ValueError("launch relay requires a loopback bootstrap endpoint and launch identity")
        if not isinstance(patched, asyncio.Event) or not patch_timeout > 0 or not connect_timeout > 0:
            raise ValueError("launch relay requires an asyncio patch event and positive timeouts")
        self.registry, self.launcher_id = registry, launcher_id
        self.bootstrap_endpoint, self.patched = bootstrap_endpoint, patched
        self.patch_timeout, self.connect_timeout, self.event = patch_timeout, connect_timeout, event
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._closing = False
        self._close_lock = asyncio.Lock()
        self._closed = False
        self.endpoint = None

    async def start(self) -> str:
        if self._server is not None or self._closing:
            raise RuntimeError("launch relay cannot be started twice")
        self._server = await asyncio.start_server(self._connected, "127.0.0.1", 0, limit=CHUNK_SIZE)
        port = self._server.sockets[0].getsockname()[1]
        self.endpoint = ("127.0.0.1", port)
        return f"127.0.0.1:{port}"

    @staticmethod
    async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while chunk := await reader.read(CHUNK_SIZE):
            writer.write(chunk)
            await writer.drain()

    async def _connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        self._tasks.add(task)
        backend_socket = backend_writer = registration = None
        pumps = []
        try:
            if self._closing:
                return
            await asyncio.wait_for(self.patched.wait(), self.patch_timeout)
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_socket.setblocking(False)
            backend_socket.bind(("127.0.0.1", 0))
            registration = self.registry.register(backend_socket.getsockname(), self.launcher_id)
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(
                backend_socket, self.bootstrap_endpoint), self.connect_timeout)
            backend_reader, backend_writer = await asyncio.open_connection(sock=backend_socket, limit=CHUNK_SIZE)
            backend_socket = None  # asyncio now owns it.
            self.event("launch_relay_connected", launcher_id=self.launcher_id)
            pumps = [asyncio.create_task(self._pump(reader, backend_writer)),
                     asyncio.create_task(self._pump(backend_reader, writer))]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for finished in done:
                await finished
        except (OSError, TimeoutError, ValueError) as error:
            self.event("launch_relay_error", launcher_id=self.launcher_id,
                       error_type=type(error).__name__)
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            if registration is not None:
                self.registry.unregister(registration)
            if backend_socket is not None:
                backend_socket.close()
            for stream in (backend_writer, writer):
                if stream is not None:
                    stream.close()
                    with suppress(OSError, TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 1)
            self._tasks.discard(task)

    async def close(self):
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            if self._server is not None:
                self._server.close()
            tasks = list(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if self._server is not None:
                # Recent Python waits for active transports as well as the listener.
                # Cancel handlers first, so their finally blocks close those streams.
                await self._server.wait_closed()
            self._closed = True
