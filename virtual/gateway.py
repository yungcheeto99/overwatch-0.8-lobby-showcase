"""Bounded RFC 6455 binary gateway over an account-free SSH HTTP tunnel.

Original project code, without another implementation or new dependencies.
HTTPS verifies the public service certificate normally. Existing pinned TLS
bytes travel unchanged inside each binary WebSocket connection.
"""
from __future__ import annotations

import asyncio
import base64
from collections import deque
from contextlib import suppress
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import struct
import subprocess
from urllib.parse import urlsplit


GATEWAY_PATH = "/ow08/gateway"
CHUNK_SIZE = 65536
MAX_FRAME_BYTES = 1024 * 1024
MAX_MESSAGE_BYTES = MAX_FRAME_BYTES
MAX_HTTP_BYTES = 16384
MAX_CONNECTIONS = 128
CONNECT_TIMEOUT = 20
IO_TIMEOUT = 60
START_TIMEOUT = 60
PING_INTERVAL = 20
CLOSE_TIMEOUT = 1
_CLOSE_CODES = frozenset((1000, 1001, 1002, 1003, 1007, 1008, 1009,
                          1010, 1011, 1012, 1013, 1014))
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_PROVIDER_HOST = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.(?:lhr\.life|localhost\.run)"
_ASSIGNED_NOTICE = re.compile(
    r"(?:^|\n)(" + _PROVIDER_HOST + r") tunneled with tls termination, https://\1(?:\s|$)",
    re.IGNORECASE,
)
_REGISTERED_ID = re.compile(r"localhost/(" + _PROVIDER_HOST + r")\Z", re.IGNORECASE)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def normalize_endpoint(value: str) -> str:
    """Return https://host[:port] for a bare hostname or HTTPS/WSS URL."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter the host's public gateway hostname or HTTPS address")
    value = value.strip()
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("Gateway addresses cannot contain whitespace or control characters")
    try:
        parts = urlsplit(value if "://" in value else "https://" + value)
        port, hostname = parts.port, parts.hostname
    except ValueError as error:
        raise ValueError("Invalid gateway hostname or port") from error
    if (parts.scheme.lower() not in ("https", "wss") or not hostname
            or parts.username is not None or parts.password is not None
            or "?" in value or "#" in value
            or parts.path not in ("", "/", GATEWAY_PATH)):
        raise ValueError("Use a hostname or HTTPS/WSS address without credentials, query, or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Gateway port must be from 1 to 65535")
    hostname = hostname.rstrip(".")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("Invalid gateway hostname") from error
        if len(hostname) > 253 or any(not _LABEL.fullmatch(label) for label in hostname.split(".")):
            raise ValueError("Invalid gateway hostname")
    else:
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Gateway address must identify a unicast host")
        hostname = str(address)
        if address.version == 6:
            hostname = "[" + hostname + "]"
    return "https://" + hostname + (f":{port}" if port and port != 443 else "")


async def _close_writer(writer):
    if writer is not None:
        writer.close()
        with suppress(OSError, ValueError):
            await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)


async def _drain(writer):
    await asyncio.wait_for(writer.drain(), IO_TIMEOUT)


def _accept_key(key):
    return base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")


def _mask_payload(data: bytes, mask: bytes) -> bytes:
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))


async def _http_headers(reader):
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), CONNECT_TIMEOUT)
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError) as error:
        raise ValueError("Incomplete or oversized gateway HTTP headers") from error
    if len(raw) > MAX_HTTP_BYTES:
        raise ValueError("Gateway HTTP headers exceed size limit")
    try:
        lines = raw.decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("Gateway HTTP headers must be ASCII") from error
    headers = {}
    for line in lines[1:-2]:
        name, separator, value = line.partition(":")
        name = name.lower()
        if not separator or not _HEADER_NAME.fullmatch(name) or name in headers:
            raise ValueError("Invalid or duplicate gateway HTTP header")
        value = value.strip(" \t")
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
            raise ValueError("Invalid gateway HTTP header value")
        headers[name] = value
    return lines[0], headers


def _is_upgrade(headers):
    return (headers.get("upgrade", "").lower() == "websocket"
            and "upgrade" in [part.strip().lower() for part in headers.get("connection", "").split(",")])


class _ProtocolError(ValueError):
    def __init__(self, message, code=1002):
        super().__init__(message)
        self.code = code


class _WebSocket:
    def __init__(self, reader, writer, *, client):
        self.reader, self.writer, self.client = reader, writer, client
        self._lock = asyncio.Lock()
        self._sent_close = False

    async def send(self, data: bytes, opcode=2):
        if len(data) > MAX_FRAME_BYTES or (opcode >= 8 and len(data) > 125):
            raise ValueError("Gateway frame exceeds size limit")
        async with self._lock:
            if self._sent_close:
                return
            if opcode == 8:
                self._sent_close = True
            size, marker = len(data), 0x80 if self.client else 0
            if size < 126:
                header = bytes((0x80 | opcode, marker | size))
            elif size <= 65535:
                header = bytes((0x80 | opcode, marker | 126)) + struct.pack("!H", size)
            else:
                header = bytes((0x80 | opcode, marker | 127)) + struct.pack("!Q", size)
            if self.client:
                mask = secrets.token_bytes(4)
                data = _mask_payload(data, mask)
                header += mask
            self.writer.write(header + data)
            await _drain(self.writer)

    async def close(self, code=1000):
        with suppress(OSError, ValueError):
            await asyncio.wait_for(self.send(struct.pack("!H", code), 8), CLOSE_TIMEOUT)

    async def _frame(self):
        first, second = await asyncio.wait_for(self.reader.readexactly(2), IO_TIMEOUT)
        final, opcode = bool(first & 0x80), first & 0x0F
        masked, size = bool(second & 0x80), second & 0x7F
        if first & 0x70 or opcode not in (0, 1, 2, 8, 9, 10):
            raise _ProtocolError("Unsupported gateway WebSocket frame")
        if masked == self.client:
            raise _ProtocolError("Invalid gateway WebSocket masking direction")
        if opcode >= 8 and (not final or size >= 126):
            raise _ProtocolError("Invalid gateway WebSocket control frame")
        if size == 126:
            size = struct.unpack("!H", await asyncio.wait_for(self.reader.readexactly(2), IO_TIMEOUT))[0]
            if size < 126:
                raise _ProtocolError("Noncanonical gateway frame length")
        elif size == 127:
            size = struct.unpack("!Q", await asyncio.wait_for(self.reader.readexactly(8), IO_TIMEOUT))[0]
            if size < 65536 or size >> 63:
                raise _ProtocolError("Noncanonical gateway frame length")
        if size > MAX_FRAME_BYTES:
            raise _ProtocolError("Gateway frame exceeds size limit", 1009)
        mask = await asyncio.wait_for(self.reader.readexactly(4), IO_TIMEOUT) if masked else None
        data = await asyncio.wait_for(self.reader.readexactly(size), IO_TIMEOUT)
        if mask:
            data = _mask_payload(data, mask)
        return final, opcode, data

    async def receive(self):
        message = bytearray()
        fragmented = False
        while True:
            try:
                final, opcode, data = await self._frame()
            except asyncio.IncompleteReadError:
                return None
            if opcode == 8:
                if len(data) == 1:
                    raise _ProtocolError("Invalid gateway close payload")
                if data:
                    code = struct.unpack("!H", data[:2])[0]
                    if code not in _CLOSE_CODES and not 3000 <= code <= 4999:
                        raise _ProtocolError("Invalid gateway close status")
                    try:
                        data[2:].decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise _ProtocolError("Invalid gateway close reason", 1007) from error
                await self.send(data, 8)
                return None
            if opcode == 9:
                await self.send(data, 10)
                continue
            if opcode == 10:
                continue
            if opcode == 1:
                raise _ProtocolError("Gateway accepts binary data only", 1003)
            if (opcode == 0 and not fragmented) or (opcode == 2 and fragmented):
                raise _ProtocolError("Invalid gateway WebSocket fragmentation")
            message.extend(data)
            if len(message) > MAX_MESSAGE_BYTES:
                raise _ProtocolError("Gateway message exceeds size limit", 1009)
            if final:
                return bytes(message)
            fragmented = True


async def _bridge(socket: _WebSocket, reader, writer):
    async def to_gateway():
        while data := await reader.read(CHUNK_SIZE):
            await socket.send(data)

    async def from_gateway():
        while (data := await socket.receive()) is not None:
            if data:
                writer.write(data)
                await _drain(writer)

    async def heartbeat():
        while True:
            await asyncio.sleep(PING_INTERVAL)
            await socket.send(secrets.token_bytes(8), 9)

    tasks = [asyncio.create_task(operation()) for operation in (to_gateway, from_gateway, heartbeat)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except _ProtocolError as error:
        await socket.close(error.code)
        raise
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await socket.close()


async def _open_websocket(endpoint, context):
    parts = urlsplit(endpoint)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            parts.hostname, parts.port or 443, ssl=context, server_hostname=parts.hostname,
            ssl_handshake_timeout=CONNECT_TIMEOUT, ssl_shutdown_timeout=1,
            limit=MAX_HTTP_BYTES), CONNECT_TIMEOUT)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (f"GET {GATEWAY_PATH} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        writer.write(request.encode("ascii"))
        await _drain(writer)
        status, headers = await _http_headers(reader)
        if not status.startswith("HTTP/1.1 101 ") or not _is_upgrade(headers):
            raise ConnectionError("Public gateway refused the WebSocket connection; check the identifier and that the host is running")
        if (headers.get("sec-websocket-accept") != _accept_key(key)
                or "sec-websocket-extensions" in headers or "sec-websocket-protocol" in headers):
            raise ConnectionError("Invalid public gateway WebSocket handshake")
        return _WebSocket(reader, writer, client=True)
    except BaseException:
        await _close_writer(writer)
        raise


class _LocalService:
    def __init__(self):
        self._server = None
        self._tasks = set()
        self._closed = False
        self._close_lock = asyncio.Lock()

    async def start(self):
        if self._closed or self._server is not None:
            raise RuntimeError("Gateway can only be started once")
        self._server = await asyncio.start_server(self._connected, "127.0.0.1", 0, limit=MAX_HTTP_BYTES)
        return self._server.sockets[0].getsockname()[:2]

    async def close(self):
        async with self._close_lock:
            self._closed = True
            server = self._server
            if server is not None:
                server.close()
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if server is not None:
                await server.wait_closed()
                self._server = None


class GatewayBridge(_LocalService):
    """Loopback HTTP WebSocket endpoint for one fixed loopback backend."""
    def __init__(self, target):
        super().__init__()
        if (not isinstance(target, tuple) or len(target) != 2 or target[0] != "127.0.0.1"
                or type(target[1]) is not int or not 1 <= target[1] <= 65535):
            raise ValueError("Public gateway requires a fixed 127.0.0.1 backend and TCP port")
        self.target = target

    async def _connected(self, reader, writer):
        task = asyncio.current_task()
        backend_writer = None
        if self._closed or len(self._tasks) >= MAX_CONNECTIONS:
            writer.write(b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await _close_writer(writer)
            return
        self._tasks.add(task)
        upgraded = False
        try:
            status, headers = await _http_headers(reader)
            if status != f"GET {GATEWAY_PATH} HTTP/1.1":
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await _drain(writer)
                return
            key = headers.get("sec-websocket-key", "")
            try:
                decoded_key = base64.b64decode(key, validate=True)
            except ValueError:
                decoded_key = b""
            if (not _is_upgrade(headers) or headers.get("sec-websocket-version") != "13"
                    or len(decoded_key) != 16 or not headers.get("host")
                    or "content-length" in headers or "transfer-encoding" in headers):
                raise ValueError("Invalid gateway WebSocket handshake")
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(*self.target, limit=CHUNK_SIZE), CONNECT_TIMEOUT)
            response = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Accept: {_accept_key(key)}\r\n\r\n")
            writer.write(response.encode("ascii"))
            await _drain(writer)
            upgraded = True
            await _bridge(_WebSocket(reader, writer, client=False), backend_reader, backend_writer)
        except (OSError, ValueError):
            if not upgraded:
                with suppress(OSError):
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await _drain(writer)
        finally:
            await _close_writer(backend_writer)
            await _close_writer(writer)
            self._tasks.discard(task)


class ClientTunnel(_LocalService):
    """Translate local pinned TLS TCP streams to the public HTTPS gateway."""
    def __init__(self, identifier):
        super().__init__()
        self.endpoint = normalize_endpoint(identifier)
        self._context = ssl.create_default_context()
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.last_error = None

    async def start(self):
        if self._closed or self._server is not None:
            raise RuntimeError("Gateway can only be started once")
        try:
            # Newly assigned provider names can take a few seconds to become
            # reachable. Never retry a certificate verification failure.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + CONNECT_TIMEOUT
            while True:
                try:
                    probe = await asyncio.wait_for(
                        _open_websocket(self.endpoint, self._context), deadline - loop.time())
                    break
                except ssl.SSLError:
                    raise
                except OSError:
                    if loop.time() >= deadline:
                        raise
                    await asyncio.sleep(min(1, deadline - loop.time()))
            try:
                await probe.close()
            finally:
                await _close_writer(probe.writer)
            return await super().start()
        except BaseException:
            await self.close()
            raise

    async def _connected(self, reader, writer):
        task = asyncio.current_task()
        if self._closed or len(self._tasks) >= MAX_CONNECTIONS:
            await _close_writer(writer)
            return
        self._tasks.add(task)
        socket = None
        try:
            socket = await _open_websocket(self.endpoint, self._context)
            await _bridge(socket, reader, writer)
        except (OSError, ValueError) as error:
            self.last_error = str(error)
        finally:
            if socket is not None:
                await _close_writer(socket.writer)
            await _close_writer(writer)
            self._tasks.discard(task)


class PublicHost:
    """Publish a fixed gateway using system SSH and a random session hostname."""
    def __init__(self, target: tuple[str, int], data_dir: Path, *, on_endpoint_change=None):
        self._gateway = GatewayBridge(target)
        self.data_dir = Path(data_dir)
        self.endpoint = None
        # Called with (new endpoint, previous endpoint) for the first assignment
        # and each subsequent change; repeated provider notices are ignored.
        self._on_endpoint_change = on_endpoint_change
        self._process = None
        self._drainer = None
        self._watcher = None
        self._ready = None
        self._closing = False
        self._failure = None
        self._logs = deque(maxlen=16)
        self._close_lock = asyncio.Lock()

    def _error(self):
        detail = " ".join(self._logs)[-2048:].strip()
        return RuntimeError("Public gateway SSH tunnel stopped" + (f": {detail}" if detail else "; check Internet access to localhost.run"))

    async def start(self) -> str:
        if self._closing or self._process is not None:
            raise RuntimeError("Public gateway can only be started once")
        ssh = shutil.which("ssh")
        if not ssh and os.name == "nt":
            candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
            if candidate.is_file():
                ssh = str(candidate)
        if not ssh:
            raise RuntimeError("Public hosting requires the system OpenSSH Client. On Windows, add OpenSSH Client under Settings > System > Optional features, then retry.")
        self._ready = asyncio.get_running_loop().create_future()
        try:
            known_hosts = self.data_dir / "virtual" / "known_hosts"
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            _, port = await self._gateway.start()
            command = [ssh, "-F", "none", "-T", "-o", "BatchMode=yes",
                       "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=none",
                       "-o", "PreferredAuthentications=none", "-o", "PasswordAuthentication=no",
                       "-o", "KbdInteractiveAuthentication=no", "-o", "PubkeyAuthentication=no",
                       "-o", "StrictHostKeyChecking=accept-new", "-o", f'UserKnownHostsFile="{known_hosts.as_posix()}"',
                       "-o", "GlobalKnownHostsFile=" + ("NUL" if os.name == "nt" else "/dev/null"),
                       "-o", "ExitOnForwardFailure=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
                       "-o", "ServerAliveInterval=20", "-o", "ServerAliveCountMax=3",
                       "-R", f"80:127.0.0.1:{port}", "nokey@localhost.run", "--", "--output", "json"]
            self._process = await asyncio.create_subprocess_exec(
                *command, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self._drainer = asyncio.create_task(self._read_output())
            self._watcher = asyncio.create_task(self._watch_process())
            try:
                await asyncio.wait_for(asyncio.shield(self._ready), START_TIMEOUT)
            except TimeoutError as error:
                raise RuntimeError("The public gateway did not assign an address within 60 seconds; check Internet access to localhost.run") from error
            if self._watcher.done():
                raise self._failure or self._error()
            return self.endpoint
        except BaseException:
            await self.close()
            raise

    async def _read_output(self):
        buffer = ""
        while data := await self._process.stdout.read(4096):
            text = _ANSI.sub("", data.decode("utf-8", errors="replace"))
            text = "".join(char for char in text if char in "\r\n\t" or char.isprintable())
            self._logs.append(text[-512:])
            buffer = (buffer + text)[-65536:]
            announced = []
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                try:
                    event = json.loads(line)
                except ValueError:
                    # Older output formats are accepted only when they contain
                    # an explicit tunnel announcement, never a banner URL.
                    match = _ASSIGNED_NOTICE.search(line)
                    if match:
                        announced.append(match.group(1))
                    continue
                if isinstance(event, dict) and event.get("type") == "v1.tcpip_forward.register.accepted":
                    identifier = event.get("id")
                    match = _REGISTERED_ID.fullmatch(identifier) if isinstance(identifier, str) else None
                    if match:
                        announced.append(match.group(1))
            for hostname in announced:
                endpoint = normalize_endpoint("https://" + hostname)
                if self.endpoint == endpoint:
                    continue
                previous_endpoint = self.endpoint
                self.endpoint = endpoint
                if self._on_endpoint_change is not None:
                    self._on_endpoint_change(endpoint, previous_endpoint)
                if not self._ready.done():
                    self._ready.set_result(endpoint)

    async def _watch_process(self):
        await self._process.wait()
        await self._drainer
        if not self._closing:
            self._failure = self._failure or self._error()
            if not self._ready.done():
                self._ready.set_exception(self._failure)

    async def wait(self):
        """Wait for SSH exit; cancellation does not stop output draining."""
        if self._watcher is None:
            raise RuntimeError("Public gateway has not started")
        await asyncio.shield(self._watcher)
        if not self._closing:
            raise self._failure or self._error()

    async def close(self):
        async with self._close_lock:
            self._closing = True
            await self._gateway.close()
            if self._process is not None and self._process.returncode is None:
                with suppress(ProcessLookupError):
                    self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), 3)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        self._process.kill()
                    await self._process.wait()
            if self._watcher is not None:
                await asyncio.gather(self._watcher, return_exceptions=True)
            elif self._drainer is not None:
                await asyncio.gather(self._drainer, return_exceptions=True)
            if self._ready is not None and not self._ready.done():
                self._ready.cancel()
            elif self._ready is not None and not self._ready.cancelled():
                self._ready.exception()
