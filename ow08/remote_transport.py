"""Pinned TLS launch transport with one local gateway for each native client.

The remote listener exposes only authenticated control and capabilities for
three fixed, server-selected loopback services. The native game continues to
use loopback endpoints; its TLS bytes pass unchanged through this outer TLS
connection. Neither native process handles nor server private keys travel here.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import ssl
from collections.abc import Callable


MESSAGE_LIMIT = 4096
CONNECT_TIMEOUT = 10
CHUNK_SIZE = 65536
MAX_CONNECTIONS = 128
MAX_STREAMS_PER_LAUNCH = 32
SERVICES = frozenset(("bootstrap", "web", "lobby"))
DEFAULT_PORT = 47325
_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")


def _hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _port(value, *, ephemeral=False) -> bool:
    return type(value) is int and (0 if ephemeral else 1) <= value <= 65535


def _ipv4(value, *, listening=False) -> str:
    if not isinstance(value, str):
        raise ValueError("Remote host must be a literal IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("Remote host must be a literal IPv4 address") from error
    if address.is_multicast or value == "255.255.255.255" or (address.is_unspecified and not listening):
        raise ValueError("Remote host must identify a unicast IPv4 endpoint")
    return str(address)


def validate_descriptor(descriptor: dict) -> dict:
    """Validate a copied invitation before opening a socket or sending a token."""
    if not isinstance(descriptor, dict) or type(descriptor.get("version")) is not int or descriptor["version"] != 2:
        raise ValueError("Remote invitation must use version 2")
    host = _ipv4(descriptor.get("host"))
    if not _port(descriptor.get("port")):
        raise ValueError("Remote invitation requires a TCP port from 1 to 65535")
    if not _hex64(descriptor.get("token")) or not _hex64(descriptor.get("tls_sha256")):
        raise ValueError("Remote invitation requires a 64-digit token and SHA-256 certificate pin")
    return {"version": 2, "host": host, "port": descriptor["port"],
            "token": descriptor["token"], "tls_sha256": descriptor["tls_sha256"].lower()}


async def _receive(reader: asyncio.StreamReader) -> dict:
    try:
        line = await reader.readline()
    except (ValueError, asyncio.LimitOverrunError) as error:
        raise ValueError("Remote transport message exceeds size limit") from error
    if not line:
        raise ConnectionError("Remote transport disconnected")
    if len(line) > MESSAGE_LIMIT or not line.endswith(b"\n"):
        raise ValueError("Invalid remote transport message")
    try:
        message = json.loads(line)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("Invalid remote transport JSON") from error
    if not isinstance(message, dict):
        raise ValueError("Remote transport message must be an object")
    return message


async def _send(writer: asyncio.StreamWriter, **message):
    data = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(data) > MESSAGE_LIMIT:
        raise ValueError("Remote transport message exceeds size limit")
    writer.write(data)
    await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter | None):
    if writer is not None:
        writer.close()
        with suppress(OSError, TimeoutError, ValueError):
            await asyncio.wait_for(writer.wait_closed(), 1)


def _server_pins(path: Path) -> dict:
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if (not isinstance(saved, dict) or type(saved.get("version")) is not int
            or saved["version"] != 1 or not isinstance(saved.get("pins"), dict)
            or any(not isinstance(endpoint, str) or not _hex64(pin)
                   for endpoint, pin in saved["pins"].items())):
        raise ValueError("Invalid saved server certificate pins")
    return {endpoint: pin.lower() for endpoint, pin in saved["pins"].items()}


def _save_server_pin(path: Path, endpoint: str, pin: str, *, replace=False):
    pins = _server_pins(path)
    if endpoint in pins and pins[endpoint] != pin and not replace:
        raise ValueError("Server certificate pin changed during connection")
    if pins.get(endpoint) == pin:
        return
    pins[endpoint] = pin
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(json.dumps({"version": 1, "pins": pins}, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


async def _open_tls(host: str, port: int):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=context, server_hostname=None,
            ssl_handshake_timeout=CONNECT_TIMEOUT, ssl_shutdown_timeout=1,
            limit=MESSAGE_LIMIT), CONNECT_TIMEOUT)
        tls = writer.get_extra_info("ssl_object")
        certificate = tls.getpeercert(binary_form=True) if tls is not None else None
        if not certificate:
            raise ValueError("Remote server did not provide a TLS certificate")
        return reader, writer, hashlib.sha256(certificate).hexdigest()
    except BaseException:
        await _close_writer(writer)
        raise


async def discover_server(host: str, port: int = DEFAULT_PORT, *, trust_file: Path,
                          expected_pin: str | None = None,
                          tunnel_identity: str | None = None) -> dict:
    """Join by IP on a trusted LAN/VPN, remembering the certificate on first use.

    First contact relies on the selected network being trusted; --server-pin
    permits verification against the fingerprint printed by the server. Future
    connections check the saved pin before requesting any per-run join token.
    Only public certificate pins are saved, never invitation tokens or RSA keys.

    A tunnel connects through a client-local TCP proxy. Its canonical public
    identifier owns the saved pin, while the invitation must advertise a
    loopback listener and is rewritten to the proxy's local endpoint.
    """
    host = _ipv4(host)
    if not _port(port):
        raise ValueError("Remote server requires a TCP port from 1 to 65535")
    if expected_pin is not None and not _hex64(expected_pin):
        raise ValueError("--server-pin requires a 64-digit SHA-256 certificate pin")
    if tunnel_identity is not None and (not isinstance(tunnel_identity, str) or not tunnel_identity):
        raise ValueError("A tunnel requires its public identifier")
    path = Path(trust_file)
    endpoint = tunnel_identity if tunnel_identity is not None else f"{host}:{port}"
    saved = _server_pins(path)
    pin = expected_pin.lower() if expected_pin is not None else saved.get(endpoint)
    writer = None
    try:
        reader, writer, observed = await _open_tls(host, port)
        if pin is not None and not hmac.compare_digest(pin, observed):
            raise ValueError("Server certificate changed or does not match --server-pin; "
                             "verify its SHA256 and supply --server-pin to trust a new certificate")
        await _send(writer, event="discover", kind="discovery", version=1)
        reply = await asyncio.wait_for(_receive(reader), CONNECT_TIMEOUT)
        if reply.get("event") != "invitation":
            raise ValueError("Server does not support joining by IP")
        descriptor = validate_descriptor(reply)
        matching_endpoint = (descriptor["host"] == "127.0.0.1" if tunnel_identity is not None
                             else descriptor["host"] == host and descriptor["port"] == port)
        if (not matching_endpoint
                or not hmac.compare_digest(descriptor["tls_sha256"], observed)):
            raise ValueError("Server returned an invitation for a different TLS endpoint")
        _save_server_pin(path, endpoint, observed, replace=expected_pin is not None)
        if pin is None:
            print(f"First connection: saved server certificate SHA256 {observed}", flush=True)
        if tunnel_identity is not None:
            descriptor = dict(descriptor, host=host, port=port)
        return descriptor
    finally:
        await _close_writer(writer)


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    while data := await reader.read(CHUNK_SIZE):
        writer.write(data)
        await writer.drain()


async def _forward(front_reader, front_writer, back_reader, back_writer):
    tasks = [asyncio.create_task(_pump(front_reader, back_writer)),
             asyncio.create_task(_pump(back_reader, front_writer))]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            await task
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class RemoteListener:
    """One TLS port carrying bounded control sessions and per-launch streams."""

    def __init__(self, callback_control: Callable, resolve_service: Callable,
                 token: str, ssl_context: ssl.SSLContext, *, discovery_pin: str | None = None):
        if not _hex64(token):
            raise ValueError("Remote listener requires a 64-digit launch token")
        if not isinstance(ssl_context, ssl.SSLContext):
            raise ValueError("Remote listener requires a server TLS context")
        if discovery_pin is not None and not _hex64(discovery_pin):
            raise ValueError("Joining by IP requires the server SHA-256 certificate pin")
        ssl_context.minimum_version = max(ssl_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.callback_control, self.resolve_service = callback_control, resolve_service
        self.token, self.ssl_context = token, ssl_context
        # IP joining deliberately admits network peers to the login boundary;
        # account authentication and per-launch stream capabilities still apply.
        self.discovery_pin = discovery_pin.lower() if discovery_pin is not None else None
        self.endpoint: tuple[str, int] | None = None
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._streams: dict[str, set[asyncio.Task]] = {}
        self._closing = False
        self._closed = False
        self._close_lock = asyncio.Lock()

    async def start(self, host: str, port: int) -> tuple[str, int]:
        if self._server is not None or self._closing:
            raise RuntimeError("Remote listener cannot be started twice")
        host = _ipv4(host, listening=True)
        if not _port(port, ephemeral=True):
            raise ValueError("Remote listen port must be from 0 to 65535")
        self._server = await asyncio.start_server(
            self._connected, host, port, ssl=self.ssl_context,
            ssl_handshake_timeout=CONNECT_TIMEOUT, ssl_shutdown_timeout=1,
            limit=MESSAGE_LIMIT, backlog=MAX_CONNECTIONS)
        self.endpoint = (host, self._server.sockets[0].getsockname()[1])
        return self.endpoint

    def _valid_control(self, hello: dict) -> bool:
        ports = hello.get("gateway_ports")
        return (hello.get("event") == "attach" and hello.get("kind") == "control"
                and type(hello.get("version")) is int and hello["version"] == 1
                and _hex64(hello.get("token"))
                and hmac.compare_digest(hello["token"], self.token)
                and isinstance(ports, dict) and set(ports) == {"web", "lobby"}
                and all(_port(port) for port in ports.values()))

    async def _connected(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        backend_writer = None
        capability = None
        try:
            if self._closing or len(self._tasks) > MAX_CONNECTIONS:
                return
            hello = await asyncio.wait_for(_receive(reader), CONNECT_TIMEOUT)
            if hello.get("kind") == "discovery":
                if (self.discovery_pin is not None and self.endpoint is not None
                        and hello.get("event") == "discover"
                        and type(hello.get("version")) is int and hello["version"] == 1):
                    await _send(writer, event="invitation", version=2,
                                host=self.endpoint[0], port=self.endpoint[1],
                                token=self.token, tls_sha256=self.discovery_pin)
                return
            if hello.get("kind") == "control":
                if not self._valid_control(hello):
                    await _send(writer, event="error", message="Remote launch could not be authenticated")
                    return
                await self.callback_control(reader, writer, hello)
                return
            service = hello.get("service")
            if (hello.get("event") != "stream" or hello.get("kind") != "stream"
                    or type(hello.get("version")) is not int or hello["version"] != 1
                    or not _hex64(hello.get("capability"))
                    or not isinstance(service, str) or service not in SERVICES):
                return
            capability = hello["capability"]
            streams = self._streams.setdefault(capability, set())
            if len(streams) >= MAX_STREAMS_PER_LAUNCH:
                return
            endpoint = self.resolve_service(capability, service)
            if (not isinstance(endpoint, tuple) or len(endpoint) != 2
                    or endpoint[0] != "127.0.0.1" or not _port(endpoint[1])):
                return
            streams.add(task)
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(*endpoint, limit=CHUNK_SIZE), CONNECT_TIMEOUT)
            # Opening a socket yields; a disconnected launcher can revoke the
            # capability meanwhile. Do not accept a stale connection afterward.
            if self.resolve_service(capability, service) != endpoint:
                return
            await _send(writer, event="stream-ready")
            await _forward(reader, writer, backend_reader, backend_writer)
        except (OSError, TimeoutError, ValueError, ConnectionError):
            # This transport never reflects supplied tokens or backend details.
            pass
        finally:
            await _close_writer(backend_writer)
            await _close_writer(writer)
            if capability is not None:
                streams = self._streams.get(capability)
                if streams is not None:
                    streams.discard(task)
                    if not streams:
                        self._streams.pop(capability, None)
            self._tasks.discard(task)

    async def close_capability(self, capability: str):
        """Cancel active streams after the Coordinator removes a launch."""
        tasks = list(self._streams.get(capability, ()))
        current = asyncio.current_task()
        for task in tasks:
            if task is not current:
                task.cancel()
        await asyncio.gather(*(task for task in tasks if task is not current), return_exceptions=True)

    async def close(self):
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            if self._server is not None:
                self._server.close()
            tasks = list(self._tasks)
            current = asyncio.current_task()
            for task in tasks:
                if task is not current:
                    task.cancel()
            await asyncio.gather(*(task for task in tasks if task is not current), return_exceptions=True)
            if self._server is not None:
                await self._server.wait_closed()
            self._closed = True


class RemoteGateway:
    """Client-local native endpoints carried through a pinned outer TLS link."""

    def __init__(self, descriptor: dict):
        self.descriptor = validate_descriptor(descriptor)
        self.ports: dict[str, int] = {}
        self.capability: str | None = None
        self._listeners: dict[str, asyncio.Server] = {}
        self._tasks: set[asyncio.Task] = set()
        self._control_writer: asyncio.StreamWriter | None = None
        self._ready = asyncio.Event()
        self._starting = False
        self._closing = False
        self._closed = False
        self._close_lock = asyncio.Lock()

    def endpoint(self, service: str) -> str:
        if service not in self.ports:
            raise ValueError("Gateway service is not listening")
        return f"127.0.0.1:{self.ports[service]}"

    async def _connect(self):
        writer = None
        try:
            reader, writer, observed = await _open_tls(self.descriptor["host"], self.descriptor["port"])
            if not hmac.compare_digest(observed, self.descriptor["tls_sha256"]):
                raise ValueError("Remote server TLS certificate does not match the invitation")
            # The token/capability is only sent by the caller after this check.
            return reader, writer
        except BaseException:
            await _close_writer(writer)
            raise

    async def start(self):
        if self._starting or self._closing:
            raise RuntimeError("Remote gateway cannot be started twice")
        self._starting = True
        try:
            for service in ("web", "lobby", "bootstrap"):
                async def connected(reader, writer, service=service):
                    await self._connected(service, reader, writer)
                server = await asyncio.start_server(connected, "127.0.0.1", 0,
                                                    limit=CHUNK_SIZE, backlog=MAX_STREAMS_PER_LAUNCH)
                self._listeners[service] = server
                self.ports[service] = server.sockets[0].getsockname()[1]
            reader, self._control_writer = await self._connect()
            await _send(self._control_writer, event="attach", kind="control", version=1,
                        token=self.descriptor["token"],
                        gateway_ports={service: self.ports[service] for service in ("web", "lobby")})
            welcome = await asyncio.wait_for(_receive(reader), CONNECT_TIMEOUT)
            if welcome.get("event") == "error":
                raise ConnectionError("Remote server rejected the launch invitation")
            if welcome.get("event") != "launch" or not _hex64(welcome.get("capability")):
                raise ValueError("Remote server did not provide a valid launch capability")
            self.capability = welcome["capability"]
            welcome = dict(welcome, bnet_endpoint=self.endpoint("bootstrap"))
            self._ready.set()
            return reader, self._control_writer, welcome
        except BaseException:
            await self.close()
            raise

    async def _connected(self, service, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        remote_writer = None
        try:
            if self._closing or len(self._tasks) > MAX_STREAMS_PER_LAUNCH:
                return
            await asyncio.wait_for(self._ready.wait(), CONNECT_TIMEOUT)
            if self._closing or self.capability is None:
                return
            remote_reader, remote_writer = await self._connect()
            await _send(remote_writer, event="stream", kind="stream", version=1,
                        capability=self.capability, service=service)
            ready = await asyncio.wait_for(_receive(remote_reader), CONNECT_TIMEOUT)
            if ready.get("event") != "stream-ready":
                return
            await _forward(reader, writer, remote_reader, remote_writer)
        except (OSError, TimeoutError, ValueError, ConnectionError):
            pass
        finally:
            await _close_writer(remote_writer)
            await _close_writer(writer)
            self._tasks.discard(task)

    async def close(self):
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            self._ready.set()
            for listener in self._listeners.values():
                listener.close()
            await _close_writer(self._control_writer)
            tasks = list(self._tasks)
            current = asyncio.current_task()
            for task in tasks:
                if task is not current:
                    task.cancel()
            await asyncio.gather(*(task for task in tasks if task is not current), return_exceptions=True)
            for listener in self._listeners.values():
                await listener.wait_closed()
            self._closed = True
