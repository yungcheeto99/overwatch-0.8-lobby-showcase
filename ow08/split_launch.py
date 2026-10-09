"""Separate menu launchers with local control and optional pinned TLS gateways.

The client launcher alone owns and patches its child. The server holds each
TLS socket until its launcher reports checked preparation, restores after the
first RPC, and restores RSA before accepting the lobby. No PID is accepted
from the control socket and no private RSA material crosses it.
"""
from __future__ import annotations

import asyncio
from contextlib import closing, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import errno
import json
import ipaddress
from pathlib import Path
import secrets
import ssl
import threading

from .bootstrap import BootstrapServer, DEFAULT_CERT, DEFAULT_KEY
from .client import (ClientLaunchError, launch_client, prepare_lobby_rsa, prepare_tls_patches,
                     restore_login_patches, restore_tls_patches, stop_client)
from .certificate import prepare_project_certificate, certificate_is_windows_trusted
from .local_rsa import DEFAULT_LOCAL_KEY, load_or_generate_local_key, local_modulus_le
from .packet_log import colorize, console_color
from .server import serve


DEFAULT_STATE = Path(__file__).resolve().parents[1] / "data" / "local-menu-server.json"
MESSAGE_LIMIT = 4096
CONTROL_TIMEOUT = 10


async def receive(reader):
    line = await reader.readline()
    if not line:
        raise ConnectionError("The other launcher disconnected")
    if len(line) > MESSAGE_LIMIT or not line.endswith(b"\n"):
        raise ValueError("Invalid launcher control message")
    message = json.loads(line)
    if not isinstance(message, dict):
        raise ValueError("Launcher control message must be an object")
    return message


async def send(writer, **message):
    encoded = json.dumps(message).encode("ascii") + b"\n"
    if len(encoded) > MESSAGE_LIMIT:
        raise ValueError("Launcher control message exceeds size limit")
    writer.write(encoded)
    await writer.drain()


@dataclass
class ClientConnection:
    writer: asyncio.StreamWriter
    patched: bool = False
    restored: bool = False
    restoration: asyncio.Future | None = None
    restoration_cid: int | None = None
    restoration_cycle: int = 0
    tls_restoration: asyncio.Future | None = None
    tls_preparation: asyncio.Future | None = None
    tls_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    tls_owner: str | None = None
    tls_cycle: int = 0
    tls_restore_sent: bool = False
    rsa_preparation: asyncio.Future | None = None
    rsa_cid: int | None = None
    rsa_owner: str | None = None
    rsa_account_id: int | None = None
    rsa_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    launcher_id: str | None = None
    patch_event: asyncio.Event | None = None
    relay: object = None
    gateway_ports: dict | None = None
    capability: str | None = None


class Coordinator:
    def __init__(self, gate, modulus, bnet_endpoint, rsa_only=False, registry=None, admissions=None,
                 *, web_endpoint=None, lobby_endpoint=None):
        self.gate, self.modulus, self.bnet_endpoint = gate, modulus, bnet_endpoint
        self.rsa_only = rsa_only
        self.token = secrets.token_hex(32)
        self.active = None
        self.tasks = set()
        self.registry = registry
        self.admissions = admissions
        self.clients = {}
        self.web_endpoint, self.lobby_endpoint = web_endpoint, lobby_endpoint
        self.on_remote_disconnect = None

    def endpoint_context(self, launcher_id):
        """Addresses seen by this native client, never backend targets."""
        connection = self.clients.get(launcher_id)
        if connection is None or connection.gateway_ports is None:
            return None
        return {service: ("127.0.0.1", port) for service, port in connection.gateway_ports.items()}

    def advertised_endpoint(self, launcher_id):
        endpoints = self.endpoint_context(launcher_id)
        return endpoints["lobby"] if endpoints is not None else None

    def resolve_service(self, capability, service):
        """A live launch grants access only to its three fixed local services."""
        if not isinstance(capability, str) or len(capability) != 64 or not capability.isascii():
            return None
        for connection in self.clients.values():
            if (connection.capability is not None and not connection.writer.is_closing()
                    and hmac.compare_digest(capability, connection.capability)):
                if service == "bootstrap":
                    return connection.relay.endpoint
                return {"web": self.web_endpoint, "lobby": self.lobby_endpoint}.get(service)
        return None

    async def connected(self, reader, writer, *, hello=None, remote=False):
        task = asyncio.current_task()
        self.tasks.add(task)
        connection = None
        try:
            if hello is None:
                hello = await asyncio.wait_for(receive(reader), CONTROL_TIMEOUT)
            token = hello.get("token")
            if (hello.get("event") != "attach" or not isinstance(token, str)
                    or not token.isascii() or not hmac.compare_digest(token, self.token)):
                await send(writer, event="error", message="This server run could not be authenticated")
                return
            if self.registry is None and self.active is not None:
                await send(writer, event="error", message="A client launcher is already connected. Close it first.")
                return
            connection = ClientConnection(writer)
            if remote:
                ports = hello.get("gateway_ports")
                if (self.registry is None or not isinstance(ports, dict) or set(ports) != {"web", "lobby"}
                        or any(type(port) is not int or not 1 <= port <= 65535 for port in ports.values())
                        or ports["web"] == ports["lobby"]):
                    raise ValueError("Remote launch requires distinct client loopback web/lobby ports")
                connection.gateway_ports = dict(ports)
                connection.capability = secrets.token_hex(32)
            elif "gateway_ports" in hello:
                raise ValueError("Gateway endpoints require the remote TLS listener")
            endpoint = self.bnet_endpoint
            if self.registry is not None:
                from .launch_bridge import LaunchRelay
                connection.launcher_id = secrets.token_hex(24)
                connection.patch_event = asyncio.Event()
                host, port = endpoint.rsplit(":", 1)
                connection.relay = LaunchRelay(self.registry, connection.launcher_id, (host, int(port)), connection.patch_event)
                endpoint = await connection.relay.start()
                self.clients[connection.launcher_id] = connection
            else:
                self.active = connection
                self.gate.clear()
            await send(writer, event="launch", bnet_endpoint=endpoint,
                       modulus_le=self.modulus.hex(), rsa_only=self.rsa_only,
                       force_credentials=self.registry is not None,
                       **({"capability": connection.capability} if remote else {}))
            while True:
                message = await receive(reader)
                if message.get("event") == "patched" and not connection.patched:
                    connection.patched = True
                    if connection.patch_event is not None:
                        connection.patch_event.set()
                    else:
                        self.gate.set()
                    await send(writer, event="tls-ready")
                elif message.get("event") == "restored":
                    receipt = connection.restoration
                    if receipt is not None and not receipt.done():
                        if (connection.restoration_cid is None or
                                (type(message.get("cid")) is int and message["cid"] == connection.restoration_cid
                                 and type(message.get("cycle")) is int
                                 and message["cycle"] == connection.restoration_cycle)):
                            connection.restored = True
                            receipt.set_result(True)
                    elif not (type(message.get("cid")) is int and type(message.get("cycle")) is int
                              and 0 < message["cycle"] <= connection.restoration_cycle):
                        raise ValueError("Unexpected client launcher restoration receipt")
                elif message.get("event") in ("tls-prepared", "tls-restored"):
                    cycle = message.get("cycle")
                    # An old receipt must never open a newer socket's patch gate.
                    if (type(cycle) is int and cycle == connection.tls_cycle
                            and connection.tls_owner is not None
                            and (message["event"] == "tls-prepared" or connection.tls_restore_sent)):
                        receipt = (connection.tls_preparation if message["event"] == "tls-prepared"
                                   else connection.tls_restoration)
                        if receipt is not None and not receipt.done():
                            receipt.set_result(True)
                elif message.get("event") == "rsa-prepared":
                    cid = message.get("cid")
                    if (type(cid) is int and cid == connection.rsa_cid
                            and connection.rsa_preparation is not None
                            and not connection.rsa_preparation.done()):
                        connection.rsa_preparation.set_result(True)
                else:
                    raise ValueError("Unexpected client launcher message")
        except (ConnectionError, OSError, ValueError, TimeoutError) as error:
            if connection:
                print(f"Client launcher disconnected: {error}", flush=True)
        finally:
            if connection is not None and connection.relay is not None:
                self.clients.pop(connection.launcher_id, None)
                if connection.capability is not None and self.on_remote_disconnect is not None:
                    await self.on_remote_disconnect(connection.capability)
                # Complete relay teardown before waking failed socket callbacks,
                # so a disconnected launch no longer resolves in the registry.
                await connection.relay.close()
                if connection.restoration is not None and not connection.restoration.done():
                    connection.restoration.set_result(False)
                for receipt in (connection.tls_preparation, connection.tls_restoration,
                                connection.rsa_preparation):
                    if receipt is not None and not receipt.done():
                        receipt.set_result(False)
                had_tls_owner = connection.tls_owner is not None
                connection.tls_owner = None
                if had_tls_owner and connection.tls_lock.locked():
                    connection.tls_lock.release()
            if connection is not None and self.active is connection:
                self.gate.clear()
                self.active = None
                if connection.restoration is not None and not connection.restoration.done():
                    connection.restoration.set_result(False)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            self.tasks.discard(task)

    async def channel_ready(self, session=None):
        connection = self.clients.get(session.launcher_id) if self.registry is not None and session is not None else self.active
        if connection is None or not connection.patched or connection.writer.is_closing():
            raise ClientLaunchError("The lobby has no patched client launcher")
        # Keep a new referral from replacing this exact receipt, and a retry's
        # TLS preparation from racing these original-byte writes. Staging uses
        # the same lock order; TLS callbacks never acquire rsa_lock.
        async with connection.rsa_lock, connection.tls_lock:
            current = self.clients.get(session.launcher_id) if self.registry is not None else self.active
            if current is not connection or connection.writer.is_closing():
                raise ClientLaunchError("Client disconnected before lobby restoration")
            cid = connection.rsa_cid
            if self.admissions is not None and cid is None:
                raise ClientLaunchError("Lobby restoration has no prepared account referral")
            if cid is not None:
                if (session is None or type(getattr(session, "admission_cid", None)) is not int
                        or session.admission_cid != cid):
                    raise ClientLaunchError("Lobby restoration does not own this referral")
                if self.admissions is not None:
                    lease = getattr(session, "lease", None)
                    if (lease is None or lease.kind != "real" or not self.admissions.is_current(lease)
                            or lease.account.id != connection.rsa_account_id):
                        raise ClientLaunchError("Lobby restoration requires its current admitted account")
            if connection.restored:
                return
            if connection.restoration is None:
                connection.restoration = asyncio.get_running_loop().create_future()
                connection.restoration_cid = cid
                if cid is None:
                    await send(connection.writer, event="restore")
                else:
                    connection.restoration_cycle += 1
                    await send(connection.writer, event="restore", cid=cid, cycle=connection.restoration_cycle)
            receipt = connection.restoration
            try:
                if not await asyncio.wait_for(asyncio.shield(receipt), CONTROL_TIMEOUT):
                    raise ClientLaunchError("Client disconnected during restoration")
            except BaseException:
                # A lost/failed restoration may already have written bytes.
                # Stop this launch rather than release another preparation.
                connection.writer.close()
                raise
        changed = "RSA modulus" if self.rsa_only else "TLS/RSA bytes"
        print(f"Original {changed} restored after encrypted channel acceptance.", flush=True)

    def _tls_connection(self, launcher_id, rpc_owner):
        connection = self.clients.get(launcher_id)
        if connection is None or not connection.patched or connection.writer.is_closing():
            raise ClientLaunchError("TLS handshake has no verified client launcher")
        if not isinstance(rpc_owner, str) or not rpc_owner:
            raise ClientLaunchError("TLS handshake requires its exact RPC socket owner")
        return connection

    async def tls_start(self, launcher_id, rpc_owner):
        """Prepare checked TLS bytes for one socket, holding its launch's lock.

        A failed password may open a fresh native TLS socket. Every socket gets
        a new receipt cycle rather than reusing the previous restoration receipt.
        """
        connection = self._tls_connection(launcher_id, rpc_owner)
        if self.rsa_only:
            return
        await asyncio.wait_for(connection.tls_lock.acquire(), CONTROL_TIMEOUT)
        if self.clients.get(launcher_id) is not connection or connection.writer.is_closing():
            connection.tls_lock.release()
            raise ClientLaunchError("Client disconnected before TLS preparation")
        connection.tls_owner = rpc_owner
        connection.tls_cycle += 1
        connection.tls_restore_sent = False
        connection.tls_preparation = asyncio.get_running_loop().create_future()
        connection.tls_restoration = asyncio.get_running_loop().create_future()
        cycle = connection.tls_cycle
        try:
            await send(connection.writer, event="prepare-tls", cycle=cycle)
            if not await asyncio.wait_for(asyncio.shield(connection.tls_preparation), CONTROL_TIMEOUT):
                raise ClientLaunchError("Client disconnected during TLS preparation")
        except BaseException:
            # Preparation may have written bytes even if its receipt was lost.
            # Its socket's finally hook is also idempotent for this exact owner.
            with suppress(Exception):
                await self.tls_end(launcher_id, rpc_owner)
            raise

    async def _finish_tls(self, connection, rpc_owner, *, strict):
        if connection.tls_owner != rpc_owner:
            if strict:
                raise ClientLaunchError("TLS restoration does not own this socket's patch cycle")
            return False
        cycle = connection.tls_cycle
        try:
            if not connection.tls_restore_sent:
                connection.tls_restore_sent = True
                await send(connection.writer, event="restore-tls", cycle=cycle)
            if not await asyncio.wait_for(asyncio.shield(connection.tls_restoration), CONTROL_TIMEOUT):
                raise ClientLaunchError("Client disconnected during TLS restoration")
            return True
        except BaseException:
            # A launcher that cannot verify restoration stops its owned child
            # when this control transport closes. Do not admit another cycle.
            connection.writer.close()
            raise
        finally:
            if connection.tls_owner == rpc_owner and connection.tls_cycle == cycle:
                connection.tls_owner = None
                if connection.tls_lock.locked():
                    connection.tls_lock.release()

    async def tls_ready(self, launcher_id, rpc_owner):
        """Restore after this socket's first RPC, then allow the next socket."""
        connection = self._tls_connection(launcher_id, rpc_owner)
        if self.rsa_only:
            return
        return await self._finish_tls(connection, rpc_owner, strict=True)

    async def tls_end(self, launcher_id, rpc_owner):
        """Restore a failed handshake; stale socket cleanup cannot unlock a retry."""
        connection = self.clients.get(launcher_id)
        if connection is None or self.rsa_only:
            return False
        return await self._finish_tls(connection, rpc_owner, strict=False)

    async def referral_ready(self, session):
        """Stage only this admitted referral's RSA immediately before its send."""
        owner = getattr(session, "owner", None)
        parts = owner.split(":", 2) if isinstance(owner, str) else ()
        admission = getattr(session, "admission", None)
        lease = getattr(session, "lease", None)
        cid = getattr(admission, "cid", None)
        if (len(parts) != 3 or parts[0] != "launch" or not parts[1] or not parts[2]
                or getattr(session, "authenticated", False) is not True
                or lease is None or getattr(lease, "owner", None) != owner
                or getattr(lease, "kind", None) != "pending"
                or getattr(admission, "lease", None) is not lease
                or type(cid) is not int or not 0 < cid < 1 << 64):
            raise ClientLaunchError("RSA preparation requires this socket's valid pending referral")
        if self.admissions is not None and self.admissions.pending_referral(cid) is not admission:
            raise ClientLaunchError("RSA preparation requires a current pending referral")
        connection = self._tls_connection(parts[1], owner)
        async with connection.rsa_lock:
            if connection.rsa_cid == cid:
                if connection.rsa_owner != owner:
                    raise ClientLaunchError("RSA referral preparation belongs to another socket")
            else:
                async with connection.tls_lock:
                    if self.clients.get(parts[1]) is not connection or connection.writer.is_closing():
                        raise ClientLaunchError("Client disconnected before RSA preparation")
                    if self.admissions is not None and self.admissions.pending_referral(cid) is not admission:
                        raise ClientLaunchError("RSA preparation requires a current pending referral")
                    connection.rsa_cid, connection.rsa_owner = cid, owner
                    connection.rsa_account_id = lease.account.id
                    connection.rsa_preparation = asyncio.get_running_loop().create_future()
                    connection.restored = False
                    connection.restoration = None
                    connection.restoration_cid = None
                    try:
                        await send(connection.writer, event="prepare-rsa", cid=cid)
                        if not await asyncio.wait_for(asyncio.shield(connection.rsa_preparation), CONTROL_TIMEOUT):
                            raise ClientLaunchError("Client disconnected during RSA preparation")
                    except BaseException:
                        connection.writer.close()
                        raise
            if connection.rsa_preparation is None or not connection.rsa_preparation.done() or not connection.rsa_preparation.result():
                raise ClientLaunchError("RSA referral preparation was not verified")

    async def close(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def publish_state(path, port, token):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps({"version": 1, "port": port, "token": token}), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def remove_state(path, token):
    """Do not delete a newer run's rendezvous file."""
    with suppress(OSError, ValueError):
        path = Path(path)
        state = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(state, dict) and state.get("token") == token:
            path.unlink()


def validate_remote_options(args):
    host = getattr(args, "remote_host", None)
    virtual = getattr(args, "network", None) == "virtual"
    if virtual and (host != "127.0.0.1" or getattr(args, "invite", None) is not None):
        raise ValueError("Virtual hosting uses its automatic public identifier; --invite is for LAN hosting")
    if host is None:
        if getattr(args, "invite", None) is not None:
            raise ValueError("--invite requires --remote-host")
        return
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_multicast or host == "255.255.255.255" or str(address) != host:
        raise ValueError("--remote-host must be a specific LAN/VPN IPv4 address")
    if args.auth_mode != "credentials" or args.preset != "beta-menu" or args.config is not None:
        raise ValueError("Remote launch requires --auth-mode credentials and the fixed beta-menu runtime")
    if args.rsa_only:
        raise ValueError("Remote launch requires the default temporary TLS patches")
    port = getattr(args, "remote_port", 47325)
    if type(port) is not int or not 1 <= port <= 65535 or port in (args.port, args.bnet_port, args.web_port):
        raise ValueError("--remote-port must be distinct from the three internal ports, between 1 and 65535")
    if getattr(args, "invite", None) is not None and args.invite.resolve() == args.state.resolve():
        raise ValueError("The remote invite and local launcher state must be separate files")


def publish_invite(path, host, port, token, tls_sha256):
    """A public certificate pin and confidential, per-run join token."""
    from .remote_transport import validate_descriptor
    descriptor = validate_descriptor(dict(version=2, host=host, port=port, token=token, tls_sha256=tls_sha256))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def announce_virtual_gateway(identifier, previous_identifier=None):
    """Highlight only the public identifier on assignment or provider rotation."""
    highlighted = colorize(identifier, "warning", color=console_color())
    label = "Virtual gateway changed" if previous_identifier is not None else "Virtual gateway"
    print(f"{label}: {highlighted}\n"
          f"Client: Start-Client.bat --network virtual --server-ip {highlighted}\n"
          "Share this identifier with players.\n"
          "No VPN password or router port forwarding is required.", flush=True)


def current_server_address(args, *, remote_listener=None, virtual_host=None):
    """Read the joining address from the current public tunnel or bound gateway."""
    if getattr(args, "network", None) == "virtual":
        return getattr(virtual_host, "endpoint", None)
    if getattr(args, "remote_host", None) is not None:
        endpoint = getattr(remote_listener, "endpoint", None)
        return f"{endpoint[0]}:{endpoint[1]}" if endpoint is not None else None
    return "127.0.0.1"


async def run_server(args):
    validate_remote_options(args)
    cert, tls_key = Path(getattr(args, "cert", DEFAULT_CERT)), Path(getattr(args, "key", DEFAULT_KEY))
    certificate = prepare_project_certificate(cert, tls_key, cert.with_suffix(".cer"),
                                              cert.parent / "local-certificate.json")
    if args.rsa_only and not certificate_is_windows_trusted(cert):
        raise ClientLaunchError("--rsa-only requires this server certificate in the Windows CurrentUser/Root trust store")
    if args.preset != "beta-menu" or args.config is not None:
        raise ValueError("The showcase uses the fixed beta-menu runtime")
    from .runtime import BetaRuntime
    runtime = BetaRuntime(extended=getattr(args, "extended", False))
    if args.auth_mode == "credentials":
        if runtime.settings["menu"] is None:
            raise ValueError("credentials authentication requires a beta menu preset")
        from .accounts import AccountStore, AdmissionManager
        from .lobby import LobbyHub
        with closing(AccountStore(args.accounts)) as accounts:
            admissions = AdmissionManager(accounts)
            return await _run_server(args, certificate, runtime, accounts, admissions,
                                     LobbyHub(admissions.is_current, accounts=accounts.list,
                                              social=accounts.social, extended=runtime.extended,
                                              hero_levels=accounts.hero_levels))
    return await _run_server(args, certificate, runtime)


async def _run_server(args, certificate, runtime, accounts=None, admissions=None, hub=None):
    # The public runner owns the store across setup, serving, and all cleanup.
    from .runtime import BetaRuntime, BetaSession
    key = load_or_generate_local_key(getattr(args, "rsa_key", DEFAULT_LOCAL_KEY))
    cert, tls_key = Path(getattr(args, "cert", DEFAULT_CERT)), Path(getattr(args, "key", DEFAULT_KEY))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    directory = None if args.no_capture else args.capture_dir.resolve() / f"server-{stamp}"
    if directory:
        directory.mkdir(parents=True)
    gate = threading.Event()
    registry = None
    if admissions is not None:
        from .launch_bridge import LaunchRegistry
        registry = LaunchRegistry()
    bootstrap = BootstrapServer(cert, tls_key, port=args.bnet_port,
                                web_port=args.web_port, lobby=f"127.0.0.1:{args.port}",
                                auth_mode=args.auth_mode, admissions=admissions,
                                capture_dir=directory / "bootstrap" if directory else None,
                                tls_gate=gate if registry is None else None,
                                connection_context=registry.resolve if registry is not None else None,
                                key_slots={name: bytes.fromhex(value) for name, value in
                                           runtime.settings.get("key_slots", {}).items()})
    coordinator = control = lobby = console = console_task = command_window = remote_listener = None
    virtual_host = virtual_watch = None
    remote_host = getattr(args, "remote_host", None)
    invite_path = getattr(args, "invite", None)
    ready = asyncio.get_running_loop().create_future()
    try:
        bootstrap.start()
        coordinator = Coordinator(gate, local_modulus_le(key), f"127.0.0.1:{bootstrap.port}",
                                  args.rsa_only, registry, admissions,
                                  **({"web_endpoint": ("127.0.0.1", bootstrap.web_port),
                                      "lobby_endpoint": ("127.0.0.1", args.port)}
                                     if remote_host is not None else {}))
        if registry is not None and remote_host is not None:
            bootstrap.endpoint_context = coordinator.endpoint_context
        if registry is not None:
            loop = asyncio.get_running_loop()
            def tls_hook(method):
                def notify(session):
                    launcher_id = session.owner.split(":", 2)[1]
                    operation = asyncio.run_coroutine_threadsafe(
                        method(launcher_id, session.owner), loop)
                    try:
                        return operation.result(CONTROL_TIMEOUT + 1)
                    except BaseException:
                        # A socket that timed out while queued must not prepare
                        # bytes later, after its bootstrap finally hook ran.
                        operation.cancel()
                        raise
                return notify
            bootstrap.on_tls_start = tls_hook(coordinator.tls_start)
            bootstrap.on_tls_ready = tls_hook(coordinator.tls_ready)
            bootstrap.on_tls_end = tls_hook(coordinator.tls_end)
            def referral_ready(session):
                operation = asyncio.run_coroutine_threadsafe(coordinator.referral_ready(session), loop)
                try:
                    return operation.result(CONTROL_TIMEOUT + 1)
                except BaseException:
                    operation.cancel()
                    raise
            bootstrap.on_referral_ready = referral_ready
        lobby = asyncio.create_task(serve("127.0.0.1", args.port, args.preset, args.config,
                                         directory / "lobby" if directory else None, ready=ready, local_rsa_key=key,
                                         on_channel_ready=coordinator.channel_ready if registry is None else None,
                                         on_session_ready=coordinator.channel_ready if registry is not None else None,
                                         admissions=admissions, hub=hub,
                                         packet_log=args.packet_log,
                                         **({"advertised_endpoint": coordinator.advertised_endpoint}
                                            if remote_host is not None else {}),
                                         runtime_factory=lambda: BetaRuntime(extended=runtime.extended),
                                         session_class=BetaSession))
        await asyncio.wait((ready, lobby), return_when=asyncio.FIRST_COMPLETED)
        if lobby.done():
            await lobby
        control = await asyncio.start_server(coordinator.connected, "127.0.0.1", 0, limit=MESSAGE_LIMIT)
        publish_state(args.state, control.sockets[0].getsockname()[1], coordinator.token)
        if remote_host is not None:
            from .remote_transport import RemoteListener
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(cert), str(tls_key))

            async def remote_control(reader, writer, hello):
                await coordinator.connected(reader, writer, hello=hello, remote=True)

            remote_listener = RemoteListener(remote_control, coordinator.resolve_service, coordinator.token, context,
                                             discovery_pin=certificate["sha256"])
            coordinator.on_remote_disconnect = remote_listener.close_capability
            host, remote_port = await remote_listener.start(remote_host, args.remote_port)
            if getattr(args, "network", None) == "virtual":
                from virtual import PublicHost
                print("Assigning a public virtual gateway...", flush=True)
                virtual_host = PublicHost((host, remote_port), args.data_dir,
                                          on_endpoint_change=announce_virtual_gateway)
                await virtual_host.start()
                virtual_watch = asyncio.create_task(virtual_host.wait())
            else:
                if invite_path is not None:
                    publish_invite(invite_path, host, remote_port, coordinator.token, certificate["sha256"])
                print(f"Remote LAN/VPN gateway: {host}:{remote_port}\n"
                      f"Client: Start-Client.bat --server-ip {host}"
                      + (f" --remote-port {remote_port}" if remote_port != 47325 else ""), flush=True)
                print(f"Guests need access to TCP {remote_port} on this address through the selected network and firewall.", flush=True)
                if invite_path is not None:
                    print(f"Remote invite: {invite_path.resolve()} (expires when this server stops)", flush=True)
        print("Menu core: fixed beta runtime\n"
              f"TLS bootstrap: 127.0.0.1:{bootstrap.port}\n"
              f"HTTP login: http://127.0.0.1:{bootstrap.web_port}/battlenet/login\n"
              f"Encrypted lobby: 127.0.0.1:{args.port}\n"
              f"Launcher control: 127.0.0.1:{control.sockets[0].getsockname()[1]}\n"
              f"Launcher state: {args.state.resolve()}\nAuthentication: {args.auth_mode}", flush=True)
        if accounts:
            from .console import Console, read_console
            console = Console(accounts, admissions, hub, extended=runtime.extended,
                              server_address=lambda: current_server_address(
                                  args, remote_listener=remote_listener, virtual_host=virtual_host))
            if getattr(args, "command_window", False):
                from .command_window import start_command_window
                command_window = await start_command_window(console)
            if command_window is None:
                console_task = asyncio.create_task(read_console(console))
            location = "separate command window" if command_window else "this window"
            print(f"Local accounts: {args.accounts.resolve()}\nDot commands: {location}; enter .help", flush=True)
            if not accounts.list():
                print("Create the first account: .accountcreate <user> <pass>", flush=True)
        print(f"Server ready. Now open Start-Client.bat.\nServer captures: {directory or 'disabled'}\n"
              "Leave this window open. Ctrl+C stops the server.", flush=True)
        print(f"TLS certificate SHA256: {certificate['sha256']}\n"
              f"Client TLS mode: {'original verification (experimental)' if args.rsa_only else 'temporary TLS patches'}", flush=True)
        if virtual_watch is not None:
            done, _ = await asyncio.wait((lobby, virtual_watch), return_when=asyncio.FIRST_COMPLETED)
            if virtual_watch in done:
                await virtual_watch
                raise RuntimeError("The virtual tunnel stopped. Restart the server for a new public identifier.")
        await lobby
    except OSError as error:
        if error.errno == errno.EADDRINUSE or getattr(error, "winerror", None) == 10048:
            raise ClientLaunchError("A server port is already in use. Stop the previous "
                                    "server with Ctrl+C, then open Start-Server.bat again.") from error
        raise
    finally:
        if virtual_watch:
            virtual_watch.cancel()
            await asyncio.gather(virtual_watch, return_exceptions=True)
        if virtual_host:
            await virtual_host.close()
        if command_window:
            await command_window.close()
        if console_task:
            console_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await console_task
        if console:
            await console.close()
        if coordinator:
            remove_state(args.state, coordinator.token)
            if invite_path is not None:
                remove_state(invite_path, coordinator.token)
        if remote_listener:
            await remote_listener.close()
        if control:
            control.close()
        if coordinator:
            await coordinator.close()
        if control:
            await control.wait_closed()
        if lobby:
            lobby.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await lobby
        ready.cancel()
        await asyncio.to_thread(bootstrap.close)


async def connect_server(state_path):
    deadline = asyncio.get_running_loop().time() + CONTROL_TIMEOUT
    while True:
        writer = None
        try:
            state = json.loads(Path(state_path).read_text(encoding="utf-8"))
            if (not isinstance(state, dict) or state.get("version") != 1
                    or type(state.get("port")) is not int or not 1 <= state["port"] <= 65535
                    or not isinstance(state.get("token"), str) or len(state["token"]) != 64
                    or any(char not in "0123456789abcdef" for char in state["token"])):
                raise ValueError("Invalid server rendezvous file; restart Start-Server.bat")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", state["port"], limit=MESSAGE_LIMIT), 2)
            await send(writer, event="attach", token=state["token"])
            welcome = await asyncio.wait_for(receive(reader), CONTROL_TIMEOUT)
            if welcome.get("event") == "error":
                raise ClientLaunchError(welcome.get("message", "Server refused the client launcher"))
            if welcome.get("event") != "launch":
                raise ValueError("Unexpected server reply; restart Start-Server.bat")
            return reader, writer, welcome
        except (OSError, ConnectionError, TimeoutError):
            if writer:
                writer.close()
            if asyncio.get_running_loop().time() >= deadline:
                raise ClientLaunchError("Start-Server.bat is not ready. Open it first and wait for 'Server ready'.")
            await asyncio.sleep(0.25)
        except BaseException:
            if writer:
                writer.close()
            raise


async def run_client(args):
    gateway = None
    virtual_tunnel = None
    remote_invite = getattr(args, "remote_invite", None)
    server_ip = getattr(args, "server_ip", None)
    if remote_invite is not None or server_ip is not None:
        from .remote_transport import DEFAULT_PORT, RemoteGateway, discover_server
        try:
            if remote_invite is not None:
                if server_ip is not None:
                    raise ValueError("Choose either --server-ip or --remote-invite")
                descriptor = json.loads(remote_invite.read_text(encoding="utf-8-sig"))
            else:
                host, port = server_ip, getattr(args, "remote_port", DEFAULT_PORT)
                tunnel_identity = None
                if getattr(args, "network", None) == "virtual":
                    from virtual import ClientTunnel
                    print(f"Connecting to the virtual gateway at {host}...", flush=True)
                    virtual_tunnel = ClientTunnel(host)
                    tunnel_identity = host
                    host, port = await virtual_tunnel.start()
                else:
                    print(f"Connecting to the LAN/VPN server at {host}:{port}...", flush=True)
                descriptor = await discover_server(host, port, trust_file=args.trust_file,
                                                   expected_pin=getattr(args, "server_pin", None),
                                                   tunnel_identity=tunnel_identity)
            gateway = RemoteGateway(descriptor)
            if remote_invite is not None:
                print(f"Connecting to the LAN/VPN server at {descriptor['host']}:{descriptor['port']}...", flush=True)
            reader, writer, welcome = await gateway.start()
        except BaseException as error:
            if gateway is not None:
                await gateway.close()
            if virtual_tunnel is not None:
                await virtual_tunnel.close()
            if isinstance(error, (OSError, ValueError, RuntimeError)):
                raise ClientLaunchError(f"Remote server connection failed: {error}") from error
            raise
    else:
        print("Connecting to the local server...", flush=True)
        reader, writer, welcome = await connect_server(args.state)
    child = launcher = receiver = None
    tls_ready = asyncio.get_running_loop().create_future()
    loop = asyncio.get_running_loop()
    closing = threading.Event()
    try:
        modulus = bytes.fromhex(welcome["modulus_le"])
        rsa_only = welcome.get("rsa_only", False)
        force_credentials = welcome.get("force_credentials", False)
        if type(force_credentials) is not bool:
            raise ClientLaunchError("Invalid credentials startup choice from server")
        if type(rsa_only) is not bool:
            raise ClientLaunchError("Invalid certificate mode from server")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        directory = None if args.no_capture else args.capture_dir.resolve() / f"client-{stamp}"
        if directory:
            directory.mkdir(parents=True)
        print(f"Client captures: {directory or 'disabled'}", flush=True)

        def started(result):
            nonlocal child
            child = result
            if closing.is_set():
                stop_client(result.process)
                raise ClientLaunchError("Client launch was stopped")

        async def patched_message():
            await send(writer, event="patched")
            await asyncio.wait_for(asyncio.shield(tls_ready), CONTROL_TIMEOUT)

        def patched():
            asyncio.run_coroutine_threadsafe(patched_message(), loop).result(CONTROL_TIMEOUT + 1)

        async def control_messages():
            tls_cycle = 0
            tls_prepared = False
            rsa_cid = None
            restoration_cycle = 0
            while True:
                message = await receive(reader)
                if message.get("event") == "tls-ready" and not tls_ready.done():
                    tls_ready.set_result(None)
                elif message.get("event") == "restore" and child is not None:
                    if force_credentials:
                        cid, cycle = message.get("cid"), message.get("cycle")
                        if (type(cid) is not int or cid != rsa_cid or type(cycle) is not int
                                or cycle != restoration_cycle + 1):
                            raise ClientLaunchError("Invalid lobby restoration referral or cycle from server")
                    await asyncio.to_thread(restore_login_patches, child, args.game)
                    if force_credentials:
                        restoration_cycle, rsa_cid = cycle, None
                        await send(writer, event="restored", cid=cid, cycle=cycle)
                    else:
                        await send(writer, event="restored")
                    changed = "RSA modulus" if rsa_only else "TLS/RSA bytes"
                    print(f"Original {changed} restored. Menu login can continue.", flush=True)
                elif message.get("event") == "prepare-tls" and child is not None and not rsa_only:
                    cycle = message.get("cycle")
                    if type(cycle) is not int or cycle != tls_cycle + 1 or tls_prepared:
                        raise ClientLaunchError("Invalid TLS preparation cycle from server")
                    await asyncio.to_thread(prepare_tls_patches, child, args.game)
                    tls_cycle, tls_prepared = cycle, True
                    await send(writer, event="tls-prepared", cycle=cycle)
                elif message.get("event") == "restore-tls" and child is not None and not rsa_only:
                    cycle = message.get("cycle")
                    if type(cycle) is not int or cycle != tls_cycle or not tls_prepared:
                        raise ClientLaunchError("Invalid TLS restoration cycle from server")
                    restore = restore_login_patches if force_credentials else restore_tls_patches
                    await asyncio.to_thread(restore, child, args.game)
                    tls_prepared = False
                    await send(writer, event="tls-restored", cycle=cycle)
                    changed = "TLS/RSA" if force_credentials else "TLS"
                    print(f"Original {changed} bytes restored. Credentials login can continue.", flush=True)
                elif message.get("event") == "prepare-rsa" and child is not None and force_credentials:
                    cid = message.get("cid")
                    if type(cid) is not int or not 0 < cid < 1 << 64:
                        raise ClientLaunchError("Invalid RSA referral correlation from server")
                    await asyncio.to_thread(prepare_lobby_rsa, child, args.game)
                    rsa_cid = cid
                    await send(writer, event="rsa-prepared", cid=cid)
                else:
                    raise ClientLaunchError("Unexpected server control message")

        receiver = asyncio.create_task(control_messages())
        launcher = asyncio.create_task(asyncio.to_thread(
            launch_client, args.game, welcome["bnet_endpoint"], not rsa_only,
            directory / "client.jsonl" if directory else None, args.observe_seconds, patch_phases=(1,),
            on_started=started, on_patch_ready=patched, local_rsa_modulus=modulus, rsa_only=rsa_only,
            force_credentials=force_credentials))
        done, _ = await asyncio.wait((launcher, receiver), return_when=asyncio.FIRST_COMPLETED)
        if receiver in done:
            await receiver
        result = await asyncio.shield(launcher)
        print("Leave this window open while using the client. Ctrl+C stops this client.", flush=True)
        while result.returncode is None:
            if receiver.done():
                await receiver
            await asyncio.sleep(0.25)
        print(f"Client exited: {result.returncode}. The server can stay open for another launch.", flush=True)
        return result.returncode
    finally:
        # Stop only our child, including one still being patched by the worker.
        closing.set()
        tls_ready.cancel()
        if child:
            await asyncio.to_thread(stop_client, child.process)
        if launcher:
            # A cancelled patch-ready future can surface through the worker.
            # It must not skip receiver, transport or owned-child cleanup.
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.shield(launcher)
        if child:
            await asyncio.to_thread(stop_client, child.process)
        if receiver:
            receiver.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await receiver
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
        if gateway is not None:
            await gateway.close()
        if virtual_tunnel is not None:
            await virtual_tunnel.close()
