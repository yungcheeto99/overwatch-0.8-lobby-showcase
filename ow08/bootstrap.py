"""Loopback Battle.net bootstrap and credential login for the beta.

This module uses framed protobuf over TLS and implements a small bounded wire
codec instead of importing generated protobufs.

Showcase credentials follow the challenge/form/ticket sequence, then issue an
account-bound lobby referral with independent proof and cipher keys.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from http.cookies import SimpleCookie
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .packet_log import colorize, console_color, console_data


CONNECTION = 1698982289
AUTHENTICATION = 233634817
AUTH_LISTENER = 1898188341
CHALLENGE_LISTENER = 3151632159
GAME_UTILITIES = 1069623117
RESPONSE_SERVICE = 254
SERVICE_NAMES = {
    CONNECTION: "ConnectionService", AUTHENTICATION: "AuthenticationServer",
    AUTH_LISTENER: "AuthenticationClient", CHALLENGE_LISTENER: "ChallengeNotify",
    GAME_UTILITIES: "GameUtilities",
}
RPC_FUNCTIONS = {
    CONNECTION: {1: "Connect", 2: "Bind", 3: "Echo", 5: "KeepAlive", 7: "Disconnect"},
    AUTHENTICATION: {1: "Logon", 4: "SelectGameAccount_DEPRECATED", 6: "SelectGameAccount",
                     7: "VerifyWebCredentials", 8: "GenerateWebCredentials"},
    AUTH_LISTENER: {5: "OnLogonComplete"},
    CHALLENGE_LISTENER: {3: "OnExternalChallenge"},
    GAME_UTILITIES: {1: "ProcessClientRequest"},
}
DEFAULT_CERT = Path(__file__).resolve().parents[1] / "data" / "localip.crt"
DEFAULT_KEY = DEFAULT_CERT.with_suffix(".key")
MAX_BODY = 1024 * 1024
MAX_HEADER = 8192
TLS_GATE_TIMEOUT = 15.0
LOCAL_TICKET = "US-OW08-LOCAL-EXPERIMENT"


def generate_development_certificate(certfile=DEFAULT_CERT, keyfile=DEFAULT_KEY, *, common_name="127.0.0.1"):
    """Generate local-only TLS credentials; cryptography is only needed here.

    Serving an existing certificate needs only Python's stdlib. Existing
    files are never overwritten, and no certificate is installed into the
    operating system's certificate store.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    certfile, keyfile = Path(certfile), Path(keyfile)
    if certfile.exists() or keyfile.exists():
        raise FileExistsError("local certificate or key already exists; refusing to overwrite")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # The beta has a separate common-name comparison in its network layer.
    # Keep CN equal to the endpoint instead of relying only on modern SANs.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost"),
            x509.DNSName("bnet-emu.fish")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=True, data_encipherment=False, key_agreement=False,
                       key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256()))
    certfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    with keyfile.open("xb") as output:
        output.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with certfile.open("xb") as output:
        output.write(certificate.public_bytes(serialization.Encoding.PEM))
    return certfile, keyfile


class WireError(ValueError):
    """Malformed or oversized protobuf/RPC input."""


def varint(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise WireError("varint must be an unsigned 64-bit integer")
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if position >= len(data):
            raise WireError("truncated varint")
        byte = data[position]
        position += 1
        if shift == 63 and byte > 1:
            raise WireError("varint exceeds 64 bits")
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, position
    raise WireError("unterminated varint")


def pb(number: int, value: int | bytes | str, wire: int | None = None) -> bytes:
    """Encode an explicit protobuf field; defaults to varint or bytes."""
    if not 0 < number <= 0x1FFFFFFF:
        raise WireError("invalid protobuf field number")
    if isinstance(value, str):
        value = value.encode("utf-8")
    if wire is None:
        wire = 2 if isinstance(value, bytes) else 0
    tag = varint(number << 3 | wire)
    if wire == 0:
        return tag + varint(value)
    if wire == 1:
        return tag + struct.pack("<Q", value)
    if wire == 2 and isinstance(value, bytes):
        return tag + varint(len(value)) + value
    if wire == 5:
        return tag + struct.pack("<I", value)
    raise WireError("unsupported protobuf value/wire type")


def fields(data: bytes) -> dict[int, list[int | bytes]]:
    """Decode protobuf primitives, retaining repeated and unknown fields."""
    if len(data) > MAX_BODY:
        raise WireError("protobuf message exceeds size limit")
    result: dict[int, list[int | bytes]] = {}
    position = 0
    while position < len(data):
        tag, position = _read_varint(data, position)
        number, wire = tag >> 3, tag & 7
        if not 0 < number <= 0x1FFFFFFF:
            raise WireError("invalid protobuf field number")
        if wire == 0:
            value, position = _read_varint(data, position)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if len(data) - position < size:
                raise WireError("truncated fixed protobuf field")
            value = int.from_bytes(data[position:position + size], "little")
            position += size
        elif wire == 2:
            size, position = _read_varint(data, position)
            if size > len(data) - position:
                raise WireError("truncated length-delimited protobuf field")
            value = data[position:position + size]
            position += size
        else:
            raise WireError(f"unsupported protobuf wire type {wire}")
        result.setdefault(number, []).append(value)
    return result


def _one(data, number, default=0):
    return data.get(number, [default])[-1]


def _text(value) -> str:
    if not isinstance(value, bytes):
        raise WireError("expected a length-delimited text field")
    return value.decode("utf-8", "replace")


@dataclass(frozen=True)
class RpcHeader:
    service_id: int = 0
    method_id: int = 0
    token: int = 0
    size: int = 0
    status: int = 0
    service_hash: int = 0

    @classmethod
    def parse(cls, data: bytes):
        value = fields(data)
        if 1 not in value or 3 not in value:
            raise WireError("RPC header lacks required service_id/token")
        numbers = [_one(value, number) for number in (1, 2, 3, 5, 6, 11)]
        if any(not isinstance(number, int) or not 0 <= number <= 0xFFFFFFFF for number in numbers):
            raise WireError("RPC header fields must be uint32 values")
        if numbers[3] > MAX_BODY:
            raise WireError("RPC body exceeds size limit")
        return cls(*numbers)


def rpc_frame(header: RpcHeader, body: bytes = b"") -> bytes:
    if len(body) > MAX_BODY:
        raise WireError("RPC body exceeds size limit")
    encoded = (pb(1, header.service_id) + pb(2, header.method_id)
               + pb(3, header.token) + pb(5, len(body)) + pb(6, header.status))
    if header.service_hash:
        encoded += pb(11, header.service_hash, 5)
    return struct.pack(">H", len(encoded)) + encoded + body


def read_exact(stream, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            if not result:
                raise EOFError("peer closed")
            raise WireError(f"peer closed after {len(result)}/{count} bytes")
        result.extend(chunk)
    return bytes(result)


def read_rpc(stream) -> tuple[RpcHeader, bytes]:
    size = struct.unpack(">H", read_exact(stream, 2))[0]
    if not 1 <= size <= MAX_HEADER:
        raise WireError(f"invalid RPC header size {size}")
    header = RpcHeader.parse(read_exact(stream, size))
    return header, read_exact(stream, header.size) if header.size else b""


def attribute(name: str, value: str | bytes | int) -> bytes:
    variant_number = 5 if isinstance(value, str) else 6 if isinstance(value, bytes) else 9
    return pb(1, name) + pb(2, pb(variant_number, value))


def referral(lobby: str, cid: int = 379775058, key_slots: Mapping[str, bytes] | None = None) -> bytes:
    keys = key_slots or {}
    if set(keys) - {"k0", "k1", "k2", "k3"}:
        raise ValueError("referral key slots must be k0, k1, k2, k3")
    attributes = [attribute("response_type", "ReferralInfo")]
    for slot in ("k0", "k1", "k2", "k3"):
        key = keys.get(slot, bytes(64))
        if not isinstance(key, bytes) or len(key) != 64:
            raise ValueError(f"{slot} must be 64 bytes")
        attributes.append(attribute(slot, key))
    attributes.extend((attribute("cid", cid), attribute("hostv4", lobby)))
    return b"".join(pb(1, value) for value in attributes)


def logon_result(cid: int = 379775058, game_account: int = 559865145,
                 username="local@localhost", battle_tag="Local#0001") -> bytes:
    account = pb(1, 0x0100000000000000, 1) + pb(2, cid, 1)
    game = pb(1, 0x020000010050726F, 1) + pb(2, game_account, 1)
    return (pb(1, 0) + pb(2, account) + pb(3, game) + pb(4, username)
            + pb(5, 1) + pb(6, 1) + pb(7, battle_tag) + pb(8, "US")
            + pb(9, bytes(64)) + pb(10, 0))


def invalid_credentials():
    """Native beta login form error."""
    return {"authentication_state": "LOGIN", "error_code": "INVALID_ACCOUNT_OR_CREDENTIALS",
            "error_message": "Invalid account or password.",
            "input_id": "password", "support_error_code": "BLZBNTTAS00000002", "error_status": "WARNING",
            "error_message_helper": "Please enter the correct username and password."}


def login_inputs(submitted):
    """Decode native form inputs without ever logging or coercing passwords."""
    if not isinstance(submitted, dict):
        raise ValueError("login form must be an object")
    if "inputs" in submitted:
        values = {}
        if not isinstance(submitted["inputs"], list):
            raise ValueError("login inputs must be an array")
        for item in submitted["inputs"]:
            if not isinstance(item, dict) or not isinstance(item.get("input_id"), str):
                raise ValueError("invalid login input")
            key = item["input_id"]
            if key in values:
                raise ValueError("duplicate login input")
            values[key] = item.get("value")
    else:
        values = {}
        for key, value in submitted.items():
            if not isinstance(value, list) or len(value) != 1:
                raise ValueError("invalid login form field")
            values[key] = value[0]
    username, password = values.get("account_name"), values.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("credentials are required")
    return username, password


def credential_shape(body):
    """Safe research metadata; cached credentials are never emitted."""
    public = b"US-6b566d8e88863148abe3f872f1c1e33b-867364322"
    return {str(number): [{"type": "bytes", "size": len(value),
                           "public_reference_ticket": value == public}
                          if isinstance(value, bytes) else {"type": "integer"}
                          for value in values] for number, values in fields(body).items()}


def rpc_description(service, method, body):
    function = RPC_FUNCTIONS.get(service, {}).get(method, "purpose unknown")
    secret = service in (AUTHENTICATION, AUTH_LISTENER)
    try:
        data = {str(number): [({"bytes": len(value), "redacted": True} if secret else
                              {"bytes": len(value), "hex": value[:64].hex(),
                               "omitted_bytes": max(0, len(value) - 64)})
                              if isinstance(value, bytes) else value
                              for value in values[:16]]
                for number, values in fields(body).items()}
    except (WireError, ValueError, TypeError):
        data = {"malformed": True, "bytes": len(body)}
    return {"service": SERVICE_NAMES.get(service, "purpose unknown"), "function": function,
            "data": data, "field_purposes": "protobuf field numbers; unlabelled purposes unknown"}


@dataclass
class RpcSession:
    """Per-client bound service ids, independent from request-token numbers."""
    imports: dict[int, int] = field(default_factory=dict)
    listeners: dict[int, int] = field(default_factory=dict)
    next_notification: int = 0x40000000
    authenticated: bool = False
    owner: str = field(default_factory=lambda: secrets.token_hex(24))
    challenge: str | None = None
    lease: object = None
    admission: object = None

    def bind(self, body: bytes) -> bytes:
        request = fields(body)
        imports = []
        # Older clients use deprecated packed fixed32 hashes (field 1).
        for value in request.get(1, []):
            if isinstance(value, bytes):
                if len(value) % 4:
                    raise WireError("packed imported service hashes are not fixed32 aligned")
                imports.extend(struct.unpack("<" + "I" * (len(value) // 4), value))
            else:
                imports.append(value)
        for value in request.get(4, []):
            imports.append(_one(fields(value), 1))
        self.imports.update({index: service for index, service in enumerate(imports, 1)})
        for value in request.get(2, []) + request.get(3, []):
            bound = fields(value)
            self.listeners[_one(bound, 1)] = _one(bound, 2)
        return pb(1, b"".join(varint(index) for index in range(1, len(imports) + 1))) if imports else b""

    def notification(self, service_hash: int, method_id: int, body: bytes) -> tuple[RpcHeader, bytes]:
        self.next_notification = (self.next_notification + 1) & 0xFFFFFFFF
        return RpcHeader(self.listeners.get(service_hash, 0), method_id,
                         self.next_notification, service_hash=service_hash), body


def dispatch(session: RpcSession, request: RpcHeader, body: bytes, *,
             auth_mode="web", web_url="http://127.0.0.1:6969/battlenet/login",
             lobby="127.0.0.1:3724", cid=379775058, key_slots=None,
             event: Callable[..., None] = lambda *args, **kwargs: None,
             admissions=None) -> list[tuple[RpcHeader, bytes]]:
    """Return response/notification pairs; unknown calls stay recorded and unhandled."""
    response = RpcHeader(RESPONSE_SERVICE, token=request.token)
    if request.service_id == RESPONSE_SERVICE:
        event("notification_ack", token=request.token, status=request.status)
        return []
    service = request.service_hash or session.imports.get(request.service_id, 0)
    if not service and request.service_id == 0:
        service = CONNECTION
    method = request.method_id
    if service == CONNECTION:
        if method == 1:
            values = fields(body)
            bindings = session.bind(_one(values, 2, b""))
            epoch = int(time.time())
            process = pb(1, 0) + pb(2, epoch)
            result = pb(1, process) + pb(2, _one(values, 1, pb(1, 1) + pb(2, epoch)))
            if bindings:
                result += pb(4, bindings)
            result += pb(6, epoch) + pb(7, _one(values, 3, 1))
            event("connect", imports=session.imports, listeners=session.listeners)
            return [(response, result)]
        if method == 2:
            return [(response, session.bind(body))]
        if method == 3:
            values = fields(body)
            result = b""
            if 1 in values:
                result += pb(1, _one(values, 1), 1)
            if 3 in values:
                result += pb(2, _one(values, 3))
            return [(response, result)]
        if method in (5, 7):
            return [(response, b"")]
    elif service == AUTHENTICATION:
        if method in (1, 8):
            values = fields(body)
            # The log never prints cached credentials or user-supplied passwords.
            event("logon", program=_text(_one(values, 1, b"")) if method == 1 else "",
                  auth_mode=auth_mode)
            if auth_mode == "direct":
                session.authenticated = True
                event("logon_complete", source="direct_hypothesis")
                return [(response, b""), session.notification(AUTH_LISTENER, 5, logon_result(cid))]
            suffix = "?externalChallenge=login&app=pro"
            if auth_mode == "credentials":
                session.authenticated = False
                session.lease = session.admission = None
                session.challenge = admissions.begin_challenge(session.owner)
                suffix += "&challenge=" + session.challenge
            challenge = pb(2, "web_auth_url") + pb(3, web_url + suffix)
            event("web_challenge", url=web_url)
            return [(response, b""), session.notification(CHALLENGE_LISTENER, 3, challenge)]
        if method == 7:
            if auth_mode == "credentials":
                from .accounts import AccountError
                try:
                    token = _one(fields(body), 1, b"").decode("ascii")
                    session.lease = admissions.verify_ticket(session.challenge, token, session.owner)
                except (AccountError, UnicodeError, AttributeError):
                    event("credentials_rejected", reason="invalid or expired ticket")
                    return [(RpcHeader(RESPONSE_SERVICE, token=request.token, status=3), b"")]
            session.authenticated = True
            event("logon_complete", source="verify_web_credentials")
            result = logon_result(cid)
            if session.lease is not None:
                account = session.lease.account
                result = logon_result(account.id, account.game_id, account.username, account.battle_tag)
            return [(response, b""), session.notification(AUTH_LISTENER, 5, result)]
        if method in (4, 6):
            # Old SelectGameAccount returns NoData; the newer form returns a result.
            result = b"" if method == 4 else pb(1, 0) + pb(2, _one(fields(body), 1, b""))
            return [(response, result)]
    elif service == GAME_UTILITIES and method == 1:
        if auth_mode == "credentials":
            if not session.authenticated or session.lease is None:
                event("referral_rejected", reason="authentication required")
                return [(RpcHeader(RESPONSE_SERVICE, token=request.token, status=3), b"")]
            from .accounts import AccountError
            try:
                if session.admission is None:
                    session.admission = admissions.issue_referral(session.lease)
                if admissions.pending_referral(session.admission.cid) is not session.admission:
                    raise AccountError("admission no longer current")
                cid, key_slots = session.admission.cid, session.admission.key_slots
            except AccountError:
                return [(RpcHeader(RESPONSE_SERVICE, token=request.token, status=3), b"")]
        names = []
        for value in fields(body).get(1, []):
            names.append(_text(_one(fields(value), 1, b"")))
        event("referral", attributes=names, hostv4=lobby, cid=cid, authenticated=session.authenticated)
        return [(response, referral(lobby, cid, key_slots))]
    event("unknown_rpc", service_hash=service, service_name=SERVICE_NAMES.get(service, "unknown"),
          service_id=request.service_id, method_id=method, token=request.token,
          body_hex="[redacted]" if service == AUTHENTICATION else body.hex())
    return []


class _TrackedRequests:
    """Register workers and sockets before spawn, so close cannot miss either."""
    def process_request(self, request, client_address):
        owner = self.owner
        worker = threading.Thread(target=self.process_request_thread, args=(request, client_address), daemon=True)
        with owner._lock:
            if owner._closing.is_set():
                self.shutdown_request(request)
                return
            owner._workers.add(worker)
            owner._sockets.add(request)
            try:
                worker.start()
            except BaseException:
                owner._workers.discard(worker)
                owner._sockets.discard(request)
                self.shutdown_request(request)
                raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.owner._lock:
                self.owner._sockets.discard(request)
                self.owner._workers.discard(threading.current_thread())


class _TcpServer(_TrackedRequests, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _HttpServer(_TrackedRequests, ThreadingHTTPServer):
    daemon_threads = True


class BootstrapServer:
    """Local TLS RPC + local JSON login form, in background threads.

    Public-network binds/referrals are rejected. Credentials are synthetic and
    never checked against or forwarded to Battle.net. Call ``close`` on shutdown.
    """

    def __init__(self, certfile=DEFAULT_CERT, keyfile=DEFAULT_KEY, *, host="127.0.0.1",
                 port=1119, web_port=6969, lobby="127.0.0.1:3724", auth_mode="web",
                 cid=379775058, key_slots=None,
                 capture_dir=Path(__file__).resolve().parents[1] / "captures" / "bootstrap", logger=print,
                 tls_gate: threading.Event | None = None, admissions=None, connection_context=None,
                 on_tls_ready=None, on_tls_start=None, on_tls_end=None,
                 on_referral_ready=None, endpoint_context=None):
        if not ipaddress.IPv4Address(host).is_loopback:
            raise ValueError("bootstrap binds must use a loopback IP address")
        lobby_host, separator, lobby_port = lobby.rpartition(":")
        if not separator or not ipaddress.IPv4Address(lobby_host).is_loopback or not 0 < int(lobby_port) < 65536:
            raise ValueError("lobby referral must be a loopback IPv4 address:port")
        if auth_mode not in ("web", "direct", "credentials"):
            raise ValueError("auth_mode must be web, direct or credentials")
        if auth_mode == "credentials" and admissions is None:
            raise ValueError("credentials authentication requires an account admission manager")
        if any(not isinstance(value, int) or not 0 <= value < 65536 for value in (port, web_port)):
            raise ValueError("listener ports must be between 0 and 65535")
        # Build now to validate key slots and ids before opening any sockets.
        referral(lobby, cid, key_slots)
        self.host, self.port, self.web_port = host, port, web_port
        self.lobby, self.auth_mode, self.cid = lobby, auth_mode, cid
        self.key_slots = dict(key_slots or {})
        self.certfile, self.keyfile = Path(certfile), Path(keyfile)
        self.capture_dir = Path(capture_dir) if capture_dir is not None else None
        self.logger = logger
        self.color = console_color()
        self.tls_gate = tls_gate
        self.admissions = admissions
        self.connection_context = connection_context
        self.endpoint_context = endpoint_context
        self.on_tls_ready = on_tls_ready
        self.on_tls_start = on_tls_start
        self.on_tls_end = on_tls_end
        self.on_referral_ready = on_referral_ready
        self.rpc_server = self.web_server = None
        self._threads = []
        self._serving = {}
        self._workers = set()
        self._sockets = set()
        self._lock = threading.RLock()
        self._closing = threading.Event()
        self._logfile = None

    def event(self, name: str, **data):
        with self._lock:
            row = {"time": datetime.now(timezone.utc).isoformat(), "event": name, **data}
            if self._logfile:
                self._logfile.write(json.dumps(row, sort_keys=True) + "\n")
                self._logfile.flush()
            readable = console_data(data)
            tone = "error" if "error" in name or "failed" in name else "in"
            label = colorize(name, tone, color=self.color)
            if name in ("rpc_received", "rpc_sent"):
                direction = "IN" if name == "rpc_received" else "OUT"
                arrow = colorize(direction, "in" if direction == "IN" else "out", color=self.color)
                service = readable.pop("service", "")
                function = readable.pop("function", "purpose unknown")
                function = colorize(f"{service}.{function}" if service else function,
                                    "function", color=self.color)
                label = f"{name} {arrow} {function}"
                if readable.get("status"):
                    label += " " + colorize(f"status={readable['status']}", "error", color=self.color)
            self.logger(f"[bootstrap] {label} " + json.dumps(readable, sort_keys=True))

    def start(self):
        if self.rpc_server:
            raise RuntimeError("bootstrap already started")
        self._closing.clear()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.certfile), str(self.keyfile))
        owner = self

        def client_hello(connection, server_name, _context):
            peer = connection.getpeername()
            owner.event("tls_client_hello", peer=f"{peer[0]}:{peer[1]}", server_name=server_name)

        context.set_servername_callback(client_hello)

        class RpcHandler(socketserver.BaseRequestHandler):
            def handle(self):
                connection = self.request
                peer = f"{self.client_address[0]}:{self.client_address[1]}"
                owner.event("tcp_accepted", peer=peer)
                session = RpcSession()
                launcher_id = None
                if owner.connection_context is not None:
                    launcher_id = owner.connection_context(self.client_address)
                    if launcher_id is None:
                        owner.event("unowned_bootstrap_rejected", peer=peer)
                        connection.close()
                        return
                    session.owner = "launch:" + launcher_id + ":" + session.owner
                with owner._lock:
                    owner._sockets.add(connection)
                try:
                    web_url = f"http://{owner.host}:{owner.web_port}/battlenet/login"
                    lobby_endpoint = owner.lobby
                    endpoints = (owner.endpoint_context(launcher_id)
                                 if owner.endpoint_context is not None and launcher_id is not None else None)
                    if endpoints is not None:
                        if (not isinstance(endpoints, dict) or set(endpoints) != {"web", "lobby"}
                                or any(not isinstance(value, tuple) or len(value) != 2
                                       or value[0] != "127.0.0.1" or type(value[1]) is not int
                                       or not 1 <= value[1] <= 65535 for value in endpoints.values())):
                            raise ValueError("Invalid client loopback gateway endpoints")
                        web_url = f"http://127.0.0.1:{endpoints['web'][1]}/battlenet/login"
                        lobby_endpoint = f"127.0.0.1:{endpoints['lobby'][1]}"
                    if owner.tls_gate is not None:
                        # Hold the accepted socket until the launcher confirms
                        # its child's local TLS patch. Poll so close() can stop
                        # an unopened gate without abandoning a waiting thread.
                        owner.event("tls_gate_waiting", peer=peer)
                        deadline = time.monotonic() + TLS_GATE_TIMEOUT
                        while not owner.tls_gate.is_set():
                            if owner._closing.is_set():
                                owner.event("tls_gate_closed", peer=peer)
                                return
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                owner.event("tls_gate_timeout", peer=peer)
                                return
                            owner.tls_gate.wait(min(0.1, remaining))
                        if owner._closing.is_set():
                            owner.event("tls_gate_closed", peer=peer)
                            return
                        owner.event("tls_gate_open", peer=peer)
                    if owner.on_tls_start is not None:
                        owner.on_tls_start(session)
                    if owner._closing.is_set():
                        return
                    connection.settimeout(15)
                    secured = context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
                    connection = secured
                    with owner._lock:
                        owner._sockets.discard(self.request)
                        if owner._closing.is_set():
                            secured.close()
                            return
                        owner._sockets.add(secured)
                    secured.do_handshake()
                    owner.event("tls_ready", peer=peer, version=secured.version(), cipher=secured.cipher()[0],
                                selected_alpn=secured.selected_alpn_protocol())
                    secured.settimeout(600 if owner.auth_mode == "credentials" else 120)
                    notify_tls_ready = owner.on_tls_ready
                    while True:
                        header, body = read_rpc(secured)
                        # A completed server handshake precedes the beta's own
                        # pin check. Its first RPC proves client TLS acceptance.
                        if notify_tls_ready is not None:
                            notify_tls_ready(session)
                            notify_tls_ready = None
                        service = header.service_hash or session.imports.get(header.service_id, 0)
                        if not service and header.service_id == 0:
                            service = CONNECTION
                        incoming_description = rpc_description(service, header.method_id, body)
                        if (header.service_hash or session.imports.get(header.service_id)) == AUTHENTICATION:
                            owner.event("auth_request_shape", peer=peer, method_id=header.method_id,
                                        fields=credential_shape(body))
                        owner.event("rpc_received", peer=peer, service_id=header.service_id,
                                    service_hash=header.service_hash, method_id=header.method_id,
                                    token=header.token, body_size=len(body),
                                    **incoming_description,
                                    body_hex="[redacted]" if (header.service_hash or session.imports.get(header.service_id)) == AUTHENTICATION else body.hex())
                        def event(name, **data):
                            owner.event(name, peer=peer, **data)
                        outgoing = dispatch(session, header, body, auth_mode=owner.auth_mode,
                                            web_url=web_url,
                                            lobby=lobby_endpoint, cid=owner.cid, key_slots=owner.key_slots, event=event,
                                            admissions=owner.admissions)
                        if (service == GAME_UTILITIES and header.method_id == 1
                                and session.admission is not None and outgoing
                                and outgoing[0][0].status == 0
                                and owner.on_referral_ready is not None):
                            # Credentials forms keep the original RSA bytes.
                            # Stage the owned local key only for a valid referral.
                            owner.on_referral_ready(session)
                        for response, payload in outgoing:
                            frame = rpc_frame(response, payload)
                            secured.sendall(frame)
                            owner.event("rpc_sent", peer=peer, service_id=response.service_id,
                                        service_hash=response.service_hash, method_id=response.method_id,
                                        token=response.token, body_size=len(payload), frame_hex=frame.hex(),
                                        status=response.status,
                                        **(rpc_description(response.service_hash, response.method_id, payload)
                                           if response.service_id != RESPONSE_SERVICE else
                                           {"function": "response to " + incoming_description["function"],
                                            "data": {"bytes": len(payload)}}))
                except EOFError:
                    owner.event("peer_closed", peer=peer)
                except (OSError, WireError, ValueError, TypeError, RuntimeError, struct.error) as error:
                    owner.event("connection_error", peer=peer, error_type=type(error).__name__, message=str(error))
                finally:
                    if owner.admissions is not None:
                        owner.admissions.abort_owner(session.owner)
                    with owner._lock:
                        owner._sockets.discard(connection)
                    connection.close()
                    if owner.on_tls_end is not None:
                        try:
                            owner.on_tls_end(session)
                        except Exception as error:
                            owner.event("tls_cleanup_error", peer=peer, error_type=type(error).__name__)

        class WebHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            # Windows may keep a socket.makefile read blocked after another
            # thread calls shutdown/close. Set the timeout before setup creates
            # its buffered readers, so an incomplete local request always drains.
            timeout = 1.0

            def handle(self):
                with owner._lock:
                    owner._sockets.add(self.connection)
                try:
                    super().handle()
                except (ConnectionError, TimeoutError):
                    owner.event("web_peer_closed", peer=self.client_address[0])
                finally:
                    with owner._lock:
                        owner._sockets.discard(self.connection)

            def log_message(self, format, *args):
                pass

            def respond(self, payload, status=200, challenge=None):
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json;charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                if challenge is not None:
                    self.send_header("Set-Cookie", f"ow08_challenge={challenge}; Path=/battlenet/login; HttpOnly; SameSite=Strict")
                    # Build 24919's HTTP worker requires JSESSIONID before it
                    # parses LOGIN_FORM; web.id is its optional companion.
                    self.send_header("Set-Cookie", f"JSESSIONID={challenge}; Path=/battlenet/login; HttpOnly; SameSite=Strict")
                    self.send_header("Set-Cookie", f"web.id={secrets.token_hex(16)}; Path=/battlenet/login; HttpOnly; SameSite=Strict")
                self.end_headers()
                self.wfile.write(data)

            def challenge_nonce(self):
                values = parse_qs(urlsplit(self.path).query).get("challenge", [])
                if len(values) == 1:
                    return values[0]
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get("Cookie", ""))
                except Exception:
                    return None
                value = cookie.get("ow08_challenge") or cookie.get("JSESSIONID")
                return value.value if value is not None else None

            def do_GET(self):
                if urlsplit(self.path).path != "/battlenet/login":
                    self.respond({"error": "unknown endpoint"}, 404)
                    return
                owner.event("web_form", peer=self.client_address[0])
                nonce = self.challenge_nonce()
                if owner.auth_mode == "credentials" and not owner.admissions.challenge_valid(nonce):
                    self.respond({"error": "invalid or expired login challenge"}, 400)
                    return
                owner.event("web_form", challenge_bound=nonce is not None)
                self.respond({"type": "LOGIN_FORM", "inputs": [
                    {"input_id": "account_name", "type": "text", "label": "Local dummy account", "max_length": 320},
                    {"input_id": "password", "type": "password", "label": "Local dummy password", "max_length": 128},
                    {"input_id": "log_in_submit", "type": "submit", "label": "Log In"},
                ]}, challenge=nonce if nonce is not None else secrets.token_hex(32))

            def do_POST(self):
                if urlsplit(self.path).path != "/battlenet/login":
                    self.respond({"error": "unknown endpoint"}, 404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= length <= 65536:
                        raise ValueError("invalid content length")
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete request body")
                    if "application/json" in self.headers.get("Content-Type", ""):
                        submitted = json.loads(body)
                    else:
                        submitted = parse_qs(body.decode("utf-8"), keep_blank_values=True)
                except (ValueError, UnicodeError) as error:
                    self.respond({"error": str(error)}, 400)
                    return
                if owner.auth_mode == "credentials":
                    from .accounts import AccountError
                    try:
                        username, password = login_inputs(submitted)
                        nonce = self.challenge_nonce()
                        ticket = owner.admissions.issue_ticket(nonce, username, password)
                    except (AccountError, ValueError, TypeError):
                        owner.event("web_credentials_rejected")
                        self.respond(invalid_credentials(), 401)
                        return
                    owner.event("web_ticket", peer=self.client_address[0], body_size=len(body), credentials_validated=True)
                    self.respond({"authentication_state": "DONE", "login_ticket": ticket})
                    return
                # Legacy web experiment, retained separately from real local accounts.
                owner.event("web_ticket", peer=self.client_address[0], body_size=len(body))
                self.respond({"authentication_state": "DONE", "login_ticket": LOCAL_TICKET})

        try:
            self.rpc_server = _TcpServer((self.host, self.port), RpcHandler)
            self.web_server = _HttpServer((self.host, self.web_port), WebHandler)
            self.rpc_server.owner = self.web_server.owner = self
            self.port = self.rpc_server.server_address[1]
            self.web_port = self.web_server.server_address[1]
            self.capture_path = None
            if self.capture_dir is not None:
                self.capture_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
                self.capture_path = self.capture_dir / f"bootstrap-{stamp}.jsonl"
                self._logfile = self.capture_path.open("x", encoding="utf-8")
            for server in (self.rpc_server, self.web_server):
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
                self._threads.append(thread)
                thread.start()
                self._serving[server] = thread
            self.event("listening", tls=f"{self.host}:{self.port}", web=f"http://{self.host}:{self.web_port}/battlenet/login",
                       lobby=self.lobby, auth_mode=self.auth_mode,
                       capture=str(self.capture_path.resolve()) if self.capture_path else "disabled")
        except Exception:
            self.close()
            raise
        return self

    def close(self):
        """Stop acceptance, unblock sockets, and finish all admitted handlers.

        Async callers must run this in a worker thread: a TLS-ready callback
        can be awaiting launcher work on their event loop. The account store
        must remain open until all RPC/HTTP workers have finished.
        """
        self._closing.set()
        with self._lock:
            for connection in list(self._sockets):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        for server in (self.rpc_server, self.web_server):
            if server:
                serving = self._serving.get(server)
                if serving is not None and serving.is_alive():
                    server.shutdown()
                server.server_close()
        # No new worker can register after _closing is set. Finish password
        # work and owner cleanup before the runner may close its SQLite store.
        current = threading.current_thread()
        while True:
            with self._lock:
                workers = tuple(worker for worker in self._workers if worker is not current)
            if not workers:
                break
            for worker in workers:
                worker.join()
        for thread in self._threads:
            if thread.ident is not None and thread is not current:
                thread.join()
        self._threads.clear()
        self._serving.clear()
        self.rpc_server = self.web_server = None
        with self._lock:
            self._sockets.clear()
            if self._logfile:
                self._logfile.close()
                self._logfile = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
