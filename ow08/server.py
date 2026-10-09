"""Bounded beta lobby sessions and listener lifetime."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
from pathlib import Path

from .capture import Capture, create_capture
from .cipher import Jam
from .config import BetaRuntime
from .menu import MenuLobby
from .protocol import (HELLO_CLIENT, HELLO_SERVER, FrameDecoder, ProtocolError, build_state_blob,
                       build_beta_state_blob, derive_keys, describe_payload, pack_frame, parse_announcement)


class Session:
    def __init__(self, reader, writer, experiment: BetaRuntime, capture: Capture, local_rsa_key=None,
                 on_channel_ready=None, admissions=None, hub=None, on_session_ready=None,
                 advertised_endpoint=None):
        self.reader, self.writer, self.exp, self.capture = reader, writer, experiment, capture
        self.rx = self.tx = None
        self.decoder = FrameDecoder(experiment.settings["max_frame_size"])
        self.families = {}
        self.fired = set()
        self.tasks = set()
        self.tx_lock = asyncio.Lock()
        self.local_rsa_key = local_rsa_key
        self.on_channel_ready = on_channel_ready
        self.on_session_ready = on_session_ready
        self.advertised_endpoint = advertised_endpoint
        self.admissions, self.hub = admissions, hub
        self.lease = None
        self.launcher_id = None
        self.admission_cid = None
        self.menu = MenuLobby(self, experiment.settings["menu"]) if experiment.settings["menu"] is not None else None

    async def read_exact(self, size, stage):
        # read() records partial bytes even if the peer closes or a timeout expires.
        result = bytearray()
        deadline = asyncio.get_running_loop().time() + self.exp.settings["timeout_seconds"]
        while len(result) < size:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"timeout reading {stage}: {len(result)}/{size} bytes")
            chunk = await asyncio.wait_for(self.reader.read(size - len(result)), remaining)
            if not chunk:
                raise ConnectionError(f"peer closed during {stage}: {len(result)}/{size} bytes")
            self.capture.bytes("c2s", "wire", chunk, stage)
            result += chunk
        return bytes(result)

    async def write_wire(self, data, stage):
        self.writer.write(data)
        self.capture.bytes("s2c", "wire", data, stage)
        await self.writer.drain()

    async def handshake(self):
        self.capture.stage("client_hello")
        hello = await self.read_exact(len(HELLO_CLIENT), "client_hello")
        if hello != HELLO_CLIENT:
            raise ProtocolError(f"unexpected lobby greeting {hello!r}")
        await self.write_wire(HELLO_SERVER, "server_hello")
        self.capture.stage("client_nonce")
        client_record = await self.read_exact(40, "client_nonce")
        admission = None
        if self.admissions is not None:
            cid = int.from_bytes(client_record[:8], "little")
            admission = self.admissions.pending_referral(cid)
            owner = admission.lease.owner
            if owner.startswith("launch:"):
                self.launcher_id = owner.split(":", 2)[1]
        cn = client_record[8:]
        sn, challenge = os.urandom(32), os.urandom(32)
        await self.write_wire(challenge + b"\x00" + sn, "server_challenge")
        roles = {"k0": "mac1", "k1": "mac2", "k2": "s2c", "k3": "c2s"}
        slots = {roles[name]: key for name, key in admission.key_slots.items()} if admission else {}
        keys = derive_keys(cn, sn, slots)
        self.capture.stage("client_proof")
        proof_record = await self.read_exact(40, "client_proof")
        matches = hmac.compare_digest(proof_record[8:], keys["mac1"])
        self.capture.event("proof", matches=matches, verified=True,
                           client_nonce_hex=cn.hex(), server_nonce_hex=sn.hex())
        if not matches:
            raise ProtocolError("MAC1 mismatch: lobby authentication proof did not match")
        if admission is not None:
            self.lease = self.admissions.claim_referral(cid, admission, "lobby-" + os.urandom(24).hex())
            self.admission_cid = cid
            if self.menu is None:
                raise ProtocolError("authenticated admission requires a beta menu runtime")
            await self.menu.attach_account(self.lease)
            self.capture.summary["user"] = self.lease.account.username
            self.capture.event("account_admitted", user=self.lease.account.username, cid=cid)
        seq = int.from_bytes(os.urandom(4), "little")
        host, port = self.writer.get_extra_info("sockname")[:2]
        if self.advertised_endpoint is not None and self.launcher_id is not None:
            endpoint = self.advertised_endpoint(self.launcher_id)
            if endpoint is not None:
                if (not isinstance(endpoint, tuple) or len(endpoint) != 2 or endpoint[0] != "127.0.0.1"
                        or type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
                    raise ProtocolError("Invalid client loopback lobby endpoint")
                host, port = endpoint
        blob = (build_beta_state_blob(seq, host, port, self.local_rsa_key) if self.local_rsa_key
                else build_state_blob(seq, host, port))
        self.tx, self.rx = Jam(keys["s2c"]), Jam(keys["c2s"])
        self.capture.event("state_blob", hex=blob.hex(), length=len(blob), seq=seq,
                           blob_style="beta-rsa" if self.local_rsa_key else "signed",
                           advertise_host=host, advertise_port=port)
        await self.write_wire(keys["mac2"] + self.tx.crypt(blob), "server_proof_and_blob")
        self.capture.stage("handshake_sent")
        await self.trigger("handshake_ready")

    async def trigger(self, event, payload=b""):
        """The fixed runtime supplies protocol control replies."""

    def task_done(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            self.capture.event("action_error", error=str(error))
            self.writer.close()

    async def send_payload(self, payload):
        framed = pack_frame(payload, self.exp.settings["max_frame_size"])
        async with self.tx_lock:
            wire = self.tx.crypt(framed) if self.tx else framed
            await self.write_wire(wire, "frame")
            self.capture.frame("s2c", payload, framed, describe_payload(payload, wire_families=self.families))

    async def send_family(self, family, offset, body=b""):
        wire = next((index for index, crc in self.families.items() if crc == family), None)
        if wire is None:
            self.capture.event("action_skipped", rule="beta-menu", reason="family CRC not announced",
                               family_crc=f"{family:08x}")
            return
        await self.send_payload(bytes((wire, offset)) + body)

    async def frame_loop(self):
        while True:
            data = await asyncio.wait_for(self.reader.read(65536), self.exp.settings["timeout_seconds"])
            if not data:
                if self.decoder.pending:
                    raise ProtocolError("peer closed in the middle of a frame")
                return "peer_closed"
            self.capture.bytes("c2s", "wire", data, "frame_stream")
            plain = self.rx.crypt(data) if self.rx else data
            for payload in self.decoder.feed(plain):
                self.capture.frame("c2s", payload, pack_frame(payload, self.exp.settings["max_frame_size"]),
                                   describe_payload(payload, wire_families=self.families))
                if payload[:2] == b"\x00\x00":
                    crcs = parse_announcement(payload)
                    self.families = dict(enumerate(crcs, start=1))
                    self.capture.summary["families"] = {str(i): f"0x{crc:08X}" for i, crc in self.families.items()}
                    self.capture.stage("announcement", count=len(crcs))
                    if self.on_session_ready:
                        callback, self.on_session_ready = self.on_session_ready, None
                        await callback(self)
                        self.capture.event("session_ready_callback")
                    elif self.on_channel_ready:
                        callback, self.on_channel_ready = self.on_channel_ready, None
                        await callback()
                        self.capture.event("channel_ready_callback")
                    await self.trigger("announcement", payload)
                elif payload[0] != 0:
                    self.capture.stage("application_frame_observed", wire=payload[0], offset=payload[1])
                await self.trigger("frame", payload)
                if self.menu:
                    await self.menu.handle(payload)

    async def run(self):
        try:
            async with asyncio.timeout(self.exp.settings["session_seconds"]):
                await self.handshake()
                return await self.frame_loop()
        finally:
            tasks = list(self.tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if self.menu and self.menu.actor is not None:
                await self.hub.release(self.menu.actor)
            if self.lease is not None:
                self.admissions.release(self.lease)


async def serve(host: str, port: int, preset="beta-menu", config=None, capture_dir: Path | None = None,
                once=False, ready=None,
                local_rsa_key=None, on_channel_ready=None, admissions=None, hub=None, packet_log=False,
                runtime_factory=None, session_class=None, on_session_ready=None,
                advertised_endpoint=None):
    from .runtime import BetaSession
    session_class = BetaSession if session_class is None else session_class
    connections = 0
    sessions = set()
    finished = asyncio.Event()
    listener = None

    async def connected(reader, writer):
        nonlocal connections
        # One-session callers stop accepting immediately after the first connection.
        if once and connections:
            writer.close()
            await writer.wait_closed()
            return
        connections += 1
        if once:
            listener.close()
        task = asyncio.current_task()
        sessions.add(task)
        capture = session = None
        reason = "server_cancelled"
        try:
            exp = make_runtime()
            capture = create_capture(capture_dir, exp.settings, connections, writer.get_extra_info("peername"),
                                     logger=print if packet_log else None)
            print(f"[{connections}] {exp.name} -> {capture.directory or 'capture disabled'}", flush=True)
            session = session_class(reader, writer, exp, capture, local_rsa_key, on_channel_ready, admissions, hub,
                                    on_session_ready,
                                    **({"advertised_endpoint": advertised_endpoint} if advertised_endpoint is not None else {}))
            reason = await session.run()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"
            if capture:
                capture.event("error", type=type(error).__name__, message=str(error))
            print(f"[{connections}] {reason}", flush=True)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            if capture:
                capture.close(reason, session.decoder.pending if session else b"")
            sessions.discard(task)
            finished.set()

    # Each connection owns its mutable menu state.
    def make_runtime():
        if runtime_factory is not None:
            return runtime_factory()
        from .config import load_config
        return load_config(preset, config)
    exp = make_runtime()
    listener = await asyncio.start_server(connected, host, port, limit=65536)
    if ready is not None and not ready.done():
        ready.set_result(listener.sockets[0].getsockname())
    addresses = ", ".join(str(sock.getsockname()) for sock in listener.sockets)
    print(f"OW 0.8 lobby listening on {addresses}", flush=True)
    print(f"Ctrl+C stops; capture={'enabled' if capture_dir is not None else 'disabled'}.", flush=True)
    try:
        if once:
            await finished.wait()
        else:
            # start_server already accepts connections. serve_forever catches
            # cancellation and waits for active transports before our cleanup,
            # which prevents us from cancelling their idle session handlers.
            await asyncio.Future()
    finally:
        listener.close()
        remaining = list(sessions)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)
        await listener.wait_closed()
