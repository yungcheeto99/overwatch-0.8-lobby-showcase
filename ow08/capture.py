"""Per-session TCP bytes, decrypted frame streams, events and a comparable summary."""

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .packet_log import console_color, describe_beta_payload, format_beta_packet, format_beta_wire


class NullCapture:
    """Session observations without disk I/O; optionally print packet descriptions.

    The mutable summary matches Capture so transport/menu code does not need
    capture-policy branches. No payload history or wire bytes are retained.
    directory is None to make the disabled policy explicit to launchers.
    """
    directory = None

    def __init__(self, experiment: dict, connection: int, peer, *, logger=None):
        self.started = time.monotonic()
        self.connection = connection
        self.logger = logger
        self.color = console_color() if logger else False
        self.closed = False
        self.summary = {"experiment": experiment["name"], "peer": list(peer), "stage": "connected",
                        "received_frames": 0, "sent_frames": 0, "families": {}, "reason": "running"}

    def event(self, event, **fields):
        pass

    def bytes(self, direction, kind, data, stage=None):
        if self.logger and kind == "wire":
            line = format_beta_wire(direction, data, stage, connection=self.connection, color=self.color)
            if line:
                self.logger(line)

    def stage(self, name, **fields):
        self.summary["stage"] = name
        self.event("stage", stage=name, **fields)

    def observe_frame(self, direction, payload, description):
        families = {int(wire): int(crc, 16) if isinstance(crc, str) else crc
                    for wire, crc in self.summary["families"].items()}
        if payload and description.get("family_crc_hex"):
            families[payload[0]] = int(description["family_crc_hex"], 16)
        decoded = describe_beta_payload(payload, wire_families=families, direction=direction)
        if (direction == "c2s" and payload[:2] == b"\0\0"
                and decoded["status"] == "decoded"):
            self.summary["families"] = {str(wire): "0x" + crc for wire, crc in
                                        enumerate(decoded["fields"]["families"], start=1)}
        if self.logger:
            self.logger(format_beta_packet(decoded, connection=self.connection,
                                           user=self.summary.get("user"), color=self.color))
        return decoded

    def frame(self, direction, payload, framed, description):
        key = "received_frames" if direction == "c2s" else "sent_frames"
        self.summary[key] += 1
        self.observe_frame(direction, payload, description)

    def close(self, reason, pending=b""):
        if not self.closed:
            self.summary.update(reason=reason, duration=round(time.monotonic() - self.started, 3),
                                pending_plaintext_bytes=len(pending))
            self.closed = True


class Capture(NullCapture):
    def __init__(self, root: Path, experiment: dict, connection: int, peer, *, logger=None):
        super().__init__(experiment, connection, peer, logger=logger)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", experiment["name"])[:80]
        self.directory = Path(root) / f"{stamp}-{connection:04d}-{safe_name}"
        self.directory.mkdir(parents=True)
        self.events = (self.directory / "events.jsonl").open("w", encoding="utf-8")
        self.files = {(direction, kind): (self.directory / f"{direction}.{kind}.bin").open("wb")
                      for direction in ("c2s", "s2c") for kind in ("wire", "frames")}
        (self.directory / "experiment.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
        self.event("connected", peer=list(peer))

    def event(self, event, **fields):
        row = {"elapsed": round(time.monotonic() - self.started, 6), "event": event, **fields}
        self.events.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.events.flush()

    def bytes(self, direction, kind, data, stage=None):
        self.files[direction, kind].write(data)
        self.files[direction, kind].flush()
        if kind == "wire":
            self.event("wire", direction=direction, stage=stage, length=len(data), hex=data.hex())
        super().bytes(direction, kind, data, stage)

    def stage(self, name, **fields):
        self.summary["stage"] = name
        self.event("stage", stage=name, **fields)

    def frame(self, direction, payload, framed, description):
        self.bytes(direction, "frames", framed)
        key = "received_frames" if direction == "c2s" else "sent_frames"
        self.summary[key] += 1
        decoded = self.observe_frame(direction, payload, description)
        self.event("frame", direction=direction, number=self.summary[key], hex=payload.hex(),
                   beta=decoded, **description)

    def close(self, reason, pending=b""):
        if self.closed:
            return
        self.summary.update(reason=reason, duration=round(time.monotonic() - self.started, 3),
                            pending_plaintext_hex=pending.hex())
        self.event("closed", **self.summary)
        (self.directory / "summary.json").write_text(json.dumps(self.summary, indent=2), encoding="utf-8")
        self.events.close()
        for file in self.files.values():
            file.close()
        self.closed = True


def create_capture(root, experiment, connection, peer, *, logger=None):
    """None disables files; a path preserves existing per-session captures."""
    if root is None:
        return NullCapture(experiment, connection, peer, logger=logger)
    return Capture(root, experiment, connection, peer, logger=logger)
