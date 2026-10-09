"""Fixed beta channel acknowledgement, keepalive and progression replies."""
from __future__ import annotations

from .config import BetaRuntime
from .login import IN_PROGRESSION_BETA, OUT_PROGRESSION_BETA
from .server import Session


class BetaSession(Session):
    async def trigger(self, event, payload=b""):
        if event == "announcement":
            await self.send_payload(b"\0\x02")
        elif event == "frame":
            if payload == b"\0\x03":
                await self.send_payload(payload)
            elif (self.families.get(payload[0]) == OUT_PROGRESSION_BETA
                  and payload[1] == 0 and "progression" not in self.fired):
                self.fired.add("progression")
                for offset, body in enumerate((bytes(17), bytes(8), bytes(4), bytes(4), bytes(4))):
                    await self.send_family(IN_PROGRESSION_BETA, offset, body)
