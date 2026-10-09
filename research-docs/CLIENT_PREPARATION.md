# Temporary client preparation and restoration

The launcher starts and patches only its own checked child process for the
[supported executable](README.md). It routes `--BNetServer` to a loopback
endpoint and temporarily prepares build-specific certificate and lobby RSA
sites. The executable on disk and Windows certificate stores are untouched.

Implementation: [client.py](../ow08/client.py),
[split_launch.py](../ow08/split_launch.py), and
[launch_bridge.py](../ow08/launch_bridge.py).

## Build-specific sites

All addresses below are RVAs relative to the loaded image:

| Site | RVA | Original / temporary bytes |
| --- | --- | --- |
| Certificate pin call | `0x1100106` | `FF 50 38` / three NOPs |
| Certificate-check branch | `0x110010D` | `0F 85 78 01 00 00` / six NOPs |
| Lobby RSA modulus | `0x14DB9A0` | Original 256-byte modulus / generated local public modulus |

The exponent at `0x14DB994` is little-endian `01 00 01` (65537).

## Restoration gates

1. Initial preparation applies both TLS edits and the local RSA
   modulus. Preparation is checked per bootstrap socket.
2. After the first RPC, the credentials path restores the original TLS and
   RSA bytes before native login continues.
3. A valid authenticated referral triggers RSA preparation again for the
   lobby's signed [JAM state](JAM_PROTOCOL.md).
4. The encrypted family announcement triggers restoration before the
   ACK/login replies.

Restoration verifies the owned process, patch receipts and live bytes, then
reads back each restored site. A mismatch stops the child.

## Compatibility limits

These addresses and signatures apply only to the supported executable.
Stability across different PCs is not fully verified.

Patch provenance is recorded in
[Sources and licensing](SOURCES_AND_LICENSE.md). The surrounding flow is
documented in [bootstrap and authentication](BOOTSTRAP_AND_AUTH.md) and
[menu initialization](MENU_INITIALIZATION.md).
