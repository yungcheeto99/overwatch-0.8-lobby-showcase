# Network, local data and diagnostics

These notes explain the showcase's transport and generated state. For the
interactive launch steps and LAN connection checks, see
[HowToUse.txt](../misc/HowToUse.txt). Authentication and account referral are
covered separately in [BOOTSTRAP_AND_AUTH.md](BOOTSTRAP_AND_AUTH.md).

## Endpoints and transport boundaries

| Service | Default endpoint | Purpose |
| --- | --- | --- |
| Battle.net TLS RPC | `127.0.0.1:1119` | Bootstrap, native authentication challenge and referral |
| Native HTTP login | `127.0.0.1:6969/battlenet/login` | Project credential form |
| Encrypted JAM lobby | `127.0.0.1:3725` | Native menu and social protocol |
| Launcher control | Loopback, automatically assigned port | Coordinates the owned client and preparation/restoration gates |
| LAN gateway | TCP `47325` on the selected LAN IPv4 | Carries remote clients' local service streams |
| Public tunnel backend | TCP `47325` on loopback | Existing gateway exposed through the temporary public tunnel |

The bootstrap, HTTP form and JAM service remain on loopback. Remote client
launchers create local endpoints for the game's connections, then carry those
streams through a TLS gateway pinned to the server certificate. The remote
launcher advertises its actual local lobby endpoint for the JAM state block.
The outer gateway does not replace the lobby's own protocol or cipher.

Virtual mode wraps that same gateway in HTTPS binary WebSockets. The inner TLS
and service streams remain opaque to the WebSocket bridge; outer HTTPS verifies
its CA certificate. Transport logic uses the Python standard library, with
Windows OpenSSH Client (`ssh.exe`) separately required for public hosting.
Relevant implementations are [remote_transport.py](../ow08/remote_transport.py),
[virtual/gateway.py](../virtual/gateway.py) and
[split_launch.py](../ow08/split_launch.py).

## LAN and temporary public hosting

For LAN, allow inbound gateway TCP `47325` from the intended guests. Use
`--remote-port` on both launchers when changing that port. Internal lobby,
bootstrap and HTTP ports are independently configurable and must be distinct.

Public hosting uses localhost.run's `nokey` SSH service to obtain a temporary
HTTPS hostname. No provider account, separate VPN installation, router port
forwarding or tunnel password is required. All participants need internet
access, and guests select VPN connection using the current identifier. A
client on the host PC uses that same public identifier when joining virtually.
Anyone with the identifier can reach the gateway. A restart obtains a new
identifier; the provider controls availability and hostname lifetime.

If the server certificate changes, guests verify the new SHA256 fingerprint
with the host before replacing a saved pin using `--server-pin`. See the
interactive guide for the corresponding connection checks.

## Persistent and transient state

Default accounts, relationships, TLS certificate/private key, lobby RSA key,
launcher rendezvous and saved server pins live under `data/`. They are
installation-specific and generated on demand. Passwords are stored as salted
PBKDF2-HMAC-SHA256 hashes. Challenges, single-use login tickets, authenticated
referrals and exclusive online leases are transient; a stored account alone
does not authorize a lobby connection.

Portraits and optional Real ID display labels are saved. Real ID labels may be
fictional; `.accountrealname PlayerName --clear` removes a label. Presence
status is session state and resets on reconnect. Extended hero-level overrides
are saved per account; default mode ignores them and sends level 1.

Synthetic players use registered accounts and hold the same exclusive ownership
as real clients. `.login PlayerName` claims an idle account and `.logoff` releases
it. Console party/group/tell commands act through synthetic players; friend and
message administration can also target real players. None of these commands
allocates matches or creates a gameplay session.

## Captures and cleanup

Console packet output is on by default; `--no-packet-log` reduces it. Disk
captures are off by default. `--capture` writes to `captures/`, while
`--capture "D:\Captures"` selects another directory. Captures may include names,
chat, machine paths, addresses and session material even when credential fields
are redacted. Review them before sharing. Packet labels describe recovered
behavior and preserve unknown fields; they are not evidence that an action is
implemented or that the original server sent the same values.

Generated data, captures, logs, keys and environments are ignored by Git.
Arbitrary custom output names selected with `--state`, `--invite` or `--accounts`
need matching local ignore rules; files outside the checkout must be managed
separately. The [.gitignore](../.gitignore) records recognized defaults.

Cleanup is optional. Close the launchers and game first, then use
`misc/CleanUp.bat --dry-run` to preview recognized items. Normal cleanup requires
typing `CLEAN`. Removing `data/` resets accounts and keys, which also changes
certificate identity for future connections. Preserve anything needed before
resetting state.
