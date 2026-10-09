# Build-24919 research notes

Protocol layouts, native receiver behavior and implementation limits for
**Overwatch Closed Beta 0.8.0.24919**. Installation and commands are covered in
the [project README](../README.md) and [interactive guide](../misc/HowToUse.txt).

The supported original `GameClientApp.exe` SHA256 is:

```text
21b761a5b48076728318290ee9d0be6ad1ee36af59e4b7aaefe7b7ac5bf2a68a
```

Addresses and layouts in these notes belong to that executable. Compatibility
with another build must be established separately.

## Reading order

| Note | Contents |
| --- | --- |
| [Bootstrap and authentication](BOOTSTRAP_AND_AUTH.md) | RPC services, web login, tickets and account admission |
| [Client preparation](CLIENT_PREPARATION.md) | Owned-process TLS/RSA preparation and restoration |
| [JAM protocol](JAM_PROTOCOL.md) | Signed state, keys, cipher, framing and family indexes |
| [Menu initialization](MENU_INITIALIZATION.md) | Hero catalogs, native selection, levels and skin limitations |
| [Social protocol](SOCIAL_PROTOCOL.md) | Chat, friends, parties, other games and activity captions |
| [Packet research](PACKET_RESEARCH.md) | Recovered message layouts, diagnostics and unresolved fields |
| [Network and storage](NETWORK_AND_STORAGE.md) | Local/remote transport, runtime data and cleanup |
| [Sources and licensing](SOURCES_AND_LICENSE.md) | Upstream research, algorithm and image provenance, source licensing |

## How to interpret the evidence

Beta descriptors establish wire order and widths; receiver inspection
establishes cache and diagnostic effects. Native menu observations support
the working login sequence. UI validation is identified separately where it
is incomplete, particularly for diagnostic messages, recolors and external-game
presence. Unknown fields retain explicit uncertainty.

Later-build layouts do not override beta evidence. Wire bodies omit C++ memory
padding, and family indexes come from each connection's announcement. Period
sources support the October roster and reconstructed level cap of 20; an
original build-24919 server capture has not established every policy or value.

Gameplay, full progression, rewards and Block/Report processing are
unimplemented. Specific technical limitations are documented with the relevant
protocol. Captures may contain private session data and need review before
sharing.
