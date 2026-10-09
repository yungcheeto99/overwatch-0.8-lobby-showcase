# Research sources and licensing

This showcase builds on public Overwatch preservation research. Thank you to
the community for the shared tools, findings and shared work underlying
the cipher, handshake, login flow and client startup.

## Sources and contributions

| Reference | Contribution here |
| --- | --- |
| [Hitachi MULTI-S01 specification, section 2.3.2](https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/11_02espec.pdf) | Canonical PANAMA equations used for the independently authored [JAM cipher](../ow08/cipher.py). |
| [squeeeezy/overwatch-1.74-lobby-server (now private, as of writing)](https://github.com/squeeeezy/overwatch-1.74-lobby-server/tree/0d624a796d072d14f2de7a420ddd0b658a31c688) | JAM initialization, signed-state layouts, key derivation and framing research used as compatibility evidence. No implementation code is included in this showcase. |
| [Boi-027/Overwatch-1-v1.74-Lobby-Research](https://github.com/Boi-027/Overwatch-1-v1.74-Lobby-Research/tree/d0cee4ce08f276b27866a4b99a11201c509e9cb6) | Handshake/state-block research and reference layouts used for the lobby connection.  |
| [plasmawatch/login-server](https://github.com/plasmawatch/login-server/tree/125f2351d53e7bf007c214984aa506e0795775ef) | Battle.net service hashes, wire fields, account identity tags, and challenge/form/ticket and login-error behavior used in [bootstrap.py](../ow08/bootstrap.py). |
| [plasmawatch/OverLauncher](https://github.com/plasmawatch/OverLauncher/tree/138ff5a3bf83afb79a32e1c5cf65fc2d557955f7) | Beta client patch addresses/signatures used by the process-owned launcher in [client.py](../ow08/client.py). |
| [saturn-xvi/prometheus](https://github.com/saturn-xvi/prometheus/tree/ad1fea7e6c04c9959c7115cb8ecd9c79c93c1ccb) | Beta metadata research and public build-24919 content-key values in [login.py](../ow08/login.py). No implementation code is included in this showcase. |
| [Logo2K's protocol notes](https://rentry.co/3bswrgmw) | Channel-trailer, framing and payload-encoding research that helped interpret the lobby wire format. |

The upstream research also acknowledges **AyakaPS** and **Blizless** for
state-trailer findings. Historical sources for the October roster and scrapped
hero progression are linked alongside the corresponding evidence in
[Packet research](PACKET_RESEARCH.md#defaults-and-extended-reconstruction).

These references explain provenance. Later-build references do not override
the original beta descriptors or receivers; see the
[research evidence guide](README.md#how-to-interpret-the-evidence).

## README images

[Lobby screen](images/lobby-screen.png) is an unaltered beta client capture.
[Lobby UI collage](images/lobby-ui-collage.png) is a composite of menu and social captures. 
The original game UI and artwork belong to Blizzard and are excluded from the project's 0BSD license.

## Source licensing

The showcase source and launchers are licensed under [0BSD](../LICENSE).
The PANAMA/JAM cipher and state/trailer encoders are independently authored
from published algorithm descriptions, protocol facts and byte-level
compatibility tests. The references above credit research rather than
included third-party implementation code; they are voluntary acknowledgments.

External dependencies retain their own license terms. Blizzard game assets,
artwork and trademarks are excluded from the project's license.
