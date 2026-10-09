# Beta chat, tells and social identity

The showcase routes native menu chat and friend/party actions through admitted
account sessions. Beta field layouts and sender identity are essential: later
builds add structures that this client's announcement and receivers do not
support.

Implementation: [friends.py](../ow08/friends.py),
[party.py](../ow08/party.py), [lobby.py](../ow08/lobby.py),
[party_lobby.py](../ow08/party_lobby.py), and
[social_store.py](../ow08/social_store.py). See
[JAM encoding](JAM_PROTOCOL.md#message-encoding) for scalars, arrays, packed
booleans and `id16`.

## Channels and native chat

A channel is `i32 type; id16`. General uses **type 9 with zero ID**; group
chat uses **type 4 with party ID**.

| Direction / CRC / offset / ID | Body |
| --- | --- |
| Inbound `DBE61F10/0`, 20400 | channel; sender name; sender id16; text |
| Outbound `11757702/0`, 21700 | channel; text |

An empty sender name with zero sender ID selects system text: **type 2** is
yellow announcement text; **type 1** is red error text. Keep the authenticated
sender identity for ordinary messages: local sender IDs trigger the native
client's local echo suppression.

Joined-channel records contain three packed booleans before the channel;
false flags permit input. Silent startup sends **20403**, while explicit
member requests use **20401**. The first welcome is delayed until the
[player/party refresh](MENU_INITIALIZATION.md#player-party-and-delayed-welcome);
pending shared messages follow it.

## Friend tells and completion tokens

| Direction / CRC / offset / ID | Body / identity |
| --- | --- |
| Outbound `027ADB37/4`, 27004 | u64 token; recipient root id16; recipient game id16; text |
| Inbound `585B3816/13`, 27113 | Received tell with sender root ID |
| Inbound `585B3816/14`, 27114 | Sent echo with recipient root ID |
| Inbound `585B3816/12`, 27112 | u64 token; u32 status, completing the request |

The hub derives senders from admitted sessions and enforces friend, channel
and party membership. Root and game identities serve distinct routing roles;
a client-supplied sender claim does not replace authenticated ownership.

The implemented social surface includes friend requests, favorites, presence,
direct tells, party invitations, acceptance/decline, leaving, kicking,
leader transfer and group chat. Portraits and optional Real ID display labels
are saved in the local account store. Online/away/busy presence is session-only
and resets on reconnect. Real ID labels may be fictional;
`.accountrealname PlayerName --clear` removes one.

Online players become Away after 15 minutes without player actions and
return to Online on activity. Busy and manually selected Away status are not affected.

## Favorites and the native star

Favorites belong to the account selecting them. Initial `27100` friend records
and incremental `27105` updates carry the preference in **bit 0 of the u64
metadata**, after the first u32 and before the root account ID. Native `27005`
changes that same bit; `27112` completes its operation token. Favorite updates
do not require an extra presence packet.

Root presence **BN1/4** supplies the full BattleTag; the client removes the
`#number` suffix for its short display name. Optional Real ID labels use
**BN1/1**.

The beta's `BaseFriendTemplate` includes a gold star only in its **Real ID
name layout**. BattleTag-only rows can offer **Remove from Favorites** without
showing a star. Set a label with `.accountrealname PlayerName "Display Name"`;
`--clear` removes it. Restoring stars in the BattleTag layout requires a client
UI change.

## Native category header counts

The client calculates category totals from friend presence; the server sends
no separate category count message. Header text can retain its initial stale count
after friends log in, log out or change games, while the friend rows and Social
total update correctly. This requires a client UI refresh fix; changing name
encoding does not correct the counters.

## Other-game presence

`.game <account> <game>` changes an online synthetic friend's advertised game
in default or extended mode. `.game` lists the available games. Selection is
session-only and resets on login; `.status` is usable. `.game <account> None`
shows the friend online on Battle.net without playing a game. Game names ignore
case, and `.users` reports this choice as Battle.net.

| Command key | Game | Native program |
| --- | --- | --- |
| `overwatch` | Overwatch | `Pro` / `0x50726F` |
| `hearthstone` | Hearthstone | `WTCG` / `0x57544347` |
| `wow` | World of Warcraft | `WOW` / `0x574F57` |
| `starcraft2` | StarCraft II | `S2` / `0x5332` |
| `diablo3` | Diablo III | `D3` / `0x4433` |
| `heroes` | Heroes of the Storm | `Hero` / `0x4865726F` |
| `none` | Battle.net (no game) | `BN` / `0x424E` |

Game-account IDs have high word `(2 << 56) | (region << 32) | program`.
The selected child's program drives `FriendVM.PrimaryProgram` (`0x91F069F3`,
`C155B0`, `DBF586`, `ABF3B0`). The native `FriendGameStatus` asset
`0BA000000000005D`, content MD5 `d87a3221810957f1cba011fece3d18a1`, contains
the five external-game icon bindings. Warcraft's numeric program is uppercase
`WOW`, although its UI label reads `WoW`.

Presence keys remain in namespace BN (`0x424E`): BN2/1 is online, BN2/2 is busy,
and BN2/10 is away. `C15800` prefers an online Overwatch child. Switching games
therefore sends the previous child offline before adding the replacement;
availability flags are cleared when reusing a cached child. Accepted friends
receive these updates, and tells validate the current advertised child ID.

Other-game Invite/Join actions are inactive. Switching away from Overwatch
cancels the synthetic actor's invitations and removes it from a shared party.
These presences do not establish connections to the other games. Category
headers have the [native refresh limitation](#native-category-header-counts)
described above.

## Activity captions

Arbitrary activity descriptions are unsupported. BN2/8 contains a
`Variant.message_value` with a `RichPresenceLocalizationKey`: fixed32 program
(field 1), fixed32 stream (field 2), and uint32 localization ID (field 3).
`C18A40/C18DA0` resolve it through a downloaded localization dictionary.
`27110` supplies a content handle for an HTTP download, not literal caption
text. Content delivery and dictionary decoding are unimplemented.

`C18E92..C18ECD` resolves `$<ID>` by recursively reading another BN2/8 key on
the same entity, using `ID` as `unique_id`. It does not substitute a raw string
presence field. `DBEC10` displays the resulting child cache at `+70` through
`StatusText` (`0x7492E87F`).

Original game-specific activity templates and localization entries have not
been recovered.

## Diagnostic messages and unresolved behavior

[Packet research](PACKET_RESEARCH.md#player-and-social-messages)
documents native console output, rich-presence localization requests/responses,
presence cache reset and report receipt/failure notices. A console diagnostic
path is not lobby chat, and decoding a report response does not implement report
processing. Native Block and Report are currently recorded but unimplemented.
The trigger for the original server's presence reset and parts of the
localization content-handle protobuf remain unresolved.

## Later-build cautions

The beta announcement lacks 1.74's extra chat fields, player-card layout,
prefixed routing header, permissions message **55500** and separate name-query
families. Family indexes are specific to each connection.
