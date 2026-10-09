# Beta login and menu initialization

The showcase initializes the native lobby with hero, player, party and social
state. This working sequence is supported by client observations and receiver
inspection; the necessity of every reply is not established.

Implementation: [login.py](../ow08/login.py), [menu.py](../ow08/menu.py),
[heroes.py](../ow08/heroes.py), and [packet_log.py](../ow08/packet_log.py).
All layouts follow the [JAM encoding rules](JAM_PROTOCOL.md#message-encoding).

## Connect and initialization order

Upon outbound Connect CRC `D7D457DD`, offset 0 / ID **21800**, the showcase
sends:

| Order | Inbound CRC / offset / beta ID | Body and purpose |
| --- | --- | --- |
| 1 | `4E958DAF` / 0 / 20500 (`0x5014`) | Account id16; player name string |
| 2 | `4E958DAF` / 3 / 20503 (`0x5017`) | u32 key count; u64 key names; u32 byte count; concatenated 16-byte key values |
| 3 | `4E958DAF` / 4 / 20504 (`0x5018`) | Four u64 arrays; first lists selected hero/classic-skin packages, other three empty |
| 4 | `70519A68` / 0 / 24900 | Hero catalog and separate title map, before connect completion |
| 5 | `4E958DAF` / 1 / 20501 (`0x5015`) | Empty completion body |
| 6 | `912CEA67` / 1 / 20801 | Own-player record: id16, string, id16, u64, party id16, empty array |
| 7 | `912CEA67` / 2 / 20802 | Three f32 values 1; six false bool bits; empty settings array |
| 8 | `C988E4B3` / 0 / 20700 | Party id16; member array with an active local leader |
| 9 | `585B3816` / 0 / 27100; `8A89BC90` / 0 / 31800 | Stored friends/presence and friend profile records |
| 10 | `E79948F2` / 0 / 30500; `74C43F11` / 0 / 23300 | Empty FreeAssets array; two empty CustomGame arrays |
| 11 | `DBE61F10` / 3 / 20403 | Silent General snapshot: one joined channel with false flags |

Connect offset 2 / ID **20502** (`0x5016`) is disconnect/reconnect control;
omit it from successful login. The connect reply order **0, 3, 4, 1**
supports bare menu entry. The seven public build-24919
content-key pairs live in [login.py](../ow08/login.py). Their value-array
count is bytes (**112** for seven keys), not a count of key pairs.

## Hero assets, catalog and names

Hero display needs both the **20504 package preload** and **24900 catalog**.
A preload or FreeAssets list alone does not populate the showcase's hero
scene. The 21 beta hero/classic-skin GUID pairs in
[heroes.py](../ow08/heroes.py) come from the client's own packages.

The catalog is:

```text
i32 level_limit 20
array(hero rows)
array(title rows)
```

A minimal hero row is 109 wire bytes:

```text
u8 1; u32 current_level 1; twelve u64; two empty arrays
```

Within the twelve u64s, index 0 is the hero GUID and index 3 is its equipped
classic-skin `0AE` wrapper GUID; the rest are zero. The first row array,
native `+68`, holds `(wrapper GUID, 025 color-selector GUID)` contexts; the
showcase leaves it empty. See [skin wrappers and recoloring](#skin-wrappers-and-recoloring).
The leading u8's exact enum meaning
is unresolved; receiver evidence argues against describing it as a
generic online/status boolean. A title row is `u64 hero GUID; empty nested
array`. Both maps are required for the native hero name.

The default random menu roster contains the **18 October heroes**. D.Va,
Genji and Mei are excluded from the preload and both catalog maps even though
their assets exist in the client's asset set. Their later public reveal
and the evidence for the cap are documented in
[packet research](PACKET_RESEARCH.md#defaults-and-extended-reconstruction).

## Native featured-hero selection

The native client chooses the lobby hero from the logged-in account's eligible
catalog.

Native chooser `CE93B0` collects all catalog heroes and a preferred pool where
cached level `+04` is above 1 or the progression value at `+10` is nonzero
(`CE9476..CE9481`). It chooses randomly from the preferred pool when populated,
otherwise from the full pool (`CE9528..CE9541`, random helper `87B390`). The
chosen GUID is cached in the player manager at `+230`.

Main-menu update `DA72B8..DA72DA` invokes that chooser when the cached GUID is
zero. A full `24900` catalog replacement (`CE80D0`) preserves the cached GUID,
so a level update does not itself change the displayed hero. Selection is
random within the preferred pool, rather than based on the highest level.

Default mode supplies level 1 for the 18 enabled heroes, so the full roster is
eligible. Extended mode supplies each account's saved levels for all 21 heroes;
any hero above level 1 can join the native preferred pool. Progression values
remain zero.

## Skin wrappers and recoloring

Build 24919 uses `0AE` base-skin wrappers (class `C25082A2`) with references to
four `0A5` color themes (class `4FB2CE32`). Hero-record equipment index 3 is
the wrapper, copied to native `+20`. A raw theme GUID in this slot prevents
the hero model from displaying. The showcase uses classic wrappers at every
level.

The context array at native `+68` holds `(wrapper GUID, 025 selector GUID)`.
`CE8D20` uses the selector's `+38` ordinal to choose a theme. Asset inspection
identified 42 selectors of class `8B9DEB02`: 21 ordinal-1 base slots and 21
ordinal-2 slots. Ordinal-3/4 selectors are unconfirmed, and the ordinal-2
context path has not been verified in the native menu. Recolor selection and
cosmetic unlocks are unimplemented; the context array remains empty.

Model/theme variants have derived lookup keys (`9C4CF0`), which are not direct
preload GUIDs. `20504` uses secondary context zero. These findings describe
the menu equipment path, not every use of color themes in the client.

## Extended mode and reconstructed levels

Default mode enables 18 heroes at level 1. Extended mode enables all 21 heroes
and saved per-account levels:

```text
.herolevel <account> <hero/all> <level>
```

Levels range from **1 through 20** and persist per account. Connected actors
receive a full 24900 catalog replacement, preserving both maps and avoiding
the incremental 24904 receiver's assumption that the hero already exists in
its cache. Normal mode ignores saved overrides and sends current level 1;
restarting in extended mode restores them. The server-supplied maximum stays
20 in both modes.

The cap of 20 is a reconstruction supported by period sources; an original
build-24919 server packet has not been recovered. XP earning, rewards and
gameplay progression are unimplemented. The
[hero progression family](PACKET_RESEARCH.md#hero-progression-family) documents
the recovered layouts and unresolved fields.

## Player, party and delayed welcome

A party member uses:

```text
string; bool leader; u8 status; u64 portrait; u64; id16; id16
```

Status **5** with leader true enables the solo menu; statuses **5..7**
count as active. The minimum record uses the authenticated local account for
both IDs. Some player and party field meanings are unknown.

After three seconds, [menu.py](../ow08/menu.py) refreshes the current player
and party, then sends the first yellow welcome as Chat offset 0. Pending shared
messages follow that welcome. Chat startup and social identity details are in
[Social protocol](SOCIAL_PROTOCOL.md).

## Player progression placeholders

PlayerProgression request `C345520E/0` receives `BD212AB1` offsets 0..4:

| Offset | Minimal reply |
| --- | --- |
| 0 | 17 zero bytes: bool; u64; two empty arrays |
| 1 | u64 zero |
| 2 | Empty u64 array |
| 3 | Empty array of string/u64 rows |
| 4 | Empty array of string/u64 rows |

These placeholders provide valid wire layouts without full progression state.
The diagnostic roles of offsets 3 and 4, the partly understood offset 1 GUID
and the remaining unknowns are documented in
[packet research](PACKET_RESEARCH.md#player-and-social-messages).
