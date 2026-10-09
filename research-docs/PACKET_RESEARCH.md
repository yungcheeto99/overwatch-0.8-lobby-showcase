# Build-24919 packet research

These notes document the known purposes, wire layouts and receiver behavior
of beta player, social and hero progression messages. The
[research index](README.md) links the handshake, menu, chat, friends and party sequence.
The corresponding names and bounded schemas are in
[ow08/packet_log.py](../ow08/packet_log.py). Decoding a message does not mean
the showcase implements its action.

## Evidence and interpretation

Wire layouts come from the beta client's message descriptors. Purpose labels
are supported by native receiver behavior and original asset/localization data.
Addresses below are RVAs (offsets from the loaded image base) for the
[supported build](README.md).

Wire scalars are little-endian. `array(T)` means `u32 count; T[count]`;
strings terminate with NUL. Native C++ offsets include padding that must not
be inserted into a wire body. Unknown fields retain explicit uncertainty.
Static inspection and packet-layout validation support these findings. Native
UI acceptance is not established for the diagnostic and incremental progression
messages.

## Player and social messages

| CRC / offset / ID | Wire body | Receiver evidence and meaning |
| --- | --- | --- |
| `912CEA67/0`, 20800 | `array(string)` | `C7D180` forwards the strings to the native print queue, `7E5C90`. Native console output; a diagnostic path rather than lobby chat. |
| `027ADB37/3`, 27003 | `u64 token; u32 key_part0; u32 key_part1; u32 selector` | `C17830` builds the message through vtable `160FCD8`, getter `FC5600`, metadata `17349A0`. `C18A40` parses rich-presence localization keys and `C18CD7` requests missing cache entries. The two key parts come from cache-key `+18/+1C`; the last selector comes from manager `+5C`, with exact semantics unresolved. |
| `585B3816/10`, 27110 | `u32 status; u64 token; u32 blob_size; protobuf bytes` | `C1A120` correlates the pending localization query, parses the protobuf through `E881C0`, and passes the content handle to `C179A0`. `C188E0/C18DA0` format downloaded rich-presence templates. Content-handle fields are partly unresolved; localization content delivery is unimplemented. |
| `585B3816/15`, 27115 | Empty | `C1A4B0` removes child presence entities through `C176C0`, deletes root presence group 1 field 3 and notifies affected friends. This is a presence cache reset; the original server trigger is unresolved. |
| `585B3816/17`, 27117 | `bool report_received` | Dispatch `C68EE0` / table `C69270` leads through `C6920F` to `C1A860`. Byte `+68` chooses resource `0DE0000000001AB7` on success or `0DE0000000001AB8` on failure. Original CASC strings confirm report receipt/failure notices. The showcase does not process reports. |
| `BD212AB1/1`, 24301 | `u64 progression_guid` | `CE8A10` appends a unique GUID to the first progression cache at manager `+158`, initializes its bool false, and requests the resource. The exact gameplay/reward role of that GUID remains unresolved. |
| `BD212AB1/3`, 24303 | `array(string unlock_name; u64 unlock_guid)` | Dispatch `C69E10` calls `C2A290`, which prints the heading `Default Unlocks` from literal `17FB808` and string/GUID rows using format literal `17FB7E8`. |
| `BD212AB1/4`, 24304 | Same as 24303 | `C2A3B0` prints `Active Unlocks` from `17FB828`, using format literal `17FB848`. Both lists are diagnostics; they do not install progression state. |

The known 24300 state layout is `bool; u64; two arrays` of
`bool; i32; u64; u64`. Its other field meanings, and the purpose of 24302's
u64 array, are unresolved. The showcase answers
24200 with five placeholder responses; diagnostic labels describe their
receiver purposes without implementing progression.

## Hero progression family

The beta family `70519A68` includes **24900 through 24908**. The dispatcher
at `C69340` accepts offsets through 8. The logger identifies and decodes all nine.

| Offset / ID | Body | Evidence and meaning |
| --- | --- | --- |
| 0 / 24900 | `i32 level_limit; array(hero_record); array(hero_guid; array(progress_entry))` | Metadata `1737D88`. `C69394..C693C2` sets manager `+F0`, then invokes `CE80D0` and `CE8290`. They replace the hero cache at `+F8` and separate hero/title-unlock map at `+120`. This is the full menu catalog. |
| 1 / 24901 | `u64 hero_guid; u64 unlock_guid` | Metadata `1737F30`, fields `1737A30`. `C693CE` resolves the existing hero through `CE95A0` and calls `CE96C0`. That function adds a nonduplicate owned unlock to the hero's `+80` array, with bool false; this message does not set a level. |
| 2 / 24902 | `u64 hero_guid; u64 skin_guid` | Metadata `1737F10`, fields `1737DB0`. The receiver updates the cached hero's `+20` equipped skin, the same field populated with its classic skin in 24900. |
| 3 / 24903 | `u64 hero_guid; u64 slot_or_context; u64 equipped_unlock_guid` | Metadata `1737A10`, fields `1737B50`. `CE8540` checks unlock resource types and updates hero equipment fields at `+28` through `+60`, or its per-context map at `+68`. The portrait/logo path at `CE85CC..CE85DD` can also set the account avatar at manager `+150`. Exact slot/context semantics remain unknown. |
| 4 / 24904 | `array(hero_level_update)` below | Metadata `1737E28`, fields `1737EC0`. `CE8480` finds an already cached hero; `CE84E2` assigns its level from update `+00`, and `CE84D9` copies update `+10` into hero `+10`. `CE84F0..CE850A` also adds listed owned unlocks through `CE96C0`. It assumes the hero already exists in the cache. |
| 5 / 24905 | `array(u64 experience_delta)` | Metadata `1737E48`, fields `1737E70`. `C296C0` prints the headings `Level` / `Delta Experience Needed` from `17FB738/17FB750`; it formats the low 32 bits of each wire u64. A diagnostic table, not an XP award. |
| 6 / 24906 | `u64 hero_guid; array(string unlock_name; u64 unlock_guid)` | Metadata `1737CE8`, fields `1737C70`. `C29970` prints an all-unlocks heading (`17FB710`) and string/GUID rows (`17FB7C8`). |
| 7 / 24907 | Same as 24906 | Metadata `17379F0`, fields `1737BF0`. `C29AA0` prints active unlocks (`17FB778/17FB7A8`). |
| 8 / 24908 | `u64 hero_guid; array(array(string unlock_name; u64 unlock_guid))` | Metadata `1737F50`, fields `1737D10`. `C29BD0` prints current unlocks by level, with literals `17FB688/17FB670/17FB6D8`. The displayed level is the zero-based outer array index; there is no explicit level scalar. |

`hero_level_update` is the following descriptor order, without padding:

```text
u32 current_level
u32 purpose_unknown
u64 hero_guid
u64 purpose_unknown_0
u64 purpose_unknown_1
array(u64 unlock_guid)
array(u32 purpose_unknown; u64 purpose_unknown_0;
      u64 purpose_unknown_1; u64 purpose_unknown_2)
```

The first unknown u64 is copied into the cached progression value and is an
experience candidate; that alone does not prove XP units, thresholds or
awarding rules. The remaining update fields and nested entries are unresolved.

A minimal 24900 hero row is 109 wire bytes:
`u8; u32 current_level; twelve u64; two empty arrays`. The first u8's exact enum
meaning is unresolved. `CE9770` derives it from the maximum resource `+38`
value among qualifying owned unlocks (resource class hash `3ECCEB5D`).
This is evidence against treating it as an arbitrary online/status boolean.
The showcase uses value 1 for this field. Among the twelve u64s, index 0 is the hero
GUID and index 3 is the equipped classic-skin `0AE` wrapper; the other
equipment/progression fields are zero in the showcase's minimal records.
The first row array at native `+68` holds `(wrapper GUID, 025 color-selector
GUID)` contexts and is empty in the showcase. A raw `0A5` theme must not
replace the wrapper. See
[skin wrappers and recoloring](MENU_INITIALIZATION.md#skin-wrappers-and-recoloring).

## Defaults and extended reconstruction

The default server supplies 18 menu heroes. D.Va, Genji and Mei are excluded
from both the 20504 package preload and both 24900 maps. Their assets are
present in this build, but they were publicly revealed later: Blizzard's
[November 6, 2015 announcement](https://investor.activision.com/static-files/814cc68e-1783-4eef-903d-6de04f07993b)
identifies all three as the final additions to its 21-hero roster, after the
[October 27 beta launch](https://overwatch.blizzard.com/en-us/news/19919176/overwatch-beta-coming-soon-10-14-2015/).

Default hero records use **current level 1**, with a **level limit of
20**. Jeff Kaplan's direct
[April 1, 2016 interview](https://gameinformer.com/b/features/archive/2016/04/01/from-guild-leader-to-game-director-pt-3-building-overwatch)
confirms the scrapped cosmetic hero progression range of 1 through 20.
That supports the reconstruction, but does not recover an original 24919
server packet: the client reads the maximum from the server, rather than
hardcoding 20. At `DA7436..DA745B`, the menu reads cached hero level `+04`
and compares it with manager maximum `+F0` for its maximum-level badge.

Extended mode exposes all 21 heroes and per-account levels 1..20. Level changes
send a full `24900` replacement, preserving both maps and avoiding `24904`'s
missing-hero assumption. Default mode sends level 1 and ignores saved
overrides. See [menu initialization](MENU_INITIALIZATION.md#extended-mode-and-reconstructed-levels)
for runtime behavior and progression limitations.
