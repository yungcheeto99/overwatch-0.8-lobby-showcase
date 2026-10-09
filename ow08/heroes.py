"""Build-24919 hero assets and the minimal native menu catalog.

The fixed roster and classic skins come from the beta's own CASC packages.
20504 preloads packages; 24900 supplies the separate per-hero cache used by
the original menu. These records do not implement full hero progression.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
import unicodedata


IN_HERO_PROGRESSION = 0x70519A68
DEFAULT_HERO_LEVEL = 1
# The client compares levels against a server-supplied limit. Twenty is a
# reconstruction of the scrapped beta cap, not a recovered original packet.
HERO_LEVEL_LIMIT = 20


@dataclass(frozen=True)
class Hero:
    key: str
    name: str
    hero_guid: int
    skin_guid: int


# APM package rows 321..341 identify the heroes. Each DUTS hero record has
# one classic skin reference; these are beta GUIDs, including the 02E type.
# The 0AE skin GUID is a base wrapper, distinct from its 0A5 color themes.
HEROES = (
    Hero("widowmaker", "Widowmaker", 0x02E000000000000A, 0x0AE00000000003EB),
    Hero("reinhardt", "Reinhardt", 0x02E0000000000007, 0x0AE00000000003E1),
    Hero("mercy", "Mercy", 0x02E0000000000004, 0x0AE00000000003D4),
    Hero("winston", "Winston", 0x02E0000000000009, 0x0AE00000000003E7),
    Hero("genji", "Genji", 0x02E0000000000029, 0x0AE00000000003E8),
    Hero("symmetra", "Symmetra", 0x02E0000000000016, 0x0AE00000000003E9),
    Hero("mccree", "McCree", 0x02E0000000000042, 0x0AE00000000003D7),
    Hero("mei", "Mei", 0x02E00000000000DD, 0x0AE00000000003DD),
    Hero("bastion", "Bastion", 0x02E0000000000015, 0x0AE00000000003DE),
    Hero("reaper", "Reaper", 0x02E0000000000002, 0x0AE00000000003E3),
    Hero("pharah", "Pharah", 0x02E0000000000008, 0x0AE00000000003E5),
    Hero("hanzo", "Hanzo", 0x02E0000000000005, 0x0AE00000000003D6),
    Hero("torbjorn", "Torbjörn", 0x02E0000000000006, 0x0AE00000000003E0),
    Hero("junkrat", "Junkrat", 0x02E0000000000065, 0x0AE00000000003D9),
    Hero("zarya", "Zarya", 0x02E0000000000068, 0x0AE00000000003E2),
    Hero("roadhog", "Roadhog", 0x02E0000000000040, 0x0AE00000000003E4),
    Hero("tracer", "Tracer", 0x02E0000000000003, 0x0AE00000000003EA),
    Hero("dva", "D.Va", 0x02E000000000007A, 0x0AE00000000003DC),
    Hero("zenyatta", "Zenyatta", 0x02E0000000000020, 0x0AE00000000003D8),
    Hero("soldier76", "Soldier: 76", 0x02E000000000006E, 0x0AE00000000003E6),
    Hero("lucio", "Lúcio", 0x02E0000000000079, 0x0AE00000000003DA),
)
_BY_KEY = {hero.key: hero for hero in HEROES}
_ALIASES = {"torb": "torbjorn", "soldier": "soldier76"}
# Present in the October client assets, but revealed after its launch roster.
EXTENDED_HERO_KEYS = frozenset(("dva", "genji", "mei"))
LAUNCH_HEROES = tuple(hero for hero in HEROES if hero.key not in EXTENDED_HERO_KEYS)


def normalize_menu_hero(value):
    """Resolve a human name to a fixed beta hero, random, or none."""
    if not isinstance(value, str):
        raise ValueError("menu hero must be a beta hero name, random, or none")
    folded = unicodedata.normalize("NFKD", value.casefold()).replace("ø", "o")
    key = "".join(char for char in folded
                  if not unicodedata.combining(char)
                  and not char.isspace() and char not in ".:_-")
    key = _ALIASES.get(key, key)
    if key not in _BY_KEY and key not in ("random", "none"):
        raise ValueError("menu hero must be a beta hero name, random, or none")
    return key


def menu_heroes(value="random", *, extended=False):
    """Return the menu's permitted roster; the client chooses from random."""
    key = normalize_menu_hero(value)
    if key == "random":
        return HEROES if extended else LAUNCH_HEROES
    if key == "none" or not extended and key in EXTENDED_HERO_KEYS:
        return ()
    return (_BY_KEY[key],)


def beta_hero_preload(value="random", *, extended=False):
    """20504: preload beta hero and classic skin packages in mode 5."""
    selected = menu_heroes(value, extended=extended)
    packs = tuple(guid for hero in selected
                  for guid in (hero.hero_guid, hero.skin_guid))
    # Four u64 arrays. C53390 loads the first, second and fourth in mode 5;
    # the third uses mode 3. Only the first list is needed for menu assets.
    return struct.pack("<I", len(packs)) + b"".join(
        struct.pack("<Q", guid) for guid in packs) + bytes(12)


def beta_hero_catalog(value="random", *, extended=False, levels=None):
    """24900: native menu hero records, classic skins, and title keys."""
    selected = menu_heroes(value, extended=extended)
    levels = {} if levels is None or not extended else levels
    if not isinstance(levels, dict):
        raise ValueError("hero levels must be a mapping of beta hero keys to levels")
    for key, level in levels.items():
        if key not in _BY_KEY or type(level) is not int or not 1 <= level <= HERO_LEVEL_LIMIT:
            raise ValueError("hero levels must be integers from 1 to 20 for beta heroes")
    rows = []
    for hero in selected:
        # Descriptor order: u8, u32, twelve u64s, then two struct arrays.
        # CE812A keys the row by memory +08; 24902 writes memory +20.
        # +20 expects the 0AE wrapper; replacing it with a 0A5 recolor theme
        # made the menu hero disappear. The first array at native +68 maps
        # (base skin, 025 color selector); only ordinals 1/2 were recovered.
        # Leave both arrays empty and keep the usual classic color at all levels.
        values = (hero.hero_guid, 0, 0, hero.skin_guid) + (0,) * 8
        rows.append(struct.pack("<BI12QII", 1, levels.get(hero.key, DEFAULT_HERO_LEVEL), *values, 0, 0))
    # The leading i32 is the native hero level limit. The menu compares the
    # row's u32 level with it; keep the reconstructed cap above a new level 1.
    # CE8290 keys the second array's map at manager +120. FeatureHeroName
    # requires both this map and the first array's +F8 map to contain the hero.
    titles = b"".join(struct.pack("<QI", hero.hero_guid, 0) for hero in selected)
    return (struct.pack("<iI", HERO_LEVEL_LIMIT, len(rows)) + b"".join(rows)
            + struct.pack("<I", len(selected)) + titles)
