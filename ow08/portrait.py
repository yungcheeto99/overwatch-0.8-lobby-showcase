"""Original build-24919 account portrait resources.

The identifiers come from the beta's general package avatar unlocks and textures.
"""

from dataclasses import dataclass
import re


DEFAULT_PORTRAIT = 0x02500000000002F7


@dataclass(frozen=True)
class Portrait:
    name: str
    guid: int


# Native enUS names and unlock GUIDs extracted from the unchanged local beta
# APM with tools/inspect_beta_assets.py. Avatar class hash: 0x8CDAA871.
# Keep this static so selecting a portrait never requires client archives.
PORTRAITS = (
    Portrait("Bastion", 0x0250000000000310),
    Portrait("D.Va", 0x0250000000000317),
    Portrait("Genji", 0x0250000000000316),
    Portrait("Hanzo", 0x025000000000030B),
    Portrait("Junkrat", 0x0250000000000315),
    Portrait("Logo 2", 0x02500000000002F9),
    Portrait("L\u00facio", 0x0250000000000313),
    Portrait("McCree", 0x0250000000000304),
    Portrait("Mei", 0x0250000000000318),
    Portrait("Mercy", 0x0250000000000305),
    Portrait("Overwatch Logo", DEFAULT_PORTRAIT),
    Portrait("Pharah", 0x0250000000000309),
    Portrait("Reaper", 0x0250000000000307),
    Portrait("Reinhardt", 0x025000000000030A),
    Portrait("Roadhog", 0x0250000000000314),
    Portrait("Soldier: 76", 0x0250000000000312),
    Portrait("Symmetra", 0x025000000000030F),
    Portrait("Torbj\u00f6rn", 0x025000000000030C),
    Portrait("Tracer", 0x0250000000000306),
    Portrait("Widowmaker", 0x0250000000000308),
    Portrait("Winston", 0x025000000000030D),
    Portrait("Zarya", 0x0250000000000311),
    Portrait("Zenyatta", 0x025000000000030E),
)
_BY_NAME = {portrait.name.casefold(): portrait for portrait in PORTRAITS}
_BY_GUID = {portrait.guid: portrait for portrait in PORTRAITS}
_GUID = re.compile(r"(?:0x[0-9a-f]{1,16}|[0-9a-f]{16})", re.IGNORECASE | re.ASCII)


def resolve_portrait(text: str) -> Portrait:
    """Resolve a printed number, case-insensitive native name or unlock GUID."""
    if not isinstance(text, str):
        raise ValueError("portrait must be a listed number, name or GUID")
    supplied = text.strip()
    portrait = _BY_NAME.get(supplied.casefold())
    if portrait is None and _GUID.fullmatch(supplied):
        portrait = _BY_GUID.get(int(supplied, 16))
    if portrait is None and supplied.isascii() and supplied.isdecimal() and len(supplied) <= 2:
        number = int(supplied)
        if 1 <= number <= len(PORTRAITS):
            portrait = PORTRAITS[number - 1]
    if portrait is None:
        raise ValueError("unknown portrait; use a listed number, name or GUID")
    return portrait
