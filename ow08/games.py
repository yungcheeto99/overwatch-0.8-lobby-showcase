"""Battle.net programs understood by the build 24919 Social renderer."""

from dataclasses import dataclass
import struct
from types import MappingProxyType


@dataclass(frozen=True)
class Game:
    slug: str
    name: str
    program: int


GAMES = MappingProxyType({game.slug: game for game in (
    # The beta requires an online application child even without a game.
    # Its native BN program selects the Battle.net row and permits whispers.
    Game("none", "Battle.net", 0x424E),
    Game("overwatch", "Overwatch", 0x50726F),
    Game("hearthstone", "Hearthstone", 0x57544347),
    Game("wow", "World of Warcraft", 0x574F57),
    Game("starcraft2", "StarCraft II", 0x5332),
    Game("diablo3", "Diablo III", 0x4433),
    Game("heroes", "Heroes of the Storm", 0x4865726F),
)})


def resolve_game(value):
    if not isinstance(value, str):
        raise ValueError("game must be a supported Battle.net game")
    key = "".join(char for char in value.casefold() if char not in " -_")
    for game in GAMES.values():
        if key in (game.slug, game.name.casefold().replace(" ", ""),
                   game.program.to_bytes(4, "big").lstrip(b"\0").decode("ascii").casefold()):
            return game
    raise ValueError("unknown game; use .game to list supported Battle.net games")


@dataclass(frozen=True)
class GameActivity:
    game: str = "overwatch"

    def __post_init__(self):
        object.__setattr__(self, "game", resolve_game(self.game).slug)


DEFAULT_GAME_ACTIVITY = GameActivity()


def game_account_id(account, game="overwatch"):
    """Keep the account number/region, replacing only the presence program."""
    selected = resolve_game(game)
    low, high = struct.unpack("<QQ", account.game_account_id)
    return struct.pack("<QQ", low, (high & ~0xFFFFFFFF) | selected.program)
