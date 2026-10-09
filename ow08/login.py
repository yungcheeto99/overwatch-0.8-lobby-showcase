"""Beta identity and public content key metadata for menu login."""

import struct

IN_CONNECT_BETA = 0x4E958DAF
OUT_CONNECT_BETA = 0xD7D457DD
IN_PROGRESSION_BETA = 0xBD212AB1
OUT_PROGRESSION_BETA = 0xC345520E

# Public build-24919 content keys supplied during login.
BETA_CASC_KEYS = (
    (0xDBD3371554F60306, "34E397ACE6DD30EEFDC98A2AB093CD3C"),
    (0x11A9203C9881710A, "2E2CB8C397C2F24ED0B5E452F18DC267"),
    (0xA19C4F859F6EFA54, "0196CB6F5ECBAD7CB5283891B9712B4B"),
    (0x87AEBBC9C4E6B601, "685E86C6063DFDA6C9E85298076B3D42"),
    (0xDEE3A0521EFF6F03, "AD740CE3FFFF9231468126985708E1B9"),
    (0x8C9106108AA84F07, "53D859DDA2635A38DC32E72B11B32F29"),
    (0x49166D358A34D815, "667868CD94EA0135B9B16C93B1124ABA"),
)


def beta_login_bodies(name="Player", known_keys=False, flag=True, account_id=None):
    """Candidate encoding of read-only beta metadata, with assumed min ID 0x5014.

    The two key arrays are distinct u64-name and byte-value arrays. Counts and
    NUL string encoding remain beta hypotheses.
    The boolean's meaning and the four data-pack arrays' contents are unknown.
    """
    if "\0" in name:
        raise ValueError("player name cannot contain NUL")
    account_id = struct.pack("<QQ", 1, 0x0100000000000000) if account_id is None else account_id
    if not isinstance(account_id, bytes) or len(account_id) != 16:
        raise ValueError("account identity must be 16 bytes")
    keys = BETA_CASC_KEYS if known_keys else ()
    names = b"".join(struct.pack("<Q", identifier) for identifier, _ in keys)
    values = b"".join(bytes.fromhex(value) for _, value in keys)
    return {
        0: account_id + name.encode("utf-8") + b"\0",
        2: bytes([bool(flag)]),
        3: struct.pack("<I", len(keys)) + names + struct.pack("<I", len(values)) + values,
        4: bytes(16),
    }
