"""A local RSA identity for the beta JAM state handshake.

The supported beta imports its 256-byte modulus and three-byte exponent in
little-endian order. It transforms the first 256 state bytes with raw RSA
before checking their fixed HMAC. These helpers sign that state for a fresh
local key whose public modulus can be supplied to the owned-child launcher.
They never open or modify a client process or the original executable.
"""
from pathlib import Path


DEFAULT_LOCAL_KEY = Path(__file__).resolve().parents[1] / "data" / "lobby-rsa.pem"
STATE_CORE_SIZE = 256
PUBLIC_EXPONENT = 65537
ORIGINAL_MODULUS_RVA = 0x14DB9A0
MODULUS_RVA = ORIGINAL_MODULUS_RVA
ORIGINAL_EXPONENT_RVA = 0x14DB994
ORIGINAL_EXPONENT_LE = bytes.fromhex("010001")
# Supported 0.8.0.24919 client SHA256:
# 21b761a5b48076728318290ee9d0be6ad1ee36af59e4b7aaefe7b7ac5bf2a68a
# Confirmed by the constructor at RVA 0x10E1790 in the unpacked code snapshot.
ORIGINAL_MODULUS_LE = bytes.fromhex(
    "adaa2900612260d2d6b5dd1420c63c84dc6e6b88278d3087642bc6b5d7a624b3"
    "0e1cfe0a48653bc8ac1ed8a2b080b0ad252d7939226455190d2a593b0ca51311"
    "d6c2885821e914e73041c98863214d3aa1ea33bc000846f10cd71e86f6bd12b72"
    "e849bebb441d8fd1409e57d532ae93559a7247be2bfb62879095d7eeba8282c4b"
    "5b2fce3fb66168d57b5e7869900af839a0cb14eec51b26edc51a3e15c153d829"
    "87df7e8ae82ecbcb28ada158eee4768c1bcc7fd7312431dc37b2d98477100681"
    "a160a4cff006410404c2903f4f67dee79f3690d333fbeea6993323b014eae77cf"
    "b2cbdc9e9526497cd2fcd7057ab3a32608ced50a1628a8bf17942d54226b5"
)


def _validated_key(private_key):
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("local lobby key must be an RSA private key")
    if private_key.key_size != 2048 or private_key.public_key().public_numbers().e != PUBLIC_EXPONENT:
        raise ValueError("local lobby key must be RSA-2048 with exponent 65537")
    return private_key


def load_or_generate_local_key(path=DEFAULT_LOCAL_KEY):
    """Load an RSA-2048 key, or create a fresh unencrypted PKCS8 PEM once.

    Existing files are never replaced, including malformed or encrypted keys.
    The generated key belongs to this installation. cryptography is needed
    for key generation/loading and signing.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    path = Path(path)
    if path.exists():
        return _validated_key(serialization.load_pem_private_key(path.read_bytes(), password=None))
    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=2048)
    encoded = private_key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())
    try:
        with path.open("xb") as output:
            output.write(encoded)
    except FileExistsError:
        # A concurrent starter won the exclusive create. Use its identity so
        # the listener and the child always refer to the same public key.
        return _validated_key(serialization.load_pem_private_key(path.read_bytes(), password=None))
    return private_key


def local_modulus_le(private_key) -> bytes:
    """Return exactly 256 little-endian public-modulus bytes for the launcher."""
    numbers = _validated_key(private_key).public_key().public_numbers()
    return numbers.n.to_bytes(STATE_CORE_SIZE, "little")


def sign_state_core(state_core: bytes, private_key) -> bytes:
    """Apply raw RSA to one 256-byte core so the beta recovers it byte-for-byte.

    This wire format has no PKCS padding. Its own fixed HMAC is supplied by
    the caller before signing. A core >= the modulus cannot recover exactly
    and is rejected; using a zero final byte keeps a 256-byte core in range.
    The 36-byte peer/channel trailer must be appended by the caller afterward.
    """
    if not isinstance(state_core, (bytes, bytearray, memoryview)) or len(state_core) != STATE_CORE_SIZE:
        raise ValueError("beta state core must contain exactly 256 bytes")
    core = bytes(state_core)
    numbers = _validated_key(private_key).private_numbers()
    message = int.from_bytes(core, "little")
    modulus = numbers.public_numbers.n
    if message >= modulus:
        raise ValueError("beta state core integer must be smaller than the local RSA modulus")
    signature = pow(message, numbers.d, modulus)
    recovered = pow(signature, numbers.public_numbers.e, modulus).to_bytes(STATE_CORE_SIZE, "little")
    if recovered != core:
        raise ValueError("local RSA state recovery failed")
    return signature.to_bytes(STATE_CORE_SIZE, "little")
