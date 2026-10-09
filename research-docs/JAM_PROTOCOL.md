# Beta JAM handshake, cipher and framing

This is the showcase's implemented build-24919 handshake. It follows the beta
receiver behavior where it differs from later builds. A valid wire layout does
not establish every trailer field's meaning or recover the original server's
complete protocol policy.

Implementation: [server.py](../ow08/server.py),
[protocol.py](../ow08/protocol.py), [cipher.py](../ow08/cipher.py), and
[local_rsa.py](../ow08/local_rsa.py).

## Handshake and directional keys

1. Exchange `HELLO PRO CLIENT\0` and `HELLO PRO SERVER\0`.
2. Client sends `u64 little-endian cid; client_nonce[32]`. Server returns
   `challenge[32]; difficulty byte 0; server_nonce[32]`.
3. Client sends an eight-byte proof prefix followed by `MAC1[32]`.
4. Verify MAC1, then send plaintext `MAC2[32]` followed by the JAM-encrypted
   292-byte state.

Derive these values with HMAC-SHA256, using each corresponding **64-byte
referral key** from [authenticated bootstrap](BOOTSTRAP_AND_AUTH.md):

| Referral key | Derived value | HMAC message |
| --- | --- | --- |
| `k0` | MAC1 | client nonce then server nonce |
| `k1` | MAC2 | server nonce then client nonce |
| `k2` | Server-to-client JAM key | client nonce then server nonce |
| `k3` | Client-to-server JAM key | server nonce then client nonce |

Project-account admission uses the account-bound referral keys and consumes the admission
after successful proof.

## Signed state block

The encrypted state is:

```text
raw RSA block[256]; peer ID[16]; channel ID[16]; u32 (4 bytes)
```

The beta always RSA-transforms the first 256 bytes. The later-build
last-byte-`FF`/out-of-range shortcut does not bypass RSA here. The recovered
core begins `01; IPv4 bytes[4]; u16 little-endian port`. Beta address tags are
**1 IPv4, 2 IPv6, 3 hostname**.

HMAC-SHA256 covers `core[0:176] || core[208:256]`; store the result at
`core[176:208]`. Its fixed 64-byte key is the concatenation of these lines:

```text
3586f3628a631b705712405b8acc71d40fd1670cc1b03ea384974a6fb1a76196
b142f0b72310ea8116d00a4c352f09acdbfb50a63ec5153e62e4d67fe09beecc
```

Sign the core as the unpadded little-endian integer:

```python
pow(int.from_bytes(core, "little"), private_exponent, modulus)
```

Serialize the result to 256 little-endian bytes. Keep the final decoded core
byte zero so its value remains below the generated RSA-2048 modulus. The
36-byte trailer stays outside RSA and inside JAM. Both state builders encode
the peer/channel trailer directly from its field layout; its full identity
semantics remain partly unknown.

The decoded endpoint must agree with the client's connection: the beta accepts
a matching address or matching port. Remote launchers therefore advertise their
actual local lobby endpoint. The generated public modulus is temporarily
prepared through the [client restoration gates](CLIENT_PREPARATION.md).

## Cipher continuity and frame routing

Keep **one continuous PANAMA/JAM cipher per direction** across the state,
frame length headers and payloads. Resetting it per frame breaks the stream.
Framed plaintext is:

```text
u24 big-endian payload length; u8 family index; u8 message offset; body
```

TCP reads may split or combine frames. The client announces its own family map:

```text
00 00; u32 little-endian count; u32 little-endian family CRCs[count]
```

Index 1 names the first CRC; index 0 is control. Resolve every recipient's
own map instead of assuming a fixed family order. After client-byte
restoration, send Base ACK `00 02`. Answer Base keepalive `00 03` with `00 03`.

## Message encoding

Beta bodies use little-endian scalars, NUL-terminated UTF-8 strings, and arrays
encoded as `u32 element count; elements in descriptor order`. Omit C++ memory
padding. `id16` in these notes means two consecutive u64 values.

**Consecutive booleans share bits starting at bit 0, including across nested
structs.** A non-boolean value or array count resets the bit cursor. Native
memory offsets and descriptor wire order are different kinds of evidence;
do not serialize native struct padding.

[Menu initialization](MENU_INITIALIZATION.md),
[social protocol](SOCIAL_PROTOCOL.md), and
[packet research](PACKET_RESEARCH.md) use these encoding rules.
The PANAMA implementation follows the [MULTI-S01 specification, section 2.3.2](https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/11_02espec.pdf).
JAM mapping, state and framing research are credited in
[Sources and licensing](SOURCES_AND_LICENSE.md).
