# Bootstrap and authenticated lobby admission

The native client first authenticates through Battle.net-style RPC and its
embedded web form. A successful form submission is only one step: a
challenge-bound ticket, referral keys and verified JAM proof bind the later
lobby connection to the same project account.

Implementation: [bootstrap.py](../ow08/bootstrap.py),
[accounts.py](../ow08/accounts.py), and
[split_launch.py](../ow08/split_launch.py).

## RPC framing and service binding

The TLS RPC stream uses bounded protobuf messages:

```text
u16 big-endian header length; protobuf header; body
```

Header fields are 1 service ID, 2 method, 3 request token, 5 body size,
6 status, and optional 11 service hash (`fixed32`). Responses use service
ID **254** and retain the request token. Imported service IDs and exported
listener IDs are bound per connection; they are not request tokens.

| Service hash (decimal) | Role / methods used |
| --- | --- |
| `1698982289` | Connection: Connect 1, Bind 2, Echo 3, KeepAlive 5, Disconnect 7 |
| `233634817` | Authentication: Logon 1, SelectGameAccount 4/6, VerifyWebCredentials 7, GenerateWebCredentials 8 |
| `3151632159` | ChallengeNotify: OnExternalChallenge 3 |
| `1898188341` | AuthenticationClient: OnLogonComplete 5 |
| `1069623117` | GameUtilities: ProcessClientRequest 1 |

## From web challenge to account ownership

1. Logon supplies a `web_auth_url` challenge. The native HTTP form receives
   its unique challenge through the query/cookie path.
2. The form validates project credentials and returns a challenge-bound,
   single-use ticket. VerifyWebCredentials consumes it.
3. OnLogonComplete supplies the account, game account, alias and BattleTag.
4. GameUtilities returns `response_type=ReferralInfo`, `cid`,
   `hostv4=address:port`, and four 64-byte key attributes `k0..k3`.
5. The admission store binds the referral `cid` and keys to the authenticated
   account. Successful [JAM proof](JAM_PROTOCOL.md) consumes that admission
   and transfers exclusive account ownership to the lobby session.

A claimed identity or peer IP alone cannot authorize a lobby session.
Synthetic players use the same exclusive ownership rule as native clients.
Challenges, tickets, referrals and online leases are transient; project account
and social data persist locally. Passwords are salted PBKDF2-HMAC-SHA256
hashes. Email-shaped project aliases identify local accounts and do not
contact a mail service or Battle.net.

## Endpoints and surrounding flow

Bootstrap, web login and lobby services stay on loopback. Remote launchers
create local endpoints for the game's connections and carry their streams
through a TLS gateway pinned to the server certificate. The decoded lobby
state advertises the launcher's actual local endpoint. Full endpoint and
transport details are in [Network and storage](NETWORK_AND_STORAGE.md).
These routes describe the showcase, not the original 2015 server topology.

[Client preparation](CLIENT_PREPARATION.md) explains how the owned client
temporarily accepts the local service and RSA key.
[JAM state construction](JAM_PROTOCOL.md#signed-state-block) explains how
the authenticated referral is used for lobby admission.
[Sources and licensing](SOURCES_AND_LICENSE.md) lists the public references
for these service hashes and ticket semantics.
