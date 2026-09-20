# Security model

## Threat model

The library defends generated browser credentials against guessing, database
credential disclosure where practical, replay, stale use, and open redirects.
It assumes the application protects its HMAC keys, uses TLS, performs correct
identity/account decisions, and supplies an adapter with the documented atomic
semantics. It does not make a compromised application process trustworthy.

## Proofs and hashing

Magic-link and session credentials contain 32 random bytes (256 bits) generated
by `SecureRandom` and encoded without Base64 padding. Their versioned SHA-256
digests are safe lookup keys because the generated source has enough entropy;
slow password hashing adds cost without addressing a password-like threat.

Codes are different. The six-digit default has one million values, so an
unkeyed database digest would be cheaply reversible offline. Code issuance
therefore requires an application-held HMAC-SHA-256 key. Use an independently
generated secret of at least 32 random bytes, keep it outside the database, and
plan key rotation as an application deployment concern. A short expiry, five
attempts, and issuance throttling remain required because HMAC does not stop
online guessing.

Hash strings carry an explicit `v1:sha256:` or `v1:hmac-sha256:` prefix.
`passwordless-auth.secret/matches?` uses `MessageDigest/isEqual` for in-process digest
comparison. High-entropy magic-link/session verification should normally hash
then query by equality, avoiding plaintext comparison entirely.

Plaintext proofs and session credentials appear only in the issuance return
value. Normal records, verification results, and public session/challenge maps
omit them. Metadata must never contain a copy of a proof.

## Expiry, attempts, and replay

Expiry is exclusive: at `now == expires-at`, a challenge or session is expired.
A challenge succeeds only once. The adapter must lock or compare-and-set the
current row, run `challenge/verify`, and apply its transition as one atomic
operation. Two concurrent requests must not both observe `:verified`.

Wrong code attempts increment atomically. The attempt that reaches the maximum
returns `:attempts-exhausted`, and even the correct code cannot succeed later.
Wrong magic-link values normally do not locate a row and are not counted.

Sessions are server-side records with independent credentials, expiry, and
revocation state. Logout revokes or deletes the server record and clears the
cookie. Applications must still re-check any account, role, organization, or
membership policy required by their domain.

## Issuance and enumeration

`passwordless-auth.policy/issuance-decision` consumes counts supplied from durable storage.
The recommended starting limits are five challenges per normalized identity and
twenty per client key in a rolling hour. Applications choose trusted client
keys, perform race-safe counting/insert decisions, and may use stricter limits.
This is deliberately not a distributed rate limiter.

Public login-request responses should not reveal whether an account exists.
Rate-limit and delivery details should normally map to the same generic response.
Identity normalization is application-owned: the core never lowercases an
opaque identity.

## Cookies

`passwordless-auth.ring/session-cookie` defaults to `Secure`, `HttpOnly`, `SameSite=Strict`,
and `Path=/`. The default name is `__Host-session`. A `__Host-` name is rejected
if `Secure` or `Path=/` is removed. `SameSite=None` is rejected without Secure.
Local HTTP development must deliberately choose a non-`__Host-` name and set
`:secure? false`.

The helper creates a Set-Cookie value; it does not parse cookies or add Ring
middleware. Clearing uses both `Max-Age=0` and a past `Expires` value with the
same policy attributes.

## Return paths

`safe-return-path` accepts only a non-empty path beginning with exactly one
forward slash. It rejects absolute/protocol-relative URLs, backslashes, control
characters, and encoded slash/backslash/control/double-encoding markers. Query
strings and fragments on a valid local path are allowed. This is intentionally
conservative and is not a general URL sanitizer.

## CSRF and login CSRF

General CSRF stays outside this library. The audited applications legitimately
use different defenses: Byggeradar and Fiskeriradar reject cross-origin unsafe
requests; Mineralradar and Støtteradar use synchronizer tokens; Fangst hashes a
separate CSRF credential. Those choices depend on the whole application, not
the authentication value model.

Login-request POST endpoints should receive the application's normal
same-origin/CSRF protection and a generic response. A GET magic-link verifier
is a bearer-proof endpoint: make it single-use, short-lived, and return
`Referrer-Policy: no-referrer`. Do not perform application-changing work from a
user-supplied return path. If a product supports account switching or linking,
evaluate login-CSRF explicitly rather than assuming SameSite alone handles it.

## Explicit non-goals

The library does not provide authorization, password hashing, passkeys, OAuth,
email, account lookup/signup policy, database schema, general CSRF middleware,
generic rate limiting, audit storage, or application lifecycle management.
Applications should log security events from stable result statuses without
including proofs or session credentials.
