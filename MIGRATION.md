# Migration guidance

## General stateful magic-link migration

1. Characterize current TTL boundaries, one-time behavior, cookies, logout,
   account policy, redirects, and public responses.
2. Add the challenge/session lifecycle columns needed by the adapter. Keep the
   application's account foreign keys and domain metadata.
3. Widen legacy `char(64)` hash columns before writing versioned hashes.
4. Implement and run both conformance assertions against the real database.
5. Replace generation/hashing/state decisions while keeping routes, email,
   domain transactions, authorization, and post-login behavior local.
6. Pin the exact library Git SHA. Use a temporary local override only for
   coordinated testing.
7. Decide separately whether outstanding challenges or active sessions need a
   compatibility read path.

Invalidating outstanding 15-minute login challenges is usually a reasonable,
documented rollout choice. Active sessions have much greater user impact:
prefer `session/credential-hash-candidates`, which reads both versioned 0.1
hashes and legacy SHA-256 hex while all new sessions write only the new format.

## Byggeradar pilot

Byggeradar creates/normalizes accounts locally, stores pending-watch intent on
the server, uses 15-minute one-time links, 12-hour hashed sessions,
`__Host-`/Strict cookies in production, and rejects cross-origin unsafe
requests. Preserve all of those domain and route behaviors.

Its adapter should map `identity`/`subject` to `account_id`, and keep the
pending-watch hash as application metadata. Verification and session creation
remain in the same application transaction so a consumed link never succeeds
without a session record. The migration may invalidate outstanding legacy
links; active legacy sessions should remain readable. Add identity and client
issuance counts without changing email/account semantics.

The completed pilot kept both forms of legacy state readable: the adapter
queries the versioned and legacy SHA-256 digest for outstanding links and
sessions. New rows write only versioned hashes. Logout now records revocation,
and rate-limited issuance returns the existing generic success page without
sending mail. See Byggeradar's `docs/passwordless-auth-migration.md` for its exact
schema and rollout notes.

## Pilot API review

The first relational store exposed one necessary testing seam: conformance
cannot invent an identity when the challenge/session tables enforce an account
foreign key. Tests therefore pass `{:identity value}` and `{:subject value}`
options to the conformance functions. This is test data, not a runtime domain
hook.

No application-specific runtime escape hatch was needed. Byggeradar constructs
its `AuthStore` around an open transaction so challenge consumption and session
insert share its existing transaction; that is an implementation of the same
contract, not a broader core API. JDBC `Timestamp`/`Instant` conversion also
stays in the store implementation.

The persistence contract proved appropriately narrow: verification is the only
challenge state transition operation, while application tables and email
association remain outside. The Ring namespace remains limited to cookie and
return-path values. OTP used the same real PostgreSQL adapter and conformance
suite naturally, although Byggeradar exposes no OTP route or UI.

## Fiskeriradar follow-up (do not implement in this pilot)

Current implementation: `src/fiskeriradar/auth.clj` uses PostgreSQL/next.jdbc,
15-minute SHA-256 magic links, atomic conditional consumption, 30-day hashed
sessions, five links per account per hour, strict host cookies, unsafe-origin
checks, pruning, and auth statistics. Its tables originate in
`resources/migrations/005-monitoring.sql`.

Plan:

1. Widen both `token_hash char(64)` columns and add challenge id/method/attempt
   fields plus session id/revocation fields, preserving accounts and watches.
2. Map account UUIDs to opaque `{:account-id ...}` identity/subject values.
3. Keep the existing advisory transaction lock and five-per-hour identity
   policy; add a durable client-key count/limit. Feed both counts into
   `passwordless-auth.policy/issuance-decision`.
4. Move only token/code/session mechanics to passwordless-auth. Keep normalization,
   account creation, pruning/statistics, routes, pending-watch cookie behavior,
   email copy/transport, and authorization in Fiskeriradar.
5. Preserve the 30-day cookie `Max-Age`, strict cookie naming, same-origin
   defense, and generic invalid/expired/used error copy.
6. Run the conformance suite plus integration coverage for five/hour limiting,
   pruning, pending-watch completion, authenticated routes, logout, and account
   deletion cascades.

Expected deliberate difference: new hashes are versioned and revocation may be
recorded instead of deletion. Legacy active sessions should receive a
compatibility lookup; outstanding old links may be invalidated at rollout.

## Mineralradar follow-up (do not implement in this pilot)

Current implementation: `src/mineralradar/auth.clj` uses PostgreSQL/next.jdbc,
15-minute SHA-256 magic links, 12-hour hashed sessions, a plaintext stored CSRF
token compared in constant time, and a transactional email outbox. Login token
schema is in `013-passwordless-auth.sql`; sessions originate in
`006-monitoring.sql`. There is no observed issuance throttle.

Plan:

1. Widen hash columns and add challenge/session lifecycle columns while
   preserving users, `email_verified_at`, watches, and all outbox rows.
2. Map user UUIDs to opaque `{:user-id ...}` values. Keep user creation and
   email verification updates application-owned.
3. Keep challenge insert and login-email outbox insert in one transaction.
   Keep successful challenge consumption, email verification, and session
   insertion in one transaction.
4. Add durable identity/client issuance counts and the recommended initial
   limits before sending/queueing mail.
5. Retain the current CSRF model initially; passwordless-auth does not absorb it.
   A later change may hash the CSRF token at rest using `passwordless-auth.secret`, but that
   is separate from this migration.
6. Run conformance plus handler/outbox tests for delivery triggering,
   verification, CSRF-protected actions, logout, account deletion, and admin
   authorization.

Legacy active sessions should receive a compatibility lookup. Outstanding old
links may be invalidated with a documented rollout window.

## Kari: replayable stateless links

Kari's encrypted five-minute JWE proves claims but has no persisted challenge
identifier, so the same link can create multiple sessions until expiry. A later
migration must add a durable challenge store and consume it before the existing
account/passkey/trusted-device plan runs. JWE claims may temporarily identify a
stored challenge, but encryption alone is not one-time use. Normalize public
known/unknown-user responses at the same time. Do not move passkeys, trusted
devices, account creation, or the 60-day Ring/SQLite session model into this
library.

## Støtteradar: plaintext session credentials

Støtteradar hashes login tokens but stores the browser session id itself as the
`user_sessions` primary key. A later migration should add a separate public
session UUID and `credential_hash`, write only versioned hashes, and optionally
retain `revoked_at`. Existing plaintext sessions cannot be safely transformed
without knowing whether the DB value is also the live cookie credential:
support a short, explicit compatibility lookup or invalidate them after an
impact decision. Keep user/watch semantics and the synchronizer CSRF token
local; consider hashing CSRF at rest as a separate hardening change.

## Adding OTP later

Add no UI merely because the core supports codes. When a consumer needs OTP:
configure an independent HMAC key, persist public challenge ids and attempt
fields, run the concurrency conformance suite, apply identity/client issuance
limits, and return a generic request response. Never email the proof from the
library or reuse a session/cookie secret as the code HMAC key.
