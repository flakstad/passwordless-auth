# Design

## Boundary

The reusable boundary is credential mechanics, not “magic links”:

```text
application identity
  → passwordless challenge
  → proof (:magic-link or :code)
  → atomic verification
  → application-created session
```

Issuance and state classification are pure except for secure randomness and an
explicit/default clock. Persistence operations remain visible. Email and public
URL construction remain application effects. Authorization is performed after
authentication by the application.

No event sink is built in. Stable result maps (`:verified`, `:invalid-proof`,
`:expired`, and so on) are sufficient inputs for application-owned logging and
avoid imposing event storage or sensitive metadata policy.

## Challenge model

```clojure
{:id                   #uuid "..."
 :identity             <opaque application value>
 :method               :magic-link | :code
 :proof-hash           "v1:sha256:..." | "v1:hmac-sha256:..."
 :created-at           java.time.Instant
 :expires-at           java.time.Instant
 :consumed-at          java.time.Instant | nil
 :failed-attempt-count 0
 :max-attempts         1 | 5
 :metadata             {<opaque application data>}}
```

All fields are required in the logical model. SQL schemas may represent the
opaque identity differently. Method is checked during verification, so a code
endpoint cannot consume a magic-link challenge. Identity is never normalized.

`challenge/verify` returns a status, a sanitized challenge on success, and at
most one explicit transition. Expected statuses are:

- `:verified`
- `:invalid-proof`
- `:expired`
- `:consumed`
- `:attempts-exhausted`

Applications may deliberately collapse these to one generic public failure.

## Session model

```clojure
{:id              #uuid "..."
 :subject         <opaque application value>
 :credential-hash "v1:sha256:..."
 :created-at      java.time.Instant
 :expires-at      java.time.Instant
 :revoked-at      java.time.Instant | nil
 :metadata        {<opaque application data>}}
```

The subject is a reference, not a principal with roles. `session/check` returns
`:active`, `:invalid-session`, `:expired-session`, or `:revoked-session` and
never returns the credential hash in its public session.

## Persistence contract

Persistence implementations satisfy the explicit `passwordless-auth.store/AuthStore`
protocol. One store value implements seven invariant-oriented operations; the
contract is not a generic CRUD abstraction.

Challenge operations:

```clojure
(insert-challenge! [store challenge])
(load-challenge [store challenge-id])
(verify-challenge! [store {:keys [selector method proof now hash-key]}])
```

Insertion returns the stored challenge. Loading returns the complete persisted
record or `nil`. Verification returns a `passwordless-auth.challenge/verify` result.

`verify-challenge!` must atomically:

1. select the current row using `selector`;
2. lock it or establish an equivalent compare-and-set guard;
3. call `passwordless-auth.challenge/verify` with the current record;
4. apply `passwordless-auth.challenge/apply-transition`;
5. persist that transition and return the original result.

It must not commit a transition if its guard no longer matches. A PostgreSQL
`SELECT ... FOR UPDATE` transaction, a conditional `UPDATE ... RETURNING`, or a
correct single-value CAS are suitable. A separate unguarded read and update is
not. Missing selectors return `{:status :invalid-proof}`.

Session operations:

```clojure
(insert-session! [store session])
(find-session [store credential-hash-candidates])
(load-session [store session-id])
(revoke-session! [store session-id revoked-at])
```

Insertion returns the stored session. Both lookup operations return a complete
persisted record or `nil`. Revocation returns `true` when the session exists,
including an already-revoked session, and `false` when it does not.

`find-session` returns the persisted record even if expired/revoked so
`session/check` can classify it. `revoke-session!` must make revocation visible
to subsequent lookups before it returns. The record is retained so later
lookups can distinguish `:revoked-session` from `:invalid-session`.

The load operations are included because code verification and conformance
need current state; they are not an invitation to build generic CRUD.

The protocol does not own connections or transactions. A store may wrap a
datasource and open the atomic verification transaction itself, or wrap an
existing transaction when authentication and application changes must commit
together. The PostgreSQL example demonstrates both forms. This keeps
transaction ownership visible without weakening the persistence contract.

`passwordless-auth.conformance/assert-challenge-store` races two consumers, checks exact
expiry, proof-at-rest, code attempts/lockout, success consumption, and replay.
`assert-session-store` checks hash-at-rest, invalid/active/expired status and
revocation visibility. Stores backed by foreign keys pass `{:identity value}`
and `{:subject value}` options created by their test fixture; otherwise the
suite generates opaque defaults.

Complete copy-and-adjust patterns live under `examples/`: PostgreSQL uses a
transaction plus `SELECT ... FOR UPDATE`, while SQLite uses guarded updates and
retries a lost compare-and-set. The examples are tested, but remain application
templates so Passwordless Auth itself does not acquire JDBC or database-driver dependencies.

## Time and errors

Public constructors/classifiers accept `:now` (`Instant`) or `:clock` (`Clock`).
Supplying neither uses `Clock/systemUTC`. Persistence adapters receive the same
instant and must not substitute database time inside an atomic decision.

Expected authentication failures are values rather than exceptions. Invalid
configuration and programmer errors throw `ExceptionInfo`.

## Issuance boundary

The chosen boundary combines durable consumer counts with a pure core decision.
Adapters/applications expose recent counts by identity and client key;
`passwordless-auth.policy/issuance-decision` compares them with explicit limits. The
consumer owns transaction isolation, response policy, and key derivation. A
callback-based generic rate limiter was rejected because it would hide storage
and distributed consistency without actually solving either.

## Dependencies and extension policy

Core uses only Clojure and JDK crypto/time. `passwordless-auth.ring` emits header values but
does not depend on Ring. New proof methods should be added only when at least
one real consumer demonstrates distinct generation/verification semantics.
Application-specific metadata remains opaque rather than becoming callbacks or
domain branches.
