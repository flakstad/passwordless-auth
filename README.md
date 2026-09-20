# passwordless-auth

`passwordless-auth` 0.3.0 is a small, storage-agnostic Clojure library for
passwordless authentication:

```text
identity → challenge → proof → verification → session
```

It supports high-entropy magic-link proofs and numeric one-time codes without
owning users, authorization, routes, email, UI, or a database. Its API is plain
functions over plain maps. Clojure and the JDK are its only dependencies.

Version 0.x is a pilot API. Pin consumers to a full Git commit, not a branch:

```clojure
{:deps
 {io.github.flakstad/passwordless-auth
  {:git/url "https://github.com/flakstad/passwordless-auth.git"
   :git/sha "<full-40-character-sha>"}}}
```

During coordinated development, override that coordinate with `:local/root`
from the command line or an uncommitted developer alias.

## Magic-link flow

```clojure
(require '[passwordless-auth.challenge :as challenge]
         '[passwordless-auth.session :as session]
         '[passwordless-auth.ring :as auth-ring]
         '[passwordless-auth.store :as store])

(defn issue-magic-link!
  [auth-store {:keys [account-id email public-url send-login-link!]}]
  (let [{:keys [record proof]}
        (challenge/issue {:method :magic-link
                          :identity {:account-id account-id}
                          :ttl (java.time.Duration/ofMinutes 15)
                          :metadata {:return-path "/konto"}})]
    (store/insert-challenge! auth-store record)
    ;; The application constructs and sends its own URL/email.
    (send-login-link! email (str public-url "/auth/verify?token=" proof))))

(defn verify-magic-link!
  [auth-store {:keys [token now]}]
  ;; The store performs lookup + decision + transition under one lock/CAS.
  (let [result (store/verify-challenge!
                auth-store
                {:selector (challenge/selector {:method :magic-link
                                                 :proof token})
                 :method :magic-link
                 :proof token
                 :now now})]
    (when (= :verified (:status result))
      (let [{:keys [record credential]}
            (session/issue {:subject (get-in result [:challenge :identity])
                            :now now
                            :ttl (java.time.Duration/ofHours 12)})]
        (store/insert-session! auth-store record)
        {:set-cookie
         (auth-ring/session-cookie {:name "__Host-example_session"
                                    :value credential
                                    :max-age 43200})}))))
```

The returned proof/credential is the only plaintext copy. Persist only the
record. A verified result contains a sanitized challenge and no proof hash.

## One-time-code flow

```clojure
(require '[passwordless-auth.challenge :as challenge]
         '[passwordless-auth.store :as store])

(defn issue-code!
  [auth-store {:keys [identity destination otp-hmac-key send-code!]}]
  (let [{:keys [record proof]}
        (challenge/issue {:method :code
                          :identity identity
                          :hash-key otp-hmac-key})]
    (store/insert-challenge! auth-store record)
    (send-code! destination proof)
    {:challenge-id (:id record)}))

(defn verify-code!
  [auth-store {:keys [challenge-id submitted-code otp-hmac-key now]}]
  (store/verify-challenge!
   auth-store
   {:selector (challenge/selector {:method :code :id challenge-id})
    :method :code
    :proof submitted-code
    :hash-key otp-hmac-key
    :now now}))
```

Codes default to six numeric digits, ten minutes, and five attempts. Code
hashes require an application-held HMAC key. The adapter must update failed
attempts under the same lock/CAS used for successful consumption.

## Sessions

```clojure
(require '[passwordless-auth.session :as session]
         '[passwordless-auth.store :as store])

(defn authenticated-subject
  [auth-store cookie-value now]
  (let [stored (store/find-session
                auth-store
                (session/credential-hash-candidates cookie-value))
        result (session/check stored {:now now})]
    (case (:status result)
      :active          (get-in result [:session :subject])
      :invalid-session nil
      :expired-session nil
      :revoked-session nil)))
```

`credential-hash-candidates` includes the 0.1 versioned digest and the legacy
64-character SHA-256 hex digest used by initial Radar consumers.

## Store conformance

An application implements the seven methods in `passwordless-auth.store/AuthStore`.
Normal application code and the conformance suite call the same protocol:

```clojure
(require '[passwordless-auth.conformance :as auth-test]
         '[your-app.auth-store :as auth-store])

(defn assert-auth-store-conformance!
  [db identity subject]
  (let [store (auth-store/postgres-store db)]
    (auth-test/assert-challenge-store store {:identity identity})
    (auth-test/assert-session-store store {:subject subject})))
```

See [DESIGN.md](DESIGN.md) for the exact operation contract and
[SECURITY.md](SECURITY.md) for the threat model. Complete, tested
copy-and-adjust implementations for [PostgreSQL and SQLite](examples/README.md)
include schema, row conversion, atomic verification, and transaction patterns.

## Public namespaces

- `passwordless-auth.secret` — generated credentials, versioned hashes, compatibility hashes.
- `passwordless-auth.challenge` — issue, select, verify, and apply explicit transitions.
- `passwordless-auth.session` — issue and classify persisted sessions.
- `passwordless-auth.store` — the explicit seven-operation persistence protocol.
- `passwordless-auth.policy` — a small issuance-count decision primitive.
- `passwordless-auth.ring` — Set-Cookie values and conservative local return paths.
- `passwordless-auth.conformance` — reusable AuthStore assertions.

Run the suite with `clojure -M:test`.
