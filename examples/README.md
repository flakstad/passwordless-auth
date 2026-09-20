# Database patterns

These are complete, tested starting points for implementing
`passwordless-auth.store/AuthStore`. They are application code, not database dependencies
of Passwordless Auth:

- [`passwordless-auth.examples.postgres-store`](passwordless_auth/examples/postgres_store.clj) uses a
  PostgreSQL transaction and `SELECT ... FOR UPDATE`.
- [`passwordless-auth.examples.sqlite-store`](passwordless_auth/examples/sqlite_store.clj) uses guarded
  compare-and-set updates because SQLite has no row-level `FOR UPDATE` lock.

Copy the relevant namespace into the application and adjust it. Do not depend
on the `passwordless-auth.examples.*` namespace from production code: examples may improve
without the compatibility guarantees of the core API.

## Dependencies

Both patterns use `next.jdbc`. Add the matching JDBC driver to the consuming
application:

```clojure
com.github.seancorfield/next.jdbc {:mvn/version "1.3.1070"}

;; PostgreSQL
org.postgresql/postgresql {:mvn/version "42.7.7"}

;; or SQLite
org.xerial/sqlite-jdbc {:mvn/version "3.50.3.0"}
```

The version numbers are known-good examples, not Passwordless Auth constraints.

## PostgreSQL

Copy `postgres_store.clj`, change its namespace, and run the three statements
in `schema-statements` through the application's migration system. Construct a
store around the datasource:

```clojure
(require '[passwordless-auth.store :as store]
         '[your-app.postgres-auth-store :as postgres-auth-store])

(defn consume! [datasource request]
  (store/verify-challenge!
   (postgres-auth-store/postgres-store datasource)
   request))
```

When authentication and application changes must share one transaction, keep
transaction ownership in the application and construct the transaction-bound
variant:

```clojure
(require '[passwordless-auth.store :as store]
         '[next.jdbc :as jdbc]
         '[your-app.postgres-auth-store :as postgres-auth-store])

(defn consume-and-create-session! [datasource request session-record]
  (jdbc/with-transaction [tx datasource]
    (let [auth-store (postgres-auth-store/transaction-store tx)
          result (store/verify-challenge! auth-store request)]
      (when (= :verified (:status result))
        (store/insert-session! auth-store session-record))
      result)))
```

The example uses a row lock and guarded update. Removing either without an
equivalent guarantee can make one challenge succeed twice.

## SQLite

Copy `sqlite_store.clj`, change its namespace, and add the statements in
`schema-statements` to the application's migrations:

```clojure
(require '[passwordless-auth.store :as store]
         '[your-app.sqlite-auth-store :as sqlite-auth-store])

(defn consume! [datasource request]
  (store/verify-challenge!
   (sqlite-auth-store/sqlite-store datasource)
   request))
```

Use a file-backed database for concurrent conformance tests. Configure a busy
timeout and, for web applications, WAL mode in the datasource URL or connection
setup. For example:

```clojure
(defn sqlite-options [database-path]
  {:jdbcUrl (str "jdbc:sqlite:" database-path
                 "?busy_timeout=30000&journal_mode=WAL")})
```

The SQLite verification loop reloads after a lost guarded update. It must
return the result only after its transition wins, otherwise two callers could
both observe `:verified`.

## Required application adjustments

The examples deliberately isolate the parts that normally change:

1. Replace `identity_edn`, `subject_edn`, and `metadata_edn` with the
   application's foreign keys or serialization format. `clojure.edn/read-string`
   is safe for EDN, but the example codec only round-trips EDN values.
2. Move `schema-statements` into the application's migration system.
3. Rename tables and columns to fit existing data rather than duplicating it.
4. Keep proof and credential columns hashed. Never add plaintext columns.
5. Preserve the atomic implementation of `verify-challenge!`.
6. Implement issuance-count queries and locking beside the application's rate
   limit keys; these are intentionally not part of `AuthStore`.
7. Run both Passwordless Auth conformance functions against the real database adapter.

## Conformance test

```clojure
(require '[passwordless-auth.conformance :as conformance]
         '[your-app.auth-store :as auth-store])

(defn assert-store! [datasource identity subject]
  (let [store (auth-store/postgres-store datasource)]
    (conformance/assert-challenge-store store {:identity identity})
    (conformance/assert-session-store store {:subject subject})))
```

Supply `:identity` and `:subject` when the schema has foreign keys. Otherwise
the conformance suite creates opaque EDN fixtures itself.
