(ns passwordless-auth.postgres-store-test
  (:require
   [passwordless-auth.conformance :as conformance]
   [passwordless-auth.examples.postgres-store :as postgres-store]
   [clojure.test :refer [deftest is]]
   [next.jdbc :as jdbc]))

(def ^:private test-url
  (System/getenv "PASSWORDLESS_AUTH_TEST_POSTGRES_URL"))

(deftest ^:integration postgres-pattern-obeys-store-contract
  (if-not test-url
    (is true "Set PASSWORDLESS_AUTH_TEST_POSTGRES_URL to run the PostgreSQL pattern test")
    (let [datasource (jdbc/get-datasource {:jdbcUrl test-url})]
      (postgres-store/create-schema! datasource)
      (jdbc/execute! datasource ["TRUNCATE auth_sessions, auth_challenges"])
      (let [auth-store (postgres-store/postgres-store datasource)]
        (is (true? (conformance/assert-challenge-store auth-store)))
        (is (true? (conformance/assert-session-store auth-store)))))))
