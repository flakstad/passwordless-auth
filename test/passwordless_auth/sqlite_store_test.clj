(ns passwordless-auth.sqlite-store-test
  (:require
   [passwordless-auth.conformance :as conformance]
   [passwordless-auth.examples.sqlite-store :as sqlite-store]
   [clojure.test :refer [deftest is]]
   [next.jdbc :as jdbc])
  (:import
   (java.nio.file Files Path)
   (java.nio.file.attribute FileAttribute)))

(defn- with-sqlite-store [f]
  (let [^Path path (Files/createTempFile "passwordless-auth-" ".sqlite"
                                         (make-array FileAttribute 0))
        datasource (jdbc/get-datasource
                    {:jdbcUrl (str "jdbc:sqlite:" path
                                   "?busy_timeout=30000&journal_mode=WAL")})]
    (try
      (sqlite-store/create-schema! datasource)
      (f (sqlite-store/sqlite-store datasource))
      (finally
        (Files/deleteIfExists path)))))

(deftest sqlite-pattern-obeys-challenge-contract
  (with-sqlite-store
    (fn [auth-store]
      (is (true? (conformance/assert-challenge-store auth-store))))))

(deftest sqlite-pattern-obeys-session-contract
  (with-sqlite-store
    (fn [auth-store]
      (is (true? (conformance/assert-session-store auth-store))))))
