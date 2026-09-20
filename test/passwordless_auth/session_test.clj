(ns passwordless-auth.session-test
  (:require [passwordless-auth.session :as session]
            [clojure.test :refer [deftest is]])
  (:import (java.time Duration Instant)))

(def now (Instant/parse "2026-09-18T10:00:00Z"))

(deftest session-lifecycle
  (let [{:keys [record credential]}
        (session/issue {:subject {:account-id 42} :now now
                        :ttl (Duration/ofMinutes 30)})]
    (is (not (.contains (pr-str record) credential)))
    (is (= :active (:status (session/check record {:now now}))))
    (is (= {:account-id 42} (get-in (session/check record {:now now})
                                     [:session :subject])))
    (is (nil? (get-in (session/check record {:now now}) [:session :credential-hash])))
    (is (= :expired-session
           (:status (session/check record {:now (:expires-at record)}))))
    (is (= :revoked-session
           (:status (session/check (assoc record :revoked-at now) {:now now}))))
    (is (= :invalid-session (:status (session/check nil {:now now}))))
    (is (session/active? record {:now now}))))
