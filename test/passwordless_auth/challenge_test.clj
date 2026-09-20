(ns passwordless-auth.challenge-test
  (:require [passwordless-auth.challenge :as challenge]
            [clojure.test :refer [deftest is]])
  (:import (java.time Clock Duration Instant ZoneOffset)))

(def now (Instant/parse "2026-09-18T10:00:00Z"))
(def fixed-clock (Clock/fixed now ZoneOffset/UTC))
(def code-key "a-test-only-otp-pepper-that-is-long")

(deftest issues-magic-link-without-plaintext-in-record
  (let [{:keys [record proof]}
        (challenge/issue {:method :magic-link :identity "CaseSensitiveIdentity"
                          :clock fixed-clock :metadata {:intent :sign-in}})]
    (is (= :magic-link (:method record)))
    (is (= "CaseSensitiveIdentity" (:identity record)))
    (is (= now (:created-at record)))
    (is (= (.plus now (Duration/ofMinutes 15)) (:expires-at record)))
    (is (= 1 (:max-attempts record)))
    (is (not (.contains (pr-str record) proof)))
    (is (= {:method :magic-link :proof-hash (:proof-hash record)}
           (challenge/selector {:method :magic-link :proof proof})))))

(deftest issues-and-verifies-code
  (let [{:keys [record proof]}
        (challenge/issue {:method :code :identity {:id 42} :now now :hash-key code-key})
        verified (challenge/verify record {:method :code :proof proof
                                           :hash-key code-key :now now})]
    (is (re-matches #"[0-9]{6}" proof))
    (is (= 5 (:max-attempts record)))
    (is (= :verified (:status verified)))
    (is (nil? (:proof-hash verified)))
    (is (nil? (:proof verified)))
    (is (= now (get-in verified [:transition :consumed-at])))
    (is (= :consumed
           (:status (challenge/verify (challenge/apply-transition record verified)
                                      {:method :code :proof proof
                                       :hash-key code-key :now now}))))))

(deftest rejects-code-without-hmac-key
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"require a :hash-key"
                        (challenge/issue {:method :code :identity "id" :now now})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"at least 32 bytes"
                        (challenge/issue {:method :code :identity "id" :now now
                                          :hash-key "short"}))))

(deftest verification-failures-have-stable-statuses
  (let [{:keys [record proof]}
        (challenge/issue {:method :magic-link :identity "id" :now now
                          :ttl (Duration/ofSeconds 30)})]
    (is (= :invalid-proof
           (:status (challenge/verify record {:method :magic-link :proof "wrong" :now now}))))
    (is (= :invalid-proof
           (:status (challenge/verify record {:method :code :proof proof :now now}))))
    (is (= :expired
           (:status (challenge/verify record {:method :magic-link :proof proof
                                              :now (:expires-at record)}))))
    (is (= :consumed
           (:status (challenge/verify (assoc record :consumed-at now)
                                      {:method :magic-link :proof proof :now now}))))))

(deftest code-attempt-transition-locks-on-final-failure
  (let [{:keys [record proof]}
        (challenge/issue {:method :code :identity "id" :now now
                          :hash-key code-key :max-attempts 2})
        first-result (challenge/verify record {:method :code :proof "000000"
                                               :hash-key code-key :now now})
        once-failed (challenge/apply-transition record first-result)
        final-result (challenge/verify once-failed {:method :code :proof "000000"
                                                    :hash-key code-key :now now})
        exhausted (challenge/apply-transition once-failed final-result)]
    (is (= :invalid-proof (:status first-result)))
    (is (= 1 (:failed-attempt-count once-failed)))
    (is (= :attempts-exhausted (:status final-result)))
    (is (= 2 (:failed-attempt-count exhausted)))
    (is (= :attempts-exhausted
           (:status (challenge/verify exhausted {:method :code :proof proof
                                                 :hash-key code-key :now now}))))))
