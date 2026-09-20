(ns passwordless-auth.conformance
  "Reusable behavioral assertions for application AuthStore implementations.

  These functions intentionally use clojure.test so a consumer can call them
  from its ordinary test suite without copying fixtures."
  (:require
   [passwordless-auth.challenge :as challenge]
   [passwordless-auth.session :as session]
   [passwordless-auth.store :as store]
   [clojure.test :refer [is testing]])
  (:import
   (java.time Duration Instant)
   (java.util UUID)))

(def ^:private code-hash-key
  "passwordless-auth-conformance-only-key-32-bytes")

(defn assert-challenge-store
  "Exercises an AuthStore challenge implementation.

  Options may contain :identity when the store requires an application fixture.

  verify-challenge! must select, decide with passwordless-auth.challenge/verify, and apply
  its transition in one row lock or CAS operation. It returns the verify result."
  ([auth-store]
   (assert-challenge-store auth-store nil))
  ([auth-store {:keys [identity]}]
   (is (satisfies? store/AuthStore auth-store)
       "store satisfies passwordless-auth.store/AuthStore")
   (let [now (Instant/parse "2030-01-01T10:00:00Z")
         identity (or identity
                      {:kind :conformance :id (str (UUID/randomUUID))})]
    (testing "magic links are hashed, expiring, atomic, and one-time"
      (let [{:keys [record proof]}
            (challenge/issue {:method :magic-link
                              :identity identity
                              :now now
                              :ttl (Duration/ofMinutes 15)})
            request {:selector (challenge/selector {:method :magic-link :proof proof})
                     :method :magic-link :proof proof :now (.plusSeconds now 1)}]
        (is (= record (store/insert-challenge! auth-store record))
            "insert-challenge! returns the stored challenge")
        (let [stored (store/load-challenge auth-store (:id record))]
          (is (= (:proof-hash record) (:proof-hash stored)))
          (is (not= proof (:proof-hash stored)))
          (is (not (.contains (pr-str stored) proof))))
        (is (= :invalid-proof
               (:status
                (store/verify-challenge! auth-store
                 {:selector (challenge/selector {:method :magic-link :proof "wrong"})
                  :method :magic-link :proof "wrong" :now (.plusSeconds now 1)}))))
        (let [gate (promise)
              attempts (doall
                        (repeatedly 2
                                    #(future @gate (store/verify-challenge! auth-store request))))]
          (deliver gate true)
          (is (= 1 (count (filter #(= :verified (:status %)) (map deref attempts))))
              "two concurrent verifications have exactly one winner")
          (is (some #{:consumed :invalid-proof}
                    (map :status (map deref attempts)))))))

    (testing "expiry is enforced at the exact boundary"
      (let [{:keys [record proof]}
            (challenge/issue {:method :magic-link :identity identity :now now
                              :ttl (Duration/ofSeconds 1)})]
        (is (= record (store/insert-challenge! auth-store record)))
        (is (= :expired
               (:status
                (store/verify-challenge! auth-store
                 {:selector (challenge/selector {:method :magic-link :proof proof})
                  :method :magic-link :proof proof :now (:expires-at record)}))))))

    (testing "codes count failures atomically and lock at the attempt limit"
      (let [{:keys [record proof]}
            (challenge/issue {:method :code :identity identity :now now
                              :hash-key code-hash-key :max-attempts 5})
            request (fn [submitted]
                      {:selector (challenge/selector {:method :code :id (:id record)})
                       :method :code :proof submitted :hash-key code-hash-key
                       :now (.plusSeconds now 1)})]
        (is (= record (store/insert-challenge! auth-store record)))
        (dotimes [_ 4]
          (is (= :invalid-proof
                 (:status (store/verify-challenge! auth-store (request "000000"))))))
        (is (= :attempts-exhausted
               (:status (store/verify-challenge! auth-store (request "000000")))))
        (is (= 5 (:failed-attempt-count
                  (store/load-challenge auth-store (:id record)))))
        (is (= :attempts-exhausted
               (:status (store/verify-challenge! auth-store (request proof)))))
        (is (nil? (:consumed-at
                   (store/load-challenge auth-store (:id record)))))))

    (testing "a successful code is consumed and cannot replay"
      (let [{:keys [record proof]}
            (challenge/issue {:method :code :identity identity :now now
                              :hash-key code-hash-key})
            request {:selector (challenge/selector {:method :code :id (:id record)})
                     :method :code :proof proof :hash-key code-hash-key
                     :now (.plusSeconds now 1)}]
        (is (= record (store/insert-challenge! auth-store record)))
        (is (= :verified (:status (store/verify-challenge! auth-store request))))
        (is (= :consumed (:status (store/verify-challenge! auth-store request))))))

    (testing "concurrent wrong codes cannot increment beyond the limit"
      (let [{:keys [record]}
            (challenge/issue {:method :code :identity identity :now now
                              :hash-key code-hash-key :max-attempts 3})
            request {:selector (challenge/selector {:method :code :id (:id record)})
                     :method :code :proof "not-a-code" :hash-key code-hash-key
                     :now (.plusSeconds now 1)}
            gate (promise)]
        (is (= record (store/insert-challenge! auth-store record)))
        (let [attempts (doall
                        (repeatedly 10
                                    #(future
                                       @gate
                                       (store/verify-challenge! auth-store request))))]
          (deliver gate true)
          (doseq [attempt attempts] @attempt)
          (is (= 3 (:failed-attempt-count
                    (store/load-challenge auth-store (:id record)))))
          (is (= :attempts-exhausted
                 (:status (store/verify-challenge! auth-store request)))))))
     true)))

(defn assert-session-store
  "Exercises an AuthStore session implementation.

  Options may contain :subject when the store requires an application fixture."
  ([auth-store]
   (assert-session-store auth-store nil))
  ([auth-store {:keys [subject]}]
   (is (satisfies? store/AuthStore auth-store)
       "store satisfies passwordless-auth.store/AuthStore")
   (let [now (Instant/parse "2030-01-01T10:00:00Z")
         {:keys [record credential]}
         (session/issue {:subject (or subject
                                     {:kind :conformance :id (str (UUID/randomUUID))})
                         :now now :ttl (Duration/ofHours 1)})]
    (is (= record (store/insert-session! auth-store record))
        "insert-session! returns the stored session")
    (let [stored (store/load-session auth-store (:id record))]
      (is (= (:credential-hash record) (:credential-hash stored)))
      (is (not= credential (:credential-hash stored)))
      (is (not (.contains (pr-str stored) credential))))
    (is (= :invalid-session
           (:status (session/check (store/find-session
                                    auth-store
                                    [(session/credential-hash "wrong")])
                                   {:now now}))))
    (let [stored (store/find-session
                  auth-store
                  (session/credential-hash-candidates credential))]
      (is (= :active (:status (session/check stored {:now now}))))
      (is (= :expired-session
             (:status (session/check stored {:now (:expires-at record)})))))
    (is (true? (store/revoke-session! auth-store
                                      (:id record)
                                      (.plusSeconds now 1))))
    (is (true? (store/revoke-session! auth-store
                                      (:id record)
                                      (.plusSeconds now 2)))
        "revocation is idempotent for an existing session")
    (is (false? (store/revoke-session! auth-store
                                       (UUID/randomUUID)
                                       (.plusSeconds now 1))))
    (is (= :revoked-session
           (:status
            (session/check
             (store/find-session auth-store
                                 (session/credential-hash-candidates credential))
             {:now (.plusSeconds now 2)}))))
     true)))
