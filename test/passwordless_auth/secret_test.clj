(ns passwordless-auth.secret-test
  (:require [passwordless-auth.secret :as secret]
            [clojure.test :refer [deftest is]]))

(deftest secure-token-shapes
  (let [one (secret/random-token)
        two (secret/random-token)]
    (is (= 43 (count one)))
    (is (re-matches #"[A-Za-z0-9_-]+" one))
    (is (not= one two))))

(deftest code-shapes
  (dotimes [_ 100]
    (is (re-matches #"[0-9]{6}" (secret/random-code))))
  (is (thrown? clojure.lang.ExceptionInfo (secret/random-code 5))))

(deftest versioned-hashes-and-legacy-compatibility
  (let [plain (secret/hash-secret "bearer")
        keyed (secret/hash-secret "123456" {:key "pepper"})
        legacy (secret/legacy-sha256-hex "bearer")]
    (is (re-matches #"v1:sha256:[A-Za-z0-9_-]{43}" plain))
    (is (re-matches #"v1:hmac-sha256:[A-Za-z0-9_-]{43}" keyed))
    (is (secret/matches? plain "bearer"))
    (is (not (secret/matches? plain "wrong")))
    (is (secret/matches? keyed "123456" {:key "pepper"}))
    (is (not (secret/matches? keyed "123456" {:key "wrong"})))
    (is (secret/matches? legacy "bearer"))
    (is (= [plain legacy]
           (secret/hash-candidates "bearer" {:include-legacy-sha256? true})))))
