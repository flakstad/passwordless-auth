(ns passwordless-auth.conformance-test
  (:require [passwordless-auth.conformance :as conformance]
            [passwordless-auth.test-support :as support]
            [clojure.test :refer [deftest]]))

(deftest in-memory-store-obeys-challenge-contract
  (conformance/assert-challenge-store (support/memory-store)))

(deftest in-memory-store-obeys-session-contract
  (conformance/assert-session-store (support/memory-store)))
