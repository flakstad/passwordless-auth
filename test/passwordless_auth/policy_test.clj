(ns passwordless-auth.policy-test
  (:require [passwordless-auth.policy :as policy]
            [clojure.test :refer [deftest is]]))

(deftest issuance-limits
  (is (= {:allowed? true}
         (policy/issuance-decision {:identity-count 4 :client-count 19})))
  (is (= {:allowed? false :reason :identity-limit}
         (policy/issuance-decision {:identity-count 5 :client-count 0})))
  (is (= {:allowed? false :reason :client-limit}
         (policy/issuance-decision {:identity-count 0 :client-count 20}))))
