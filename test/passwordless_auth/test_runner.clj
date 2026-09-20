(ns passwordless-auth.test-runner
  (:require
   [passwordless-auth.challenge-test]
   [passwordless-auth.conformance-test]
   [passwordless-auth.policy-test]
   [passwordless-auth.postgres-store-test]
   [passwordless-auth.ring-test]
   [passwordless-auth.secret-test]
   [passwordless-auth.session-test]
   [passwordless-auth.sqlite-store-test]
   [clojure.test :as test]))

(defn -main
  [& _]
  (let [{:keys [fail error]}
        (test/run-tests 'passwordless-auth.challenge-test
                        'passwordless-auth.conformance-test
                        'passwordless-auth.policy-test
                        'passwordless-auth.postgres-store-test
                        'passwordless-auth.ring-test
                        'passwordless-auth.secret-test
                        'passwordless-auth.session-test
                        'passwordless-auth.sqlite-store-test)]
    (shutdown-agents)
    (when (pos? (+ fail error))
      (System/exit 1))))
