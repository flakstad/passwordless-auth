(ns passwordless-auth.ring-test
  (:require [passwordless-auth.ring :as ring]
            [clojure.test :refer [deftest is]]))

(deftest accepts-only-conservative-local-return-paths
  (doseq [path ["/" "/konto" "/konto?tab=sikkerhet" "/søk?q=stein#resultat"]]
    (is (= path (ring/safe-return-path path "/fallback")) path))
  (doseq [value [nil "" "   " "https://evil.example/x" "http://evil.example"
                 "//evil.example" "///evil.example" "\\\\evil.example"
                 "/\\evil.example" "%2f%2fevil.example" "/%2Fevil.example"
                 "/%5cevil.example" "/%255cevil.example" "/ok\rLocation: https://evil"
                 "/ok\nLocation: //evil" "/%0d%0aLocation:evil"]]
    (is (= "/fallback" (ring/safe-return-path value "/fallback")) (pr-str value))))

(deftest cookie-defaults-and-clearing
  (is (= "__Host-app_session=token; Path=/; HttpOnly; Secure; SameSite=Strict"
         (ring/session-cookie {:name "__Host-app_session" :value "token"})))
  (is (= "app_session=token; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
         (ring/session-cookie {:name "app_session" :value "token"
                               :secure? false :same-site :lax :max-age 3600})))
  (let [cleared (ring/clear-session-cookie {:name "__Host-app_session"})]
    (is (.contains cleared "Max-Age=0"))
    (is (.contains cleared "Expires=Thu, 01 Jan 1970 00:00:00 GMT"))
    (is (.contains cleared "HttpOnly; Secure; SameSite=Strict")))
  (is (thrown? clojure.lang.ExceptionInfo
               (ring/session-cookie {:name "__Host-app_session" :value "x" :secure? false})))
  (is (thrown? clojure.lang.ExceptionInfo
               (ring/session-cookie {:name "app" :value "x" :secure? false
                                     :same-site :none}))))
