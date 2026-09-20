(ns passwordless-auth.policy)

(def recommended-identity-limit 5)
(def recommended-client-limit 20)

(defn issuance-decision
  "Pure decision over durable recent-challenge counts supplied by the application.

  Counts normally cover a rolling hour. The application owns keys, storage,
  locking, and the generic public response."
  [{:keys [identity-count client-count identity-limit client-limit]
    :or {identity-count 0
         client-count 0
         identity-limit recommended-identity-limit
         client-limit recommended-client-limit}}]
  (cond
    (>= identity-count identity-limit)
    {:allowed? false :reason :identity-limit}

    (>= client-count client-limit)
    {:allowed? false :reason :client-limit}

    :else
    {:allowed? true}))
