(ns passwordless-auth.challenge
  (:require
   [passwordless-auth.secret :as secret]
   [passwordless-auth.time :as time])
  (:import
   (java.time Duration)
   (java.util UUID)))

(def supported-methods #{:magic-link :code})
(def default-magic-link-ttl (Duration/ofMinutes 15))
(def default-code-ttl (Duration/ofMinutes 10))
(def default-code-digits 6)
(def default-code-max-attempts 5)

(defn hash-proof
  ([proof] (secret/hash-secret proof))
  ([proof options] (secret/hash-secret proof options)))

(defn issue
  "Constructs a challenge record and returns its plaintext proof exactly once.

  Code challenges require :hash-key. Identity is opaque and is never normalized."
  [{:keys [id identity method ttl digits max-attempts metadata hash-key]
    :as options}]
  (when-not (contains? supported-methods method)
    (throw (ex-info "unsupported challenge method" {:method method})))
  (when (nil? identity)
    (throw (ex-info ":identity is required" {})))
  (when (and (= :code method)
             (or (not (string? hash-key))
                 (< (count (.getBytes ^String hash-key "UTF-8")) 32)))
    (throw (ex-info "code challenges require a :hash-key of at least 32 bytes"
                    {:method method})))
  (let [created-at (time/now options)
        ttl (or ttl (if (= :code method) default-code-ttl default-magic-link-ttl))
        proof (if (= :code method)
                (secret/random-code (or digits default-code-digits))
                (secret/random-token 32))
        max-attempts (or max-attempts
                         (if (= :code method) default-code-max-attempts 1))]
    (when-not (and (integer? max-attempts) (pos? max-attempts))
      (throw (ex-info ":max-attempts must be a positive integer" {:max-attempts max-attempts})))
    {:record {:id (or id (UUID/randomUUID))
              :identity identity
              :method method
              :proof-hash (hash-proof proof {:key hash-key})
              :created-at created-at
              :expires-at (time/expires-at created-at ttl)
              :consumed-at nil
              :failed-attempt-count 0
              :max-attempts max-attempts
              :metadata (or metadata {})}
     :proof proof}))

(defn selector
  "Builds the non-plaintext lookup selector expected by an AuthStore."
  [{:keys [method id proof]}]
  (case method
    :magic-link {:method method
                 :proof-hash (when (string? proof) (hash-proof proof))}
    :code {:method method :id id}
    (throw (ex-info "unsupported challenge method" {:method method}))))

(defn public-challenge
  [record]
  (dissoc record :proof-hash))

(defn apply-transition
  "Applies a transition returned by verify. Store implementations use this only
  while holding their lock or compare-and-set guard."
  [record {:keys [transition]}]
  (case (:op transition)
    :consume (assoc record :consumed-at (:consumed-at transition))
    :record-failure (assoc record :failed-attempt-count
                           (:failed-attempt-count transition))
    nil record
    (throw (ex-info "unsupported challenge transition" {:transition transition}))))

(defn verify
  "Returns a result and requested state transition without mutating storage.

  The store must evaluate this function and apply :transition under one row
  lock or compare-and-set operation. The result never contains proof material."
  [record {:keys [method proof hash-key] :as options}]
  (let [now (time/now options)
        failures (long (or (:failed-attempt-count record) 0))
        max-attempts (long (or (:max-attempts record) 1))]
    (cond
      (nil? record) {:status :invalid-proof}
      (not= method (:method record)) {:status :invalid-proof}
      (:consumed-at record) {:status :consumed}
      (time/expired? (:expires-at record) now) {:status :expired}
      (>= failures max-attempts) {:status :attempts-exhausted}
      (secret/matches? (:proof-hash record) proof {:key hash-key})
      {:status :verified
       :challenge (public-challenge record)
       :transition {:op :consume :consumed-at now}}

      (= :code method)
      (let [next-count (inc failures)]
        {:status (if (>= next-count max-attempts)
                   :attempts-exhausted
                   :invalid-proof)
         :transition {:op :record-failure
                      :failed-attempt-count next-count}})

      :else {:status :invalid-proof})))
