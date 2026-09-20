(ns passwordless-auth.time
  (:import
   (java.time Clock Duration Instant)))

(defn now
  "Returns an Instant from an explicit :now or Clock. Defaults to UTC system time."
  [{:keys [now clock]}]
  (cond
    (instance? Instant now) now
    (some? now) (throw (ex-info ":now must be a java.time.Instant" {:value now}))
    (instance? Clock clock) (Instant/now ^Clock clock)
    (nil? clock) (Instant/now (Clock/systemUTC))
    :else (throw (ex-info ":clock must be a java.time.Clock" {:value clock}))))

(defn expires-at
  [^Instant created-at ttl]
  (when-not (instance? Duration ttl)
    (throw (ex-info ":ttl must be a java.time.Duration" {:value ttl})))
  (when-not (pos? (.toMillis ^Duration ttl))
    (throw (ex-info ":ttl must be positive" {:value ttl})))
  (.plus created-at ^Duration ttl))

(defn expired?
  "Expiry is exclusive: a value is expired when now equals or follows expires-at."
  [^Instant expires-at ^Instant now]
  (not (.isBefore now expires-at)))
