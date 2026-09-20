(ns passwordless-auth.session
  (:require
   [passwordless-auth.secret :as secret]
   [passwordless-auth.time :as time])
  (:import
   (java.time Duration)
   (java.util UUID)))

(def default-ttl (Duration/ofHours 12))

(defn credential-hash
  [credential]
  (secret/hash-secret credential))

(defn credential-hash-candidates
  [credential]
  (secret/hash-candidates credential {:include-legacy-sha256? true}))

(defn issue
  "Constructs a server-side session record and returns its opaque credential once."
  [{:keys [id subject ttl metadata] :as options}]
  (when (nil? subject)
    (throw (ex-info ":subject is required" {})))
  (let [created-at (time/now options)
        credential (secret/random-token 32)]
    {:record {:id (or id (UUID/randomUUID))
              :subject subject
              :credential-hash (credential-hash credential)
              :created-at created-at
              :expires-at (time/expires-at created-at (or ttl default-ttl))
              :revoked-at nil
              :metadata (or metadata {})}
     :credential credential}))

(defn public-session
  [record]
  (dissoc record :credential-hash))

(defn check
  "Classifies a stored session record at an explicit time."
  [record options]
  (let [now (time/now options)]
    (cond
      (nil? record) {:status :invalid-session}
      (:revoked-at record) {:status :revoked-session}
      (time/expired? (:expires-at record) now) {:status :expired-session}
      :else {:status :active :session (public-session record)})))

(defn active?
  [record options]
  (= :active (:status (check record options))))
