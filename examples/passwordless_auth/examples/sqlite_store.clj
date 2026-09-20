(ns passwordless-auth.examples.sqlite-store
  "Complete next.jdbc/SQLite AuthStore pattern intended for copying.

  This implementation uses guarded updates rather than relying on SQLite row
  locks. Replace the EDN identity/metadata codec and table names as needed."
  (:require
   [passwordless-auth.challenge :as challenge]
   [passwordless-auth.store :as store]
   [clojure.edn :as edn]
   [clojure.string :as str]
   [next.jdbc :as jdbc]
   [next.jdbc.result-set :as rs])
  (:import
   (java.time Instant)
   (java.util UUID)))

(def schema-statements
  ["CREATE TABLE IF NOT EXISTS auth_challenges (
       id TEXT PRIMARY KEY,
       identity_edn TEXT NOT NULL,
       method TEXT NOT NULL,
       proof_hash TEXT NOT NULL,
       created_at TEXT NOT NULL,
       expires_at TEXT NOT NULL,
       consumed_at TEXT,
       failed_attempt_count INTEGER NOT NULL,
       max_attempts INTEGER NOT NULL,
       metadata_edn TEXT NOT NULL
     )"
   "CREATE UNIQUE INDEX IF NOT EXISTS auth_challenges_method_proof_hash
      ON auth_challenges(method, proof_hash)"
   "CREATE TABLE IF NOT EXISTS auth_sessions (
       id TEXT PRIMARY KEY,
       subject_edn TEXT NOT NULL,
       credential_hash TEXT NOT NULL UNIQUE,
       created_at TEXT NOT NULL,
       expires_at TEXT NOT NULL,
       revoked_at TEXT,
       metadata_edn TEXT NOT NULL
     )"])

(defn create-schema!
  [connectable]
  (doseq [statement schema-statements]
    (jdbc/execute! connectable [statement])))

(defn- encode-edn [value]
  (pr-str value))

(defn- decode-edn [value]
  (edn/read-string (str value)))

(defn- ->db-time [value]
  (some-> value str))

(defn- ->instant [value]
  (some-> value str Instant/parse))

(defn- ->uuid [value]
  (when value
    (if (instance? UUID value) value (UUID/fromString (str value)))))

(defn- challenge-row [row]
  (when row
    {:id (->uuid (:id row))
     :identity (decode-edn (:identity-edn row))
     :method (keyword (:method row))
     :proof-hash (:proof-hash row)
     :created-at (->instant (:created-at row))
     :expires-at (->instant (:expires-at row))
     :consumed-at (->instant (:consumed-at row))
     :failed-attempt-count (:failed-attempt-count row)
     :max-attempts (:max-attempts row)
     :metadata (decode-edn (:metadata-edn row))}))

(defn- session-row [row]
  (when row
    {:id (->uuid (:id row))
     :subject (decode-edn (:subject-edn row))
     :credential-hash (:credential-hash row)
     :created-at (->instant (:created-at row))
     :expires-at (->instant (:expires-at row))
     :revoked-at (->instant (:revoked-at row))
     :metadata (decode-edn (:metadata-edn row))}))

(def ^:private query-options
  {:builder-fn rs/as-unqualified-kebab-maps})

(defn- insert-challenge-row! [connectable record]
  (jdbc/execute-one!
   connectable
   ["INSERT INTO auth_challenges
       (id, identity_edn, method, proof_hash, created_at, expires_at,
        consumed_at, failed_attempt_count, max_attempts, metadata_edn)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    (str (:id record))
    (encode-edn (:identity record))
    (name (:method record))
    (:proof-hash record)
    (->db-time (:created-at record))
    (->db-time (:expires-at record))
    (->db-time (:consumed-at record))
    (:failed-attempt-count record)
    (:max-attempts record)
    (encode-edn (:metadata record))])
  record)

(defn- select-challenge [connectable selector]
  (let [[where value] (if-let [id (:id selector)]
                        ["id = ?" (str id)]
                        ["proof_hash = ?" (:proof-hash selector)])]
    (challenge-row
     (jdbc/execute-one!
      connectable
      [(str "SELECT * FROM auth_challenges WHERE method = ? AND " where)
       (name (:method selector)) value]
      query-options))))

(defn- apply-transition! [connectable record transition]
  (case (:op transition)
    :consume
    (:next.jdbc/update-count
     (jdbc/execute-one!
      connectable
      ["UPDATE auth_challenges SET consumed_at = ?
        WHERE id = ? AND consumed_at IS NULL
          AND failed_attempt_count = ? AND expires_at = ?"
       (->db-time (:consumed-at transition))
       (str (:id record))
       (:failed-attempt-count record)
       (->db-time (:expires-at record))]))

    :record-failure
    (:next.jdbc/update-count
     (jdbc/execute-one!
      connectable
      ["UPDATE auth_challenges SET failed_attempt_count = ?
        WHERE id = ? AND consumed_at IS NULL
          AND failed_attempt_count = ? AND expires_at = ?"
       (:failed-attempt-count transition)
       (str (:id record))
       (:failed-attempt-count record)
       (->db-time (:expires-at record))]))

    nil 0))

(defn- verify-with-cas! [connectable {:keys [selector] :as request}]
  (loop []
    (let [record (select-challenge connectable selector)
          result (challenge/verify record request)
          transition (:transition result)]
      (if-not transition
        result
        (if (= 1 (apply-transition! connectable record transition))
          result
          (recur))))))

(defn- insert-session-row! [connectable record]
  (jdbc/execute-one!
   connectable
   ["INSERT INTO auth_sessions
       (id, subject_edn, credential_hash, created_at, expires_at,
        revoked_at, metadata_edn)
     VALUES (?, ?, ?, ?, ?, ?, ?)"
    (str (:id record))
    (encode-edn (:subject record))
    (:credential-hash record)
    (->db-time (:created-at record))
    (->db-time (:expires-at record))
    (->db-time (:revoked-at record))
    (encode-edn (:metadata record))])
  record)

(defrecord SQLiteAuthStore [connectable]
  store/AuthStore

  (insert-challenge! [_ record]
    (insert-challenge-row! connectable record))

  (load-challenge [_ id]
    (challenge-row
     (jdbc/execute-one! connectable
                        ["SELECT * FROM auth_challenges WHERE id = ?" (str id)]
                        query-options)))

  (verify-challenge! [_ request]
    (verify-with-cas! connectable request))

  (insert-session! [_ record]
    (insert-session-row! connectable record))

  (find-session [_ credential-hashes]
    (when (seq credential-hashes)
      (session-row
       (jdbc/execute-one!
        connectable
        (into [(str "SELECT * FROM auth_sessions WHERE credential_hash IN ("
                    (str/join "," (repeat (count credential-hashes) "?"))
                    ") LIMIT 1")]
              credential-hashes)
        query-options))))

  (load-session [_ id]
    (session-row
     (jdbc/execute-one! connectable
                        ["SELECT * FROM auth_sessions WHERE id = ?" (str id)]
                        query-options)))

  (revoke-session! [_ id revoked-at]
    (= 1
       (:next.jdbc/update-count
        (jdbc/execute-one!
         connectable
         ["UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?)
           WHERE id = ?"
          (->db-time revoked-at) (str id)])))))

(defn sqlite-store
  "Returns a store for a SQLite datasource or existing next.jdbc transaction."
  [connectable]
  (->SQLiteAuthStore connectable))
