(ns passwordless-auth.examples.postgres-store
  "Complete next.jdbc/PostgreSQL AuthStore pattern intended for copying.

  Replace the EDN identity/metadata codec and table names to match the
  application. Runtime PostgreSQL and next.jdbc dependencies are application
  dependencies, not Passwordless Auth dependencies."
  (:require
   [passwordless-auth.challenge :as challenge]
   [passwordless-auth.store :as store]
   [clojure.edn :as edn]
   [clojure.string :as str]
   [next.jdbc :as jdbc]
   [next.jdbc.result-set :as rs])
  (:import
   (java.sql Timestamp)
   (java.time Instant OffsetDateTime ZoneOffset)))

(def schema-statements
  ["CREATE TABLE IF NOT EXISTS auth_challenges (
       id UUID PRIMARY KEY,
       identity_edn TEXT NOT NULL,
       method TEXT NOT NULL,
       proof_hash TEXT NOT NULL,
       created_at TIMESTAMPTZ NOT NULL,
       expires_at TIMESTAMPTZ NOT NULL,
       consumed_at TIMESTAMPTZ,
       failed_attempt_count INTEGER NOT NULL,
       max_attempts INTEGER NOT NULL,
       metadata_edn TEXT NOT NULL
     )"
   "CREATE UNIQUE INDEX IF NOT EXISTS auth_challenges_method_proof_hash
      ON auth_challenges(method, proof_hash)"
   "CREATE TABLE IF NOT EXISTS auth_sessions (
       id UUID PRIMARY KEY,
       subject_edn TEXT NOT NULL,
       credential_hash TEXT NOT NULL UNIQUE,
       created_at TIMESTAMPTZ NOT NULL,
       expires_at TIMESTAMPTZ NOT NULL,
       revoked_at TIMESTAMPTZ,
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
  (some-> value (OffsetDateTime/ofInstant ZoneOffset/UTC)))

(defn- ->instant [value]
  (cond
    (nil? value) nil
    (instance? Instant value) value
    (instance? OffsetDateTime value) (.toInstant ^OffsetDateTime value)
    (instance? Timestamp value) (.toInstant ^Timestamp value)
    :else (throw (ex-info "unsupported PostgreSQL timestamp" {:value value}))))

(defn- challenge-row [row]
  (when row
    {:id (:id row)
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
    {:id (:id row)
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
    (:id record)
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

(defn- select-challenge [connectable selector lock?]
  (let [suffix (if lock? " FOR UPDATE" "")
        [where value] (if-let [id (:id selector)]
                        ["id = ?" id]
                        ["proof_hash = ?" (:proof-hash selector)])]
    (challenge-row
     (jdbc/execute-one!
      connectable
      [(str "SELECT * FROM auth_challenges WHERE method = ? AND " where suffix)
       (name (:method selector)) value]
      query-options))))

(defn- verify-in-transaction! [tx {:keys [selector] :as request}]
  (let [record (select-challenge tx selector true)
        result (challenge/verify record request)
        transition (:transition result)
        updated (case (:op transition)
                  :consume
                  (jdbc/execute-one!
                   tx
                   ["UPDATE auth_challenges SET consumed_at = ?
                     WHERE id = ? AND consumed_at IS NULL
                       AND failed_attempt_count = ?"
                    (->db-time (:consumed-at transition))
                    (:id record)
                    (:failed-attempt-count record)])

                  :record-failure
                  (jdbc/execute-one!
                   tx
                   ["UPDATE auth_challenges SET failed_attempt_count = ?
                     WHERE id = ? AND consumed_at IS NULL
                       AND failed_attempt_count = ?"
                    (:failed-attempt-count transition)
                    (:id record)
                    (:failed-attempt-count record)])

                  nil nil)]
    (when (and transition (not= 1 (:next.jdbc/update-count updated)))
      (throw (ex-info "challenge transition lost its atomic guard"
                      {:challenge-id (:id record)
                       :transition (:op transition)})))
    result))

(defn- insert-session-row! [connectable record]
  (jdbc/execute-one!
   connectable
   ["INSERT INTO auth_sessions
       (id, subject_edn, credential_hash, created_at, expires_at,
        revoked_at, metadata_edn)
     VALUES (?, ?, ?, ?, ?, ?, ?)"
    (:id record)
    (encode-edn (:subject record))
    (:credential-hash record)
    (->db-time (:created-at record))
    (->db-time (:expires-at record))
    (->db-time (:revoked-at record))
    (encode-edn (:metadata record))])
  record)

(defrecord PostgresAuthStore [connectable transaction?]
  store/AuthStore

  (insert-challenge! [_ record]
    (insert-challenge-row! connectable record))

  (load-challenge [_ id]
    (challenge-row
     (jdbc/execute-one! connectable
                        ["SELECT * FROM auth_challenges WHERE id = ?" id]
                        query-options)))

  (verify-challenge! [_ request]
    (if transaction?
      (verify-in-transaction! connectable request)
      (jdbc/with-transaction [tx connectable]
        (verify-in-transaction! tx request))))

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
                        ["SELECT * FROM auth_sessions WHERE id = ?" id]
                        query-options)))

  (revoke-session! [_ id revoked-at]
    (= 1
       (:next.jdbc/update-count
        (jdbc/execute-one!
         connectable
         ["UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?)
           WHERE id = ?"
          (->db-time revoked-at) id])))))

(defn postgres-store
  "Store backed by a datasource. verify-challenge! opens its own transaction."
  [datasource]
  (->PostgresAuthStore datasource false))

(defn transaction-store
  "Store backed by an existing next.jdbc transaction.

  Use this when challenge verification and application work must commit in the
  same transaction. The application remains the transaction owner."
  [transaction]
  (->PostgresAuthStore transaction true))
