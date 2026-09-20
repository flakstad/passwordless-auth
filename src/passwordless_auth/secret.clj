(ns passwordless-auth.secret
  (:require [clojure.string :as str])
  (:import
   (java.nio.charset StandardCharsets)
   (java.security MessageDigest SecureRandom)
   (java.util Base64)
   (javax.crypto Mac)
   (javax.crypto.spec SecretKeySpec)))

(def ^:private ^SecureRandom secure-random (SecureRandom.))
(def ^:private url-encoder (.withoutPadding (Base64/getUrlEncoder)))
(def ^:private url-decoder (Base64/getUrlDecoder))

(defn random-token
  "Returns a URL-safe bearer credential with byte-count bytes of entropy."
  ([] (random-token 32))
  ([byte-count]
   (when-not (and (integer? byte-count) (<= 16 byte-count 1024))
     (throw (ex-info "byte-count must be between 16 and 1024" {:byte-count byte-count})))
   (let [bytes (byte-array byte-count)]
     (.nextBytes secure-random bytes)
     (.encodeToString url-encoder bytes))))

(defn random-code
  "Returns a uniformly generated, zero-padded numeric code. Six digits is the default."
  ([] (random-code 6))
  ([digits]
   (when-not (and (integer? digits) (<= 6 digits 9))
     (throw (ex-info "digits must be between 6 and 9" {:digits digits})))
   (let [bound (long (reduce *' (repeat digits 10)))
         value (.nextLong secure-random bound)]
     (format (str "%0" digits "d") value))))

(defn- utf8-bytes
  [value]
  (.getBytes (str value) StandardCharsets/UTF_8))

(defn- sha256-bytes
  [value]
  (.digest (MessageDigest/getInstance "SHA-256") (utf8-bytes value)))

(defn- hmac-sha256-bytes
  [key value]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. (utf8-bytes key) "HmacSHA256"))
    (.doFinal mac (utf8-bytes value))))

(defn hash-secret
  "Hashes a bearer secret using a versioned format. A key selects HMAC-SHA-256."
  ([value] (hash-secret value nil))
  ([value {:keys [key]}]
   (when-not (string? value)
     (throw (ex-info "secret must be a string" {})))
   (when (and (some? key) (str/blank? (str key)))
     (throw (ex-info "hash key must not be blank" {})))
   (let [[algorithm digest] (if key
                              ["hmac-sha256" (hmac-sha256-bytes key value)]
                              ["sha256" (sha256-bytes value)])]
     (str "v1:" algorithm ":" (.encodeToString url-encoder digest)))))

(defn legacy-sha256-hex
  "Compatibility digest for migrations from unversioned SHA-256 hex storage."
  [value]
  (apply str (map #(format "%02x" (bit-and % 0xff)) (sha256-bytes value))))

(defn hash-candidates
  "Current hash followed by explicitly requested compatibility hashes."
  ([value] (hash-candidates value nil))
  ([value {:keys [key include-legacy-sha256?]}]
   (cond-> [(hash-secret value {:key key})]
     include-legacy-sha256? (conj (legacy-sha256-hex value)))))

(defn- decode-hash
  [stored]
  (when-let [[_ algorithm encoded]
             (and (string? stored)
                  (re-matches #"^v1:(sha256|hmac-sha256):([A-Za-z0-9_-]{43})$" stored))]
    {:algorithm algorithm
     :digest (.decode url-decoder ^String encoded)}))

(defn matches?
  "Constant-time comparison of a submitted value with a supported stored hash."
  ([stored value] (matches? stored value nil))
  ([stored value {:keys [key]}]
   (if-not (string? value)
     false
     (if-let [{:keys [algorithm digest]} (decode-hash stored)]
       (let [actual (case algorithm
                      "sha256" (sha256-bytes value)
                      "hmac-sha256" (when key (hmac-sha256-bytes key value)))]
         (boolean (and actual (MessageDigest/isEqual ^bytes digest ^bytes actual))))
       (boolean
        (and (string? stored)
             (re-matches #"[0-9a-f]{64}" stored)
             (MessageDigest/isEqual (utf8-bytes stored)
                                    (utf8-bytes (legacy-sha256-hex value)))))))))
