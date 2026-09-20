(ns passwordless-auth.ring
  (:require [clojure.string :as str]))

(def ^:private same-sites #{:strict :lax :none})
(def ^:private dangerous-encoded #"(?i)%(?:0a|0d|00|25|2f|5c)")

(defn safe-return-path
  "Returns candidate only when it is a conservative local absolute path."
  ([candidate] (safe-return-path candidate "/"))
  ([candidate fallback]
   (if (and (string? candidate)
            (not (str/blank? candidate))
            (str/starts-with? candidate "/")
            (not (str/starts-with? candidate "//"))
            (not (str/includes? candidate "\\"))
            (not (re-find #"[\u0000-\u001f\u007f]" candidate))
            (not (re-find dangerous-encoded candidate)))
     candidate
     fallback)))

(defn- valid-cookie-token?
  [value]
  (and (string? value)
       (not (str/blank? value))
       (not (re-find #"[\x00-\x20\x7f;,]" value))))

(defn- cookie-header
  [{:keys [name value secure? same-site path max-age expires]
    :or {secure? true same-site :strict path "/"}}]
  (when-not (valid-cookie-token? name)
    (throw (ex-info "invalid cookie name" {:name name})))
  (when-not (valid-cookie-token? value)
    (throw (ex-info "invalid cookie value" {})))
  (when-not (contains? same-sites same-site)
    (throw (ex-info "unsupported SameSite policy" {:same-site same-site})))
  (when-not (and (string? path)
                 (str/starts-with? path "/")
                 (not (re-find #"[\x00-\x20\x7f;]" path)))
    (throw (ex-info "invalid cookie path" {:path path})))
  (when (and (some? max-age)
             (or (not (integer? max-age)) (neg? max-age)))
    (throw (ex-info "cookie Max-Age must be a non-negative integer"
                    {:max-age max-age})))
  (when (and expires
             (or (not (string? expires)) (re-find #"[\r\n;]" expires)))
    (throw (ex-info "invalid cookie expiry" {})))
  (when (and (= :none same-site) (not secure?))
    (throw (ex-info "SameSite=None requires Secure" {})))
  (when (and (str/starts-with? name "__Host-")
             (or (not secure?) (not= "/" path)))
    (throw (ex-info "__Host- cookies require Secure and Path=/" {:name name})))
  (str name "=" value
       "; Path=" path
       "; HttpOnly"
       (when secure? "; Secure")
       "; SameSite=" (str/capitalize (clojure.core/name same-site))
       (when (some? max-age) (str "; Max-Age=" (long max-age)))
       (when expires (str "; Expires=" expires))))

(defn session-cookie
  "Returns a Set-Cookie header value with conservative defaults.

  Security-relevant overrides are explicit keys in the argument map."
  [{:keys [name value] :as options}]
  (cookie-header (merge {:name (or name "__Host-session")
                         :value value}
                        options)))

(defn clear-session-cookie
  "Returns a Set-Cookie header value that expires the selected session cookie."
  [{:keys [name] :as options}]
  (cookie-header (merge {:name (or name "__Host-session")
                         :value "deleted"
                         :max-age 0
                         :expires "Thu, 01 Jan 1970 00:00:00 GMT"}
                        options)))
