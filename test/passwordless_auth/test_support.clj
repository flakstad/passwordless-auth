(ns passwordless-auth.test-support
  (:require [passwordless-auth.challenge :as challenge]
            [passwordless-auth.store :as store]))

(defrecord MemoryStore [challenges sessions lock]
  store/AuthStore

  (insert-challenge! [_ record]
    (locking lock
      (swap! challenges assoc (:id record) record)
      record))

  (load-challenge [_ id]
    (get @challenges id))

  (verify-challenge! [_ {:keys [selector] :as request}]
    (locking lock
      (let [record (some (fn [[_ candidate]]
                           (when (and (= (:method selector) (:method candidate))
                                      (if-let [id (:id selector)]
                                        (= id (:id candidate))
                                        (= (:proof-hash selector)
                                           (:proof-hash candidate))))
                             candidate))
                         @challenges)
            result (challenge/verify record request)]
        (when record
          (swap! challenges assoc (:id record)
                 (challenge/apply-transition record result)))
        result)))

  (insert-session! [_ record]
    (locking lock
      (swap! sessions assoc (:id record) record)
      record))

  (find-session [_ credential-hashes]
    (some (fn [[_ record]]
            (when (some #{(:credential-hash record)} credential-hashes)
              record))
          @sessions))

  (load-session [_ id]
    (get @sessions id))

  (revoke-session! [_ id now]
    (locking lock
      (if (get @sessions id)
        (do
          (swap! sessions update id #(assoc % :revoked-at (or (:revoked-at %) now)))
          true)
        false))))

(defn memory-store
  []
  (->MemoryStore (atom {}) (atom {}) (Object.)))
