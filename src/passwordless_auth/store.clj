(ns passwordless-auth.store
  "Persistence contract for challenges and sessions.")

(defprotocol AuthStore
  (insert-challenge!
    [store challenge]
    "Persists a challenge and returns the stored challenge.")

  (load-challenge
    [store challenge-id]
    "Returns the stored challenge, or nil when it does not exist.")

  (verify-challenge!
    [store request]
    "Atomically loads, verifies, and transitions a challenge.

    Implementations must call passwordless-auth.challenge/verify against the current
    record and persist its transition under one row lock or compare-and-set
    guard. Two concurrent calls must not both return :verified.")

  (insert-session!
    [store session]
    "Persists a session and returns the stored session.")

  (find-session
    [store credential-hash-candidates]
    "Returns the matching stored session, including expired or revoked
    sessions, or nil when no candidate matches.")

  (load-session
    [store session-id]
    "Returns the stored session, or nil when it does not exist.")

  (revoke-session!
    [store session-id revoked-at]
    "Makes revocation visible before returning. Returns true when the session
    exists, including when it was already revoked, and false otherwise."))
