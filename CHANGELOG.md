# Changelog

## 0.3.0 - 2026-09-20

- Rename the project and Git dependency coordinate from `bevis` to
  `passwordless-auth`.
- Rename public namespaces from `bevis.*` to `passwordless-auth.*` without
  changing authentication behavior or the persistence contract.

## 0.2.0 - 2026-09-18

- Replace the function-map persistence boundary with `bevis.store/AuthStore`.
- Add tested copy-and-adjust PostgreSQL and SQLite store patterns.

## 0.1.0 - 2026-09-18

- Initial passwordless challenge/session value model.
- Magic-link and HMAC-protected numeric-code proofs.
- Explicit atomic persistence contract and reusable conformance assertions.
- Versioned credential hashes with legacy Radar session compatibility.
- Conservative Ring cookie and local return-path helpers.
- Pure issuance-limit decision primitive.
