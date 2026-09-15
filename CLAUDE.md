# bauth — notes for Claude

Headless authentication server for web and mobile apps (SPA, SSR, Tauri…) and their APIs.
Apps draw their own screens and call bauth's JSON API; bauth issues OAuth 2.1 tokens.
Rewrite started 2026-09 from a 2020 actix prototype: nothing of the old code is kept.

## Working with the maintainer
- Conversation in **French**; code, comments and docs in English.
- Apply changes directly in the repo, one step at a time, then verify (build, tests, end-to-end run).
- **Never commit**: the maintainer commits himself.
- Containers run with **podman** (`podman compose`, `podman build`), not Docker Desktop.
- Project is pre-production: fixing a mistake in an existing migration is fine (the dev DB gets
  reverted and re-run) — say so instead of adding a corrective migration.

## Workspace
Crates and dependencies: see `Cargo.toml` (`bauth_server` the server, `bauth_client` the token
`Verifier` for APIs, `bauth_core` shared claims, `sdk/client` the `@bauth/client` TS SDK).
The SDK needs **TypeScript 5** — `openapi-typescript` requires it.

## Commands
```sh
podman compose up -d mailpit postgres-test   # SMTP :1025, UI :8026; test Postgres on :5440
cd bauth_server && sqlx migrate run          # sqlx-cli reads bauth_server/sqlx.toml
cargo run -p bauth_server                    # reads .env (see .env.example)
SQLX_OFFLINE=true cargo clippy --all-features --all --tests -- -D warnings   # what CI runs
SQLX_OFFLINE=true cargo test --all-features --all      # needs DATABASE_URL (see below)
cd bauth_server && cargo sqlx prepare        # after ANY query change: refresh .sqlx, commit it
UPDATE_OPENAPI=1 cargo test -p bauth_server openapi   # after ANY route/schema change: refresh openapi.json
cd sdk/client && npm run generate && npm test         # then refresh the SDK types (CI checks they match)
```
CI (`.github/workflows/_check_server.yml`) and the Dockerfile build with `SQLX_OFFLINE=true`:
a stale `bauth_server/.sqlx` breaks both. A stale `bauth_server/openapi.json` fails `cargo test`.

## Server layout (`bauth_server/src`)
`routes/` handlers own the transactions and call `queries::*`; `queries/` has one file per table
(`sqlx::query!` fns generic over `E: Executor`, so they take `&state.db` or `&mut *tx`; helpers doing
several queries take `&mut DbConnection`). The rest of the tree is what `ls` shows. What isn't obvious:
- `state.signing_keys` is an `ArcSwap` (hot-reloaded): read it with `state.signing_keys.load()`.
- A new route must be added **both** to `routes::router()` **and** to `paths(...)` in `routes/openapi.rs`,
  with a unique `operation_id` when the function name is generic (it names the SDK operation).
  Every handler carries `#[utoipa::path]` listing its error `code`s; request/response types derive `ToSchema`.
- `jobs/` (`tokio-cron-scheduler`, started in `main`, UTC): `purge` hourly at :17, signing-key reload
  hourly at :07 (creates a key if none can sign — emergency retirement by SQL), key rotation daily at
  03:23 (new key when the signing one is 30 days old). Batched deletes under `pg_try_advisory_lock` /
  advisory xact lock, so several instances can run at once.
- `purge` must **never** delete refresh tokens of a live session: theft detection needs them.
- Signing keys: Ed25519 seeds encrypted by `master_key` (XChaCha20-Poly1305, per-key AAD); a new key is
  published 24 h before it signs and kept 24 h after; the signing key is picked per token from
  `active_at` / `retired_at`.

## Database
- Can share a Postgres with other apps: **everything lives in schema `bauth`**. Always write `bauth.table`
  in SQL — the search path could otherwise hit another app's `public.users`.
- Migration table `bauth._sqlx_migrations` (see `sqlx.toml`). Reversible migrations (`sqlx migrate add -r`).
- Tables: `users`, `password_credentials`, `email_verifications`, `login_flows`, `authorization_codes`,
  `signing_keys`, `sessions`, `refresh_tokens` (`parent_id`, `superseded_at`), `password_resets`,
  `magic_links` (`code_hash`, `code_failures`), `email_changes`.
- UUID v7 ids (`uuidv7()` default, Postgres 18), `timestamptz` ↔ `DateTime<Utc>`.
- Emails normalized **in SQL** with `lower(btrim($1))` on insert and lookup.

## Flows
- A session = one login of a user on a client (a refresh token family). Access token claims:
  `iss sub aud client_id sid iat exp jti`; `aud` = client's `audience` (defaults to client id).
- Refresh rotation: reusing a rotated token within 30 s is allowed (two tabs); later, it's a retry
  if no successor was used (unused successors get `superseded_at`), otherwise theft → revoke session.
  A superseded token coming back also revokes the session.
- Password login requires a verified email; magic link (or its code), reset and email change links verify it.
- Anyone can register an address they don't own: a magic link/code login that verifies an account
  deletes its password and revokes its sessions (`magic_link::log_in`, notice email sent). Unverified
  accounts are purged after 7 days. Lock order in those transactions: `users` row, then credentials.
- Magic link email = link + 6-digit code, one `magic_links` row: using either consumes it. The code
  (`POST /flows/login/{id}/magic-code`) is typed on the device that asked (mobile mail apps open links
  elsewhere). Only 10^6 values, so (`magic_code.rs`, `routes/magic_link.rs`): looked up by flow, newest
  email of the flow only, consumed after 5 wrong codes, and at most 10 wrong codes per account over
  24 h (sum of `code_failures`) — past that codes are refused for the account, links still work. Checks
  run with the user row locked (`FOR NO KEY UPDATE`) so concurrent guesses can't overshoot. HMAC keyed by
  `MasterKey::derive("magic_code")` over `flow_id || code`; 3 emails per flow (counted on `login_flows`
  whether the account exists or not); `invalid_code` for wrong code / unknown flow / no email sent /
  account budget spent.

## Security invariants (keep them when changing code)
- Secrets sent to users are random 256-bit tokens; only their SHA-256 is stored. Sole exception: the
  6-digit magic code (HMAC, flow-bound, few attempts — see Flows).
- Single-use tokens are consumed atomically: `UPDATE … SET consumed_at = now() WHERE … IS NULL RETURNING`.
- Email links carry the token in the URL **fragment** and are confirmed by a **POST** from the app page
  (mail scanners follow GET links). Each link stores the address it was sent to and is refused if the
  account's email changed since.
- No account enumeration: registration, verification resend, recovery, magic link and email change answer identically
  whether the address exists; argon2 runs (or `verify_dummy`) before touching the DB.
- `redirect_uri` compared byte for byte; client URLs must be https, http on localhost, or a native app
  scheme containing a dot (`com.example.app:/…`, RFC 8252).
- Rate limits are checked before argon2 / DB writes. `X-Forwarded-For` only trusted from
  `BAUTH_TRUSTED_PROXIES`.
- `CurrentUser` checks the session in the DB: revocation is immediate for `/me`.
  Password, email change and account deletion require the current password.
- `ServerConfig` has no `Debug` (it holds secrets). `MasterKey` has a redacting `Debug`.
- CORS allows only client origins: origins of each client's http(s) URLs, `BAUTH_VERIFICATION_URL`,
  plus `allowed_origins` (Tauri: `tauri://localhost`, `http://tauri.localhost`). No credentials.

## Errors
- App routes: `ApiError` → `{ "code": "<stable_code>", "message": "…" }`. Mostly 400; `unauthorized` 401
  (with `WWW-Authenticate`), `not_found` 404, `rate_limited` 429 (+ `Retry-After`), `internal_error` 500.
  Use `AppJson` / `AppPath` extractors so rejections keep that shape.
- `/oauth/*`: `OAuthError` in RFC 6749 format (`{"error": "invalid_grant", …}`), form-encoded input.

## Configuration
- Env (`.env.example`): `BAUTH_BIND_ADDR`, `BAUTH_ISSUER` (no trailing slash), `BAUTH_DATABASE_URL`,
  `BAUTH_MASTER_KEY` (base64 32 bytes; losing it invalidates keys), `BAUTH_CONFIG`, `BAUTH_SMTP_URL`,
  `BAUTH_MAIL_FROM`, `BAUTH_VERIFICATION_URL`, `BAUTH_TRUSTED_PROXIES`, `RUST_LOG`.
- `bauth.toml` clients (`deny_unknown_fields`): `id`, `name`, `redirect_uris`, `allow_signup`,
  `audience`, `password_reset_url`, `magic_link_url`, `allowed_origins`.

## Tests
- Unit tests next to the code (crypto, validation, config, rate limits…).
- Integration tests in `bauth_server/src/tests/`: the real router (`app(state)`) against a fresh
  Postgres database per test (`#[sqlx::test]`), emails captured by `Mailer::capture()`.
  `TestApp` has helpers (`register_verified`, `login`, `refresh`, `last_token`, `age_rotations`…).
  Files: `oauth` (PKCE, code replay, refresh rotation), `accounts` (verification, no enumeration,
  reset, magic link and code, stale links), `me` (session revocation, password change, deletion),
  `protections` (rate limits, per-flow email cap, X-Forwarded-For, CORS), `jobs` (purge retention and lock),
  `key_rotation` (prepublication, handover, unpublication, emergency retirement).
- `DATABASE_URL` points to the dedicated `postgres-test` compose service (port 5440, in-memory): sqlx
  creates `_sqlx_test_*` databases and a `_sqlx_test` schema there. Never the dev Postgres.
  CI runs its own `postgres:18` service. Failed tests keep their database until the next run.
- Add an integration test for each new flow or security rule; keep them scenario-level, not exhaustive.
- `bauth_client/tests/verifier.rs` spins a fake JWKS server; `sdk/client/test` mocks fetch.
- Bruno collection in `bruno/bauth` (folder `me` sets `Bearer {{access_token}}`).

## Deployment
- `Dockerfile`: cargo-chef, `rust:1.98-slim-trixie` → `debian:trixie-slim`, non-root, port 8401,
  `BAUTH_CONFIG=/etc/bauth/bauth.toml` (mount it). Migrations run at startup.
- `release.yml` (on GitHub release): check then push `ghcr.io/wadjetz/bauth:{latest,sha}`.
- Meant to run behind a reverse proxy (TLS, `X-Forwarded-For` from `BAUTH_TRUSTED_PROXIES`).

## Audit findings (2026-09-15, full read of `bauth_server`, `bauth_client`, migrations)
Nothing below is fixed yet. Remove an item once it is (or once the decision is recorded elsewhere).

### Fix before production
2. **Pending email changes survive a password reset/change.** `recovery::reset` and
   `me::change_password` call `password_resets::consume_all_for_user` but not the same for
   `email_changes`: someone who knew the old password and requested `POST /me/email` keeps a 1 h link
   that moves the account to their address after the owner reset the password. Fix: add
   `email_changes::consume_all_for_user` to both, and consider storing the requesting `session_id`
   in `email_changes` so a revoked session's link dies too.
3. **Unlimited unauthenticated endpoints.** `POST /flows/login` inserts a row per call (redirect URI
   + 512 B `state`, purged after 1 day) with no `ClientIp` limit; `/oauth/token` and `/oauth/revoke`
   open a transaction (`FOR UPDATE`) per call with no limit either. Add per-IP limiters.
4. **`recovery::reset` hashes before checking the token** (`password::hash` runs before
   `password_resets::consume`): argon2 for anyone, bounded only by `token_per_ip`. Do a cheap
   pending-token check first, like `submit_password` does with `login_flows::is_pending`.

### Should fix / decide
5. **Refresh grace window is a permanent fork.** Reuse of a rotated token within 30 s creates a
   second child of the same parent (`oauth.rs::refresh_token`, `(None, Some(_))` within
   `REFRESH_REUSE_GRACE`); both lineages then rotate normally and theft is never detected (RFC 9700
   §4.14.2 expects any reuse to be treated as a breach). Alternative: allow the second child but
   revoke the session when a *second* child of one parent gets rotated — two tabs sharing storage
   only ever use one of them (this changes `two_tabs_refreshing_at_once_both_keep_working`).
6. **`state` is accepted but never returned.** `CreateFlowRequest.state` says "echoed back with the
   code", but `LoginResponse::Completed` only carries `code`. Return `state` (and `redirect_uri`,
   which the magic-link page needs to know where to go) or drop the field and the column.
7. **`CurrentUser` accepts any `aud`** (`current_user.rs`, `validate_aud = false`): a resource
   server holding a user's `aud: other-api` token can read `/me`, list and **revoke sessions** without the
   password. Options: add the issuer as a second audience (`aud` becomes an array in `bauth_core`),
   or accept and document the trust in resource servers. Session revocation should count as sensitive.
8. **Per-email login limit locks the owner out.** `login_per_email` (10 then 1/30 s) is charged
   for every attempt, so wrong passwords sprayed at a victim's address make their correct login 429.
   Count failures only (separate counter) or key by `(ip, email)` with a looser per-email budget.
9. **Trusted proxies by exact IP** (`rate_limit::parse_trusted_proxies`): the reverse proxy's address on a
   Docker network changes across restarts; when it isn't trusted (or doesn't forward `X-Forwarded-For`),
   every user shares one bucket and login is globally rate limited. Accept CIDRs (`ipnet`) and
   document the reverse proxy setup.
10. **RFC 8414 metadata claims a grant that doesn't exist per spec.** `well_known.rs` advertises
    `response_types_supported: ["code"]` and `authorization_code` without `authorization_endpoint`
    (REQUIRED when a supported grant uses it). bauth's code flow is its own JSON API (`/flows/login`),
    not RFC 6749 §4.1: generic OAuth libraries can't drive it. Say so in the metadata's doc, or drop
    the endpoint. Also `validate_issuer` allows a path, but RFC 8414 §3.1 puts `/.well-known/…`
    between host and path, so an issuer with a path wouldn't be discoverable at `routes::router()`.
11. **RFC 8252 §7.3 loopback redirects**: `http://127.0.0.1:{any port}/…` must match on any port;
    `Client::allows_redirect_uri` compares byte for byte. Only matters for a native app using a
    loopback listener (Tauri desktop); none does today.
12. **Signing key creation has no lock.** `signing_keys::ensure_and_load` inserts a key when none
    can sign: several instances starting at once each create one. And if every key was retired by SQL
    between the :07 reload and the 03:23 rotation, `rotate_if_due` publishes a key for +24 h, then
    `reload` creates an immediate one that is never retired (`retire_all_except` already ran) and
    stays in the JWKS forever. Create keys under `ROTATION_LOCK_KEY`, and make `rotate_if_due`
    create an immediate key when nothing signs.
13. **`email::is_valid` accepts addresses lettre can't send to** (`a<b@c.fr`, quotes): the request
    is 202, the background send fails, the user never gets the link. Validate with
    `lettre::Address::from_str` (`Mailbox` parse) inside `is_valid`.
14. **Emergency key retirement latency.** Deleting a compromised key row leaves it verifiable up to
    1 h in `bauth_client` caches (`JWKS_MAX_AGE`) and until the next :07 reload for bauth's own `/me`
    (`CurrentUser` uses the in-memory JWKS). Runbook: delete the row, restart bauth, restart APIs or
    wait 1 h. The planned admin API should do the reload itself.

### Hygiene
15. `current_user.rs` `strip_prefix("Bearer ")` is case-sensitive; `bauth_client::extract` is
    case-insensitive (RFC 9110 §11.1). Align on the client's behaviour.
16. `/oauth/token` responses lack `Pragma: no-cache` (RFC 6749 §5.1 MUST; OAuth 2.1 dropped it).
17. Unknown routes and 405s return an empty body, not `{code, message}`: add a `fallback` returning
    `not_found`.
18. No `Cache-Control: no-store` on `/me*` responses and no `X-Content-Type-Options: nosniff`
    anywhere (`SetResponseHeaderLayer`).
19. No graceful shutdown (`axum::serve(..).with_graceful_shutdown`) and no request timeout layer:
    SIGTERM cuts in-flight requests; slow clients are left to the reverse proxy.
20. `POST /me/password` accepts `new_password == current_password`; `POST /me/email` confirmation
    keeps every session open (design choice: the old address only gets a notification).
21. Accounts without a password (magic link only) can't `DELETE /me` nor change email
    (`password_not_set` sends them through password reset). Intended, but apps must explain it.
22. `config.rs` defaults `BAUTH_BIND_ADDR` to `0.0.0.0:3000`; `.env.example` and the Dockerfile use
    8401.
23. Web apps keeping refresh tokens in JS storage give an XSS a 30-day session: weigh a shorter web
    session TTL (per-client TTL is on the list) or a BFF/cookie pattern for web apps. Not a
    bauth change, but it drives the session TTL decision.

Reviewed and fine: PKCE S256 only with shape checks; codes bound to client, redirect URI and
challenge, 60 s TTL, replay revokes the session; `invalid_grant` on mismatch rolls back so the code
stays usable by the real app (a 256-bit verifier can't be brute-forced); refresh rows locked
`FOR UPDATE`; RFC 9068 claims and `typ: at+jwt` checked on both sides; JWKS prepublication (24 h)
above the client cache (1 h); XChaCha20-Poly1305 with per-key AAD; token hashes only; JSON routes
need a preflight so cross-origin login CSRF is not possible; emails built with `lettre::Mailbox`
(no header injection); body limits (axum 2 MB, password 128 chars, `state` 512 B, email 254).

## Scope (decided 2026-09-15)
Login methods: **password, magic link (+ 6-digit code), and later Google**. Nothing else is planned for now: don't
propose OIDC provider features, TOTP/passkeys, admin UI, etc. unless the maintainer asks.

## Not done yet
- Audit items 2–4 above (before production).
- Import of users from an existing app (keep UUIDs, bcrypt → argon2id rehash on first login).
- **Sign in with Google** (bauth is an OIDC *client* of Google, it does not need to be an OIDC provider):
  - `identities (user_id, provider, subject, email, created_at)`, unique `(provider, subject)`:
    Google's `sub` is the identity, never the email (addresses can change or be recycled).
  - Flow: `POST /flows/login/{id}/google` → Google authorization URL (bauth's own PKCE + `state` +
    `nonce` stored on the flow) → Google redirects to **one** bauth callback
    (`GET /oauth/google/callback`) → bauth exchanges the code, verifies the `id_token` (`iss`, `aud`,
    `exp`, `nonce`, Google JWKS), completes the flow and redirects to the flow's `redirect_uri` with
    `code` (+ `state`). The app then uses `/oauth/token` as today.
  - Linking: known `(google, sub)` → that user. Otherwise an account with the same email is linked
    only if `email_verified` is true; like the magic link (`magic_link::log_in`), linking an **unverified**
    account must drop its password and sessions. No account → create it if the client `allow_signup`.
  - Config: `BAUTH_GOOGLE_CLIENT_ID` / `BAUTH_GOOGLE_CLIENT_SECRET`; `google` listed in `methods`
    only when configured (per client opt-in: `google = true` in `bauth.toml`).
  - `GET /me` exposes linked providers; unlinking is refused if it would leave no way to log in.

### Parked ideas
Kept for later, not planned. See the `bauth-roadmap` skill (`.claude/skills/bauth-roadmap/`);
don't start any of them unless asked.
