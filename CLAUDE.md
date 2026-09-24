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
`Verifier` for APIs, `bauth_core` shared claims, `bauth_sdk` the `@wadjetz/bauth-client` TS SDK).
The SDK needs **TypeScript 5** — `openapi-typescript` requires it.

## Commands
```sh
podman compose up -d                         # dev Postgres :5441, SMTP :1025, UI :8026, test Postgres :5440
cd bauth_server && sqlx migrate run          # sqlx-cli reads bauth_server/sqlx.toml
cargo run -p bauth_server                    # reads .env (see .env.example)
SQLX_OFFLINE=true cargo clippy --all-features --all --tests -- -D warnings   # what CI runs
SQLX_OFFLINE=true cargo test --all-features --all      # needs DATABASE_URL (see below)
cd bauth_server && cargo sqlx prepare        # after ANY query change: refresh .sqlx, commit it
UPDATE_OPENAPI=1 cargo test -p bauth_server openapi   # after ANY route/schema change: refresh openapi.json
cd bauth_sdk && npm run generate && npm test          # then refresh the SDK types (CI checks they match)
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
- Emails are Tera 2 templates in `bauth_server/templates/emails/`, one `.txt` + `.html` pair each
  (French, *vouvoiement*), compiled into the binary: a new template must also be listed in the
  `templates!` call of `emails.rs`. `.html` autoescapes; components (`code`, `button`) in `components.html`.
- Signing keys: Ed25519 seeds encrypted by `master_key` (XChaCha20-Poly1305, per-key AAD); a new key is
  published 24 h before it signs and kept 24 h after; the signing key is picked per token from
  `active_at` / `retired_at`.

## Database
- Can share a Postgres with other apps: **everything lives in schema `bauth`**. Always write `bauth.table`
  in SQL — the search path could otherwise hit another app's `public.users`.
- Migration table `bauth._sqlx_migrations` (see `sqlx.toml`). Reversible migrations (`sqlx migrate add -r`).
- Tables: one per file in `queries/` (and in `migrations/`). Columns that aren't self-explanatory:
  `refresh_tokens.parent_id` / `superseded_at` (rotation lineage), `magic_links.user_id` NULL =
  sign-up, plus its `code_hash` / `code_failures`.
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
- Passwordless sign-up goes through the magic link, never `/registration` (one email only): an unknown
  address gets a "create your account" email when the client `allow_signup` (row with `user_id` NULL);
  the account is created, verified and without password, when the link or code is used — or joined if
  it was registered meanwhile (same unverified-account rule as above). Nothing exists before.
- Magic link email = link + 6-digit code, one `magic_links` row: using either consumes it. The code
  (`POST /flows/login/{id}/magic-code`) is typed on the device that asked (mobile mail apps open links
  elsewhere). Only 10^6 values, so (`magic_code.rs`, `routes/magic_link.rs`): looked up by flow, newest
  email of the flow only, consumed after 5 wrong codes, and at most 10 wrong codes per address over
  24 h (sum of `code_failures` by `email`) — past that codes are refused for the address, links still
  work. Checks run under an advisory xact lock on the address (sign-ups have no user row) so concurrent
  guesses can't overshoot. HMAC keyed by
  `MasterKey::derive("magic_code")` over `flow_id || code`; 3 emails per flow (counted on `login_flows`
  whether the account exists or not); `invalid_code` for wrong code / unknown flow / no email sent /
  address budget spent.

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
  Password, email change and account deletion require the current password — or, for an account
  without one, a 6-digit code emailed by `POST /me/confirmation` (`confirmations`, bound to the
  session **and** the action, 15 min, 5 wrong codes then consumed, 10 per account a day, account row
  locked). `/me/password` still goes through password reset: a code must not set a password.
- `ServerConfig` has no `Debug` (it holds secrets). `MasterKey` has a redacting `Debug`.
- CORS allows only client origins: origins of each client's http(s) URLs,
  plus `allowed_origins` (Tauri: `tauri://localhost`, `http://tauri.localhost`). No credentials.

## Errors
- App routes: `ApiError` → `{ "code": "<stable_code>", "message": "…" }`. Mostly 400; `unauthorized` 401
  (with `WWW-Authenticate`), `not_found` 404, `rate_limited` 429 (+ `Retry-After`), `internal_error` 500.
  Use `AppJson` / `AppPath` extractors so rejections keep that shape.
- `/oauth/*`: `OAuthError` in RFC 6749 format (`{"error": "invalid_grant", …}`), form-encoded input.

## Configuration
- Env: the list is `.env.example`. Non-obvious: `BAUTH_ISSUER` takes no trailing slash, and
  `BAUTH_MASTER_KEY` is base64 32 bytes — losing it invalidates every signing key.
- `bauth.toml` clients (`deny_unknown_fields`): `id`, `name`, `redirect_uris`, `allow_signup`,
  `audience`, `password_reset_url`, `magic_link_url`, `verification_url` (email confirmation page:
  password registration, verification resend and email change fail without it), `allowed_origins`.

## Tests
- Unit tests next to the code (crypto, validation, config, rate limits…).
- Integration tests in `bauth_server/src/tests/`: the real router (`app(state)`) against a fresh
  Postgres database per test (`#[sqlx::test]`), emails captured by `Mailer::capture()`.
  `TestApp` has helpers (`register_verified`, `login`, `refresh`, `last_token`, `age_rotations`…).
  Files: `oauth` (PKCE, code replay, refresh rotation), `accounts` (verification, no enumeration,
  reset, magic link and code, passwordless sign-up, stale links), `me` (session revocation, password change, deletion),
  `protections` (rate limits, per-flow email cap, X-Forwarded-For, CORS), `me` also covers confirmation codes, `jobs` (purge retention and lock),
  `key_rotation` (prepublication, handover, unpublication, emergency retirement).
- `DATABASE_URL` points to the dedicated `postgres-test` compose service (port 5440, in-memory): sqlx
  creates `_sqlx_test_*` databases and a `_sqlx_test` schema there. Never the dev Postgres.
  CI runs its own `postgres:18` service. Failed tests keep their database until the next run.
- Add an integration test for each new flow or security rule; keep them scenario-level, not exhaustive.
- `bauth_client/tests/verifier.rs` spins a fake JWKS server; `bauth_sdk/test` mocks fetch.
- Bruno collection in `bruno` (folder `me` sets `Bearer {{access_token}}`).

## Deployment
- `Dockerfile`: cargo-chef, `rust:1.98-slim-trixie` → `debian:trixie-slim`, non-root, port 8401,
  `BAUTH_CONFIG=/etc/bauth/bauth.toml` (mount it). Migrations run at startup.
- `release.yml` (on GitHub release): check then push `ghcr.io/wadjetz/bauth:{latest,sha}`.
- `@wadjetz/bauth-client` is published by hand (`npm publish`, see README "Releasing the SDK"): bump it
  with any server API change — `0.1.1` predates `client_id` on `POST /verification`.
- Meant to run behind a reverse proxy (TLS, `X-Forwarded-For` from `BAUTH_TRUSTED_PROXIES`).

## Audit findings (2026-09-15, full read of `bauth_server`, `bauth_client`, migrations)
Numbers are stable references: once an item is fixed (or decided), replace its text with a one-line
`Fixed <date>: …` note instead of deleting it, so the numbering never shifts.
Only items 1–4 (the pre-production blockers) are kept here; items 5–23 and the second audit
(2026-09-16, items 24–43: magic code, sign-up, confirmations, SDK) are in the `bauth-roadmap` skill.

### Fix before production
1. *Fixed 2026-09-15: pre-registration takeover through magic link — a magic link/code login on an
   unverified account drops its password and sessions; unverified accounts are purged after 7 days
   (see Flows). Residual: item 28.*
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

### Should fix / decide, and hygiene
Items 5–23 (refresh grace fork, `state` never returned, `aud` on `/me`, per-email limit, trusted
proxy CIDRs, RFC 8414/8252 details, signing-key lock, `email::is_valid`, key-retirement latency,
and the hygiene list) are in the `bauth-roadmap` skill, with items 24–43.

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
- **Sign in with Google** (bauth is an OIDC *client* of Google, it does not need to be an OIDC
  provider). Design — identities table, flow, linking rules, config — in the `bauth-roadmap` skill.

### Parked ideas
Kept for later, not planned. See the `bauth-roadmap` skill (`.claude/skills/bauth-roadmap/`);
don't start any of them unless asked.
