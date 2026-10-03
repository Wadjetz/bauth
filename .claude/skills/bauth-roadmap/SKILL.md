---
name: bauth-roadmap
description: Parked ideas for bauth (kept for later, not planned), the audit findings from item 5 on (both audits), and the Sign in with Google design. Read when the maintainer asks about future features, the roadmap, whether an idea was already considered, an audit item above 4, or how Google login should work — never to start work unprompted.
---

# bauth — parked ideas

Not planned. Don't start any of these unless the maintainer asks.
The active scope is in `CLAUDE.md` (`## Scope`): magic link (+ 6-digit code), later Google.

Earlier roadmap: audit log, per-client session TTL, emergency key rotation through an admin API,
roles per audience, GitHub/other OIDC providers, TOTP/passkeys, signed webhooks (`user.deleted`),
`client_credentials`, delayed account deletion.

Security
- Record `ip` + `user_agent` on sessions (and on the audit log): `GET /me/sessions` shows
  "Chrome on macOS · Paris · 2 h ago", and a **new-device email** goes out on a login from an unseen
  IP/UA (with a "this wasn't me → revoke everything" link).
- **Undo link** in the `email_changed` email: a 7-day token that reverts the change and revokes
  every session.
- `auth_time` claim + `POST /flows/login` with `prompt=login` for an existing session: apps can
  require a fresh login for sensitive screens instead of re-implementing it.
- Optional bot protection per client on the magic link request (Turnstile/hCaptcha
  token verified server-side), and a disposable-email domain blocklist.
- TOTP with recovery codes and "remember this device" (trusted-device token bound to the session);
  passkeys (WebAuthn) as a login method in `methods`.
- DPoP (RFC 9449) for the web client, so a stolen refresh token is useless without the browser's key.
- Confidential clients (`client_secret`, `private_key_jwt`) for server-side apps / a BFF.

Accounts
- Invitations for `allow_signup = false` clients: `POST /invitations` (admin) → sign-up email
  carrying the invite; optional expiry and single use.
- Account linking with other providers (GitHub…), same rules as Google (`email_verified` honoured,
  never auto-linked when unverified).
- `GET /me/export` (GDPR: profile, sessions, audit log as JSON) and `GET /me/logins` (login history).
- Multiple / secondary emails, and a cooldown after an email change (no second change for 24 h).
- Terms-of-service version accepted per user (`tos_accepted_at`, `tos_version`), re-prompted by apps.
- User locale for emails; HTML + text templates, per-client branding (`mail_from`, logo, colours).

Admin & operations
- **Admin API** (bearer with a `bauth-admin` audience, or a CLI over the DB): list/search users,
  disable/enable, revoke sessions, delete, emergency key rotation, hot reload
  of `bauth.toml`. Nothing can set `disabled_at` today.
- `bauth` CLI subcommands: `check-config`, `create-user`, `disable-user`, `rotate-key`,
  `rotate-master-key` (re-encrypt signing keys under a new `BAUTH_MASTER_KEY`).
- Audit log table (`who, what, target, ip, ua, at`) for every security event; feeds `/me/logins`,
  the admin API and webhooks.
- Prometheus `/metrics` (logins, failures, 429s, emails sent/failed, argon2 queue depth, purge
  counts) and OpenTelemetry traces; JSON logs in production.
- Shared rate-limit state for several instances (Postgres `UNLOGGED` table or Redis); `/health/ready`
  also checks that a signing key can sign now.
- Configurable retention per table (purge job).

Protocol
- A real `authorization_endpoint` with a minimal hosted login page, so generic OAuth/OIDC libraries
  and third-party apps (Grafana, Gitea…) work (fixes audit item 10); OIDC provider on top of it:
  `id_token`, `/userinfo`, `.well-known/openid-configuration`.
- Token introspection (RFC 7662) for APIs that can't verify JWTs (PHP, serverless), returning the
  session state too (live revocation for those callers).
- Device authorization grant (RFC 8628) for a future CLI/TV client.
- `scope` support: per-client allowed scopes, `scope` claim, `bauth_client` `require_scope` helper.
- Loopback redirect with any port (RFC 8252 §7.3) for desktop apps (audit item 11).

SDK & DX
- `@wadjetz/bauth-client`: token store abstraction (memory / `localStorage` / Tauri secure storage), single-
  flight auto refresh with a `fetch` wrapper, PKCE + magic-link helpers wired end to end, typed errors.
- `bauth_client`: `AuthUser::require_client(..)` / roles helpers once roles exist; a `mock` feature
  issuing test tokens without bauth.
- A tiny reference app (Vite page for login / magic-link / email change) usable by every
  client as a starting point, and a Playwright end-to-end test running it against bauth + Mailpit.

## Audit findings (2026-09-16, changes since the 2026-09-15 audit)
Scope: magic code, passwordless sign-up, unverified-account rule, `POST /me/confirmation`, purge,
`MasterKey::derive`, `bauth_sdk`, release workflow. Nothing below is fixed yet. Items 1–4 live in
`CLAUDE.md` (the pre-production blockers); items 5–23 are further down this file; numbering
continues. Once an item is fixed or decided, replace its text with a one-line `Fixed <date>: …`
note instead of deleting it, so numbers stay stable.

### Bugs
24. *Fixed 2026-09-27: `change_email` checks the new address's rate limit before confirming; a
    taken address still spends the code (checking it first would let a stolen token probe
    accounts) — documented on the 202.*
25. *Fixed 2026-09-26: each magic link email extends its flow to the email's expiry
    (`greatest(expires_at, …)` in `count_magic_link_request`, bounded by the 3-emails cap).*
26. *Fixed 2026-09-26: `magic_link::request` reads the flow, runs every check, then counts the
    email with a conditional `UPDATE` (`magic_link_requests < 3`).*

### Security — decide
27. *Moot 2026-10-02: no passwords; the code is the only confirmation*
28. *Moot 2026-10-02: registration with a password removed*
29. *Fixed 2026-10-02: one key per purpose (`magic_code::CodeKeys`: `derive("magic_code")` and
    `derive("confirmation_code")`); `generate` / `verify` take an `owner` (flow or session).*
30. **The raw master key is used directly as the HMAC key in `MasterKey::derive` and as the XChaCha20
    key.** Safe in practice (different primitives), but the usual rule is root key → one subkey per
    use. Deriving the cipher key too (`derive("encrypt")`) changes the key of existing `signing_keys`
    rows: do it before production or version the ciphertext.
31. **Anyone can spend an address's email budget.** `email_per_address` is one bucket shared by
    magic link, email change *and* `POST /me/confirmation`: five magic link requests for the
    victim's address make their next confirmation code request 429 for 3 minutes. Low; an
    authenticated route can use its own (user, session) bucket.
32. **`confirmation_code` emails don't name the app.** Magic link emails carry `client.name`; the
    confirmation one doesn't although the session has `client_id`. With two apps on bauth the user
    can't tell where "supprimer ton compte" came from, which the "wasn't me" advice relies on.

### Duplication / refactoring
33. *Decided 2026-10-02: constants (`magic_code::MAX_FAILURES_PER_CODE`, `MAX_FAILURES_PER_DAY`,
    `CODE_TTL`) and the format check (`magic_code::check_format`) are shared. The query trios and the
    attempt sequence stay per table: the locks differ and `sqlx::query!` can't take a table name, so a
    generic "spend one attempt" would cost more than it saves.*
34. *Fixed 2026-10-02: `Recipient::Account(id) | Recipient::SignUp`; the two emails share `magic()`.*
35. *Fixed 2026-10-02: `magic_link::log_in` has no `finish` detour nor `MagicLogin`/`notify` any more
    (nothing to remove from an unverified account without passwords).*
36. *Fixed 2026-10-02: `wrong_code` lives in `tests/mod.rs`; `login_with_code` is gone.*

### Hygiene
37. **SDK formatting drift:** `bauth_sdk/src/client.ts` was reformatted with Biome's defaults (tabs,
    semicolons) while `errors.ts`, `pkce.ts` and `test/` use 2 spaces and no semicolons. The package
    has no formatter config and CI checks none: add a `biome.json` and a `check` step.
38. **Untested:** the 10-per-user daily budget and the users-row lock of `confirmations` (the
    magic-link equivalents have a test and were mutation-checked); item 25's window;
    `magic_link::request` for a disabled account (`disabled_at` set by SQL, like `tests/jobs.rs`).
39. **`confirmations.action` is free text:** add `CHECK (action IN ('change_email',
    'delete_account'))` so a typo in `ConfirmationAction::as_str` can't create unreachable rows.
40. *Fixed 2026-10-02: `me_confirmation.yml`; `me_email.yml` / `me_delete.yml` send its code.*
41. *Fixed 2026-09-26: `createBauthClient` methods call each other through a local `client`, not `this`.*
42. *Fixed 2026-10-02: CLAUDE.md names both codes as the exceptions to 256-bit tokens.*
43. **`_check_sdk.yml` never packs:** an `npm pack --dry-run` (or publint) step would catch a broken
    `files` / `exports` before a release publishes it.

Reviewed and fine: sign-up creates nothing before the email is used, and `users::create`
(`ON CONFLICT DO NOTHING`, then lookup by address) covers two sign-ups racing; link and code
paths roll back on `flow_expired`, so nothing is consumed; the advisory xact lock on the address is
taken in its own statement before the budget query (mutation-checked: without it 11/10 failures got
counted); wrong codes are committed on the failure path; the per-flow cap's `Retry-After` can't be 0
(an expired flow answers `flow_expired` first); codes are bound to the flow / session by the HMAC and
to the action by the lookup; purge cascades
(`user_id NULL` links go with their flow, confirmations with their session or user).

## Audit findings 5–23 (2026-09-15 audit, moved here 2026-09-16)
Items 1–4 stay in `CLAUDE.md` (`## Audit findings`): 1 is fixed, 2–4 are the pre-production
blockers. The "Reviewed and fine" list of that audit stays there too. Same rule as above: once an
item is fixed or decided, replace its text with a one-line `Fixed <date>: …` note instead of
deleting it, so the numbering never shifts.

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
   server holding a user's `aud: other-api` token can read `/me`, list and **revoke sessions** without a
   confirmation code. Options: add the issuer as a second audience (`aud` becomes an array in `bauth_core`),
   or accept and document the trust in resource servers. Session revocation should count as sensitive.
   Note: `bauth_client::Verifier::me` calls `/me` with an API's token (`aud` of that API):
   restricting `aud` on `/me` must keep a way for APIs to read the email.
8. *Moot 2026-10-02: password login removed, and `login_per_*` with it*
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
20. `POST /me/email` confirmation keeps every session open (design choice: the old address only
    gets a notification). (`/me/password` was removed with the passwords on 2026-10-02.)
21. *Fixed 2026-09-16: accounts without a password confirm email change and deletion with a code
    from `POST /me/confirmation` (see Security invariants). Follow-up: item 27.*
23. Web apps keeping refresh tokens in JS storage give an XSS a 30-day session: weigh a shorter web
    session TTL (per-client TTL is on the list) or a BFF/cookie pattern for web apps. Not a
    bauth change, but it drives the session TTL decision.

## Sign in with Google — design
Planned (listed under `## Not done yet` in `CLAUDE.md`), not started. bauth is an OIDC *client* of
Google here; it does not need to be an OIDC provider.
- `identities (user_id, provider, subject, email, created_at)`, unique `(provider, subject)`:
  Google's `sub` is the identity, never the email (addresses can change or be recycled).
- Flow: `POST /flows/login/{id}/google` → Google authorization URL (bauth's own PKCE + `state` +
  `nonce` stored on the flow) → Google redirects to **one** bauth callback
  (`GET /oauth/google/callback`) → bauth exchanges the code, verifies the `id_token` (`iss`, `aud`,
  `exp`, `nonce`, Google JWKS), completes the flow and redirects to the flow's `redirect_uri` with
  `code` (+ `state`). The app then uses `/oauth/token` as today.
- Linking: known `(google, sub)` → that user. Otherwise an account with the same email is linked
  only if `email_verified` is true; like the magic link (`magic_link::log_in`), an **unverified**
  account is simply verified by the link, as with the magic link. No account → create it if the client `allow_signup`.
- Config: `BAUTH_GOOGLE_CLIENT_ID` / `BAUTH_GOOGLE_CLIENT_SECRET`; `google` listed in `methods`
  only when configured (per client opt-in: `google = true` in `bauth.toml`).
- `GET /me` exposes linked providers; unlinking is refused if it would leave no way to log in.
