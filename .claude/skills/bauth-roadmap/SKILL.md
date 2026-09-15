---
name: bauth-roadmap
description: Parked ideas for bauth (kept for later, not planned). Read only when the maintainer asks about future features, the long-term roadmap, or whether an idea was already considered — never to start work unprompted.
---

# bauth — parked ideas

Not planned. Don't start any of these unless the maintainer asks.
The active scope is in `CLAUDE.md` (`## Scope`): password, magic link (+ 6-digit code), later Google.

Earlier roadmap: audit log, per-client session TTL, emergency key rotation through an admin API,
roles per audience, GitHub/other OIDC providers, TOTP/passkeys, signed webhooks (`user.deleted`),
`client_credentials`, delayed account deletion.

Security
- Record `ip` + `user_agent` on sessions (and on the audit log): `GET /me/sessions` shows
  "Chrome on macOS · Paris · 2 h ago", and a **new-device email** goes out on a login from an unseen
  IP/UA (with a "this wasn't me → revoke everything" link).
- **Undo links** in security emails: `password_changed` and `email_changed` carry a 7-day token that
  reverts the change and locks the account (`disabled_at`) until a password reset.
- `auth_time` claim + `POST /flows/login` with `prompt=login` for an existing session: apps can
  require a fresh password for sensitive screens instead of re-implementing it.
- Breached-password check at registration/change (HIBP k-anonymity range API, fail-open on outage).
- Optional bot protection per client on `/registration`, `/recovery`, magic link (Turnstile/hCaptcha
  token verified server-side), and a disposable-email domain blocklist.
- TOTP with recovery codes and "remember this device" (trusted-device token bound to the session);
  passkeys (WebAuthn) as a login method in `methods`.
- DPoP (RFC 9449) for the web client, so a stolen refresh token is useless without the browser's key.
- Confidential clients (`client_secret`, `private_key_jwt`) for server-side apps / a BFF.

Accounts
- Invitations for `allow_signup = false` clients: `POST /invitations` (admin) → email → registration
  with the invite token; optional expiry and single use.
- Account linking with other providers (GitHub…), same rules as Google (`email_verified` honoured,
  never auto-linked when unverified).
- `GET /me/export` (GDPR: profile, sessions, audit log as JSON) and `GET /me/logins` (login history).
- Multiple / secondary emails, and a cooldown after an email change (no second change for 24 h).
- Terms-of-service version accepted per user (`tos_accepted_at`, `tos_version`), re-prompted by apps.
- User locale for emails; HTML + text templates, per-client branding (`mail_from`, logo, colours).

Admin & operations
- **Admin API** (bearer with a `bauth-admin` audience, or a CLI over the DB): list/search users,
  disable/enable, revoke sessions, resend verification, delete, emergency key rotation, hot reload
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
- A tiny reference app (Vite page for verify-email / reset / magic-link / login) usable by every
  client as a starting point, and a Playwright end-to-end test running it against bauth + Mailpit.
