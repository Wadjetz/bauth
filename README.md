# bauth

Headless authentication server: apps draw their own screens and call bauth's API.

> [!WARNING]
> **This project is written with AI assistance and its human review is still in progress.**
> It has not been audited; known issues are listed under "Audit findings" in [`CLAUDE.md`](CLAUDE.md).
> Use it at your own risk: it comes with no warranty of any kind (see the [license](LICENSE)).

- Passwordless: login and sign-up by email, with a magic link and a 6-digit code in the same email
- OAuth 2.1 authorization code flow with PKCE; EdDSA access tokens (JWT) published in a JWKS
- Refresh token rotation with reuse detection, revocation, `/me` (profile, email change, sessions, account
  deletion — sensitive changes confirmed by an emailed code)
- Rate limits per IP and per email address

## Crates

| Crate | Role |
|---|---|
| `bauth_server` | The server (axum, sqlx, Postgres) |
| `bauth_client` | Verifies bauth access tokens in an API (JWKS cache) |
| `bauth_core` | Types shared by both |

The TypeScript SDK for apps is [`@wadjetz/bauth-client`](bauth_sdk) on npm.

## Development

```sh
cp .env.example .env            # then set BAUTH_MASTER_KEY: openssl rand -base64 32
podman compose up -d           # dev Postgres :5441, emails on http://localhost:8026, test Postgres :5440
cd bauth_server && sqlx migrate run && cd ..
cargo run -p bauth_server
```

Clients are declared in [`bauth.toml`](bauth.toml). Example requests live in [`bruno/`](bruno).

After changing a SQL query, refresh the offline query cache used by CI and Docker:

```sh
cd bauth_server && cargo sqlx prepare
```

After changing a route, a request or response type, or a `#[utoipa::path]` doc, regenerate
`bauth_server/openapi.json` (otherwise its test fails), then the SDK types generated from it:

```sh
UPDATE_OPENAPI=1 SQLX_OFFLINE=true cargo test -p bauth_server openapi
cd bauth_sdk && npm run generate && npm test
```

## Releasing

A release is a version bump merged into `main`: the server and `@wadjetz/bauth-client` share one
version, telling how compatible the API is (the SDK types come from `openapi.json`): `patch` for
fixes, `minor` for additions — and, while in `0.x`, for breaking changes too.

```sh
# set the new version in Cargo.toml ([workspace.package]), then:
cd bauth_sdk && npm version 0.4.0 --no-git-tag-version && cd ..   # package.json and package-lock.json
UPDATE_OPENAPI=1 SQLX_OFFLINE=true cargo test -p bauth_server openapi   # Cargo.lock, openapi.json
cd bauth_sdk && npm run generate && npm test
```

Once it is on `main`, `release.yml` sees that `v<version>` has no tag yet: it runs the checks, pushes
`ghcr.io/wadjetz/bauth:<version>` (and `:<major>.<minor>`, `:latest`, `:<sha>`), publishes the SDK to
npm (trusted publishing, with provenance), then creates the tag and the GitHub release with generated
notes. If a step fails, re-run the workflow: what was already done is skipped.

## Docker

```sh
podman run -p 8401:8401 \
  -v ./bauth.toml:/etc/bauth/bauth.toml:ro \
  -e BAUTH_DATABASE_URL=postgres://… \
  -e BAUTH_MASTER_KEY=… \
  -e BAUTH_ISSUER=https://auth.example.com \
  -e BAUTH_SMTP_URL=smtps://… \
  ghcr.io/wadjetz/bauth:0.3   # or an exact version, or `latest`
```

Migrations run at startup. See [`.env.example`](.env.example) for every setting.

## License

[MIT](LICENSE)
