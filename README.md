# bauth

Headless authentication server: apps draw their own screens and call bauth's API.

> [!WARNING]
> **This project is written with AI assistance and its human review is still in progress.**
> It has not been audited; known issues are listed under "Audit findings" in [`CLAUDE.md`](CLAUDE.md).
> Use it at your own risk: it comes with no warranty of any kind (see the [license](LICENSE)).

- Registration with email verification, password login, magic links (+ 6-digit code, passwordless sign-up), password reset
- OAuth 2.1 authorization code flow with PKCE; EdDSA access tokens (JWT) published in a JWKS
- Refresh token rotation with reuse detection, revocation, `/me` (profile, password, email, sessions, account deletion)
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
podman compose up -d mailpit postgres-test   # emails on http://localhost:8026, test Postgres on :5440
cd bauth_server && sqlx migrate run && cd ..
cargo run -p bauth_server
```

Clients are declared in [`bauth.toml`](bauth.toml). Example requests live in [`bruno/`](bruno).

After changing a SQL query, refresh the offline query cache used by CI and Docker:

```sh
cd bauth_server && cargo sqlx prepare
```

## Docker

```sh
podman run -p 8401:8401 \
  -v ./bauth.toml:/etc/bauth/bauth.toml:ro \
  -e BAUTH_DATABASE_URL=postgres://… \
  -e BAUTH_MASTER_KEY=… \
  -e BAUTH_ISSUER=https://auth.example.com \
  -e BAUTH_SMTP_URL=smtps://… \
  ghcr.io/wadjetz/bauth:latest
```

Migrations run at startup. See [`.env.example`](.env.example) for every setting.

## License

[MIT](LICENSE)
